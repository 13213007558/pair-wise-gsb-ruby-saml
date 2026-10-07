require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/ecp'

class EcpTest < Minitest::Test
  ACS_URL = "https://example.com/access/saml"
  IDP_URL = "https://idp.example.com/ecp"
  SP_URL = "https://sp.example.com/protected"
  RELAY_STATE = "opaque state"
  REQUEST_ID = "_ecp-authn-request"

  attr_reader :idp_cert, :idp_key, :settings

  def setup
    @idp_cert, @idp_key = CertificateHelper.generate_pair
    @settings = OneLogin::RubySaml::Settings.new
    settings.sp_entity_id = "consumer.example.com"
    settings.assertion_consumer_service_url = ACS_URL
    settings.idp_entity_id = "http://example.com/services/trust"
    settings.idp_sso_service_url = IDP_URL
    settings.idp_cert = idp_cert.to_pem
    settings.soft = false
  end

  def test_identifies_paos_initial_request_headers
    headers = {
      "HTTP_ACCEPT" => "text/html, application/vnd.paos+xml",
      "HTTP_PAOS" => 'ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:bindings:PAOS"'
    }

    paos = OneLogin::RubySaml::PaosRequest.new(headers)
    assert paos.ecp?
    assert_equal OneLogin::RubySaml::EcpMessage::PAOS_CONTENT_TYPE, paos.media_types.last
    assert_includes paos.services, OneLogin::RubySaml::Utils::BINDINGS[:paos]
    assert_equal OneLogin::RubySaml::EcpMessage::PAOS_CONTENT_TYPE, paos.client_headers["Accept"]
    assert_includes paos.client_headers["PAOS"], OneLogin::RubySaml::Utils::BINDINGS[:paos]
    refute OneLogin::RubySaml::PaosRequest.new("Accept" => "text/html").ecp?
  end

  def test_two_leg_ecp_exchange_with_local_sp_client_and_idp
    flow = FakeEcpFlow.new(self)
    result = OneLogin::RubySaml::EcpClient.new.authenticate(
      settings,
      :sp_url => SP_URL,
      :relay_state => RELAY_STATE,
      :transport => flow
    )

    assert flow.initial_request
    assert_equal "application/vnd.paos+xml", flow.initial_request.headers["Accept"]
    assert_includes flow.initial_request.headers["PAOS"], OneLogin::RubySaml::Utils::BINDINGS[:paos]
    assert_equal RELAY_STATE, flow.initial_request.headers["RelayState"]
    refute flow.initial_request.headers.key?("Content-Type")
    refute flow.initial_request.headers.key?("SOAPAction")

    assert_equal IDP_URL, flow.idp_http_request.url
    assert_equal "text/xml; charset=utf-8", flow.idp_http_request.headers["Content-Type"]
    assert_equal OneLogin::RubySaml::EcpMessage::SOAP_ACTION, flow.idp_http_request.headers["SOAPAction"]
    assert_equal RELAY_STATE, flow.idp_http_request.headers["RelayState"]
    refute flow.idp_http_request.headers.key?("PAOS")
    assert flow.idp_request.valid?
    assert_nil soap_header(flow.idp_http_request.body, OneLogin::RubySaml::EcpMessage::PAOS_NAMESPACE, "Request")
    assert soap_header(flow.idp_http_request.body, OneLogin::RubySaml::EcpMessage::ECP_NAMESPACE, "Request")

    assert_equal ACS_URL, flow.sp_http_request.url
    assert_equal "text/xml; charset=utf-8", flow.sp_http_request.headers["Content-Type"]
    assert_equal OneLogin::RubySaml::EcpMessage::SOAP_ACTION, flow.sp_http_request.headers["SOAPAction"]
    assert_equal RELAY_STATE, flow.sp_http_request.headers["RelayState"]
    refute flow.sp_http_request.headers.key?("PAOS")
    assert_nil soap_header(flow.sp_http_request.body, OneLogin::RubySaml::EcpMessage::ECP_NAMESPACE, "Response")
    assert soap_body_node(flow.sp_http_request.body, "urn:oasis:names:tc:SAML:2.0:protocol", "Response")

    [flow.idp_http_request.body, flow.sp_http_request.body].each do |message|
      refute_includes message, RELAY_STATE
      refute_includes message, "RelayState"
    end

    assert_equal REQUEST_ID, result.request_id
    assert_equal RELAY_STATE, result.relay_state
    assert result.sp_response.is_valid?
    assert_equal "someone@example.com", result.sp_response.name_id
    assert_equal ACS_URL, result.idp_response.assertion_consumer_service_url
  end

  def test_rejects_response_consumer_url_mismatch
    flow = FakeEcpFlow.new(self, :wrong_consumer_url => true)
    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      OneLogin::RubySaml::EcpClient.new.authenticate(settings, :sp_url => SP_URL, :transport => flow)
    end
    assert_match(/AssertionConsumerServiceURL/, error.message)
  end

  def test_requires_paos_and_ecp_soap_headers_at_first_hop
    settings.assertion_consumer_service_url = ACS_URL
    authn_request = OneLogin::RubySaml::Authrequest.new
    sp_message = OneLogin::RubySaml::EcpAuthnRequest.create(settings, :authn_request => authn_request)
    idp_message = sp_message.to_idp_request

    assert OneLogin::RubySaml::EcpAuthnRequest.new(sp_message.raw_message, settings).valid?
    assert OneLogin::RubySaml::EcpIdpRequest.new(idp_message, settings).valid?

    document = REXML::Document.new(sp_message.raw_message)
    header = document.root.elements.to_a.find { |node| node.name == "Header" }
    paos = header.elements.to_a.find { |node| node.namespace == OneLogin::RubySaml::EcpMessage::PAOS_NAMESPACE }
    paos.attributes["responseConsumerURL"] = "https://attacker.example/acs"
    invalid = OneLogin::RubySaml::EcpAuthnRequest.new(document.to_s, settings)
    invalid.soft = true
    refute invalid.valid?
    assert_includes invalid.errors.join, "responseConsumerURL must match AssertionConsumerServiceURL"
  end

  def signed_saml_response(request_id)
    now = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    document = XMLSecurity::Document.new
    assertion = document.add_element("saml:Assertion", {
      "xmlns:saml" => OneLogin::RubySaml::SamlMessage::ASSERTION,
      "ID" => "_ecp-assertion",
      "Version" => "2.0",
      "IssueInstant" => now
    })
    assertion.add_element("saml:Issuer").text = settings.idp_entity_id
    subject = assertion.add_element("saml:Subject")
    subject.add_element("saml:NameID").text = "someone@example.com"
    confirmation = subject.add_element("saml:SubjectConfirmation", {
      "Method" => "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    })
    confirmation.add_element("saml:SubjectConfirmationData", {
      "NotOnOrAfter" => (Time.now.utc + 300).strftime("%Y-%m-%dT%H:%M:%SZ"),
      "Recipient" => ACS_URL,
      "InResponseTo" => request_id
    })
    conditions = assertion.add_element("saml:Conditions", {
      "NotBefore" => (Time.now.utc - 60).strftime("%Y-%m-%dT%H:%M:%SZ"),
      "NotOnOrAfter" => (Time.now.utc + 300).strftime("%Y-%m-%dT%H:%M:%SZ")
    })
    conditions.add_element("saml:AudienceRestriction").add_element("saml:Audience").text = settings.sp_entity_id
    statement = assertion.add_element("saml:AuthnStatement", { "AuthnInstant" => now })
    statement.add_element("saml:AuthnContext").add_element("saml:AuthnContextClassRef").text =
      "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    document.uuid = "_ecp-assertion"
    document.sign_document(idp_key, idp_cert)

    <<-XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_ecp-response" Version="2.0" IssueInstant="#{now}"
                Destination="#{ACS_URL}" InResponseTo="#{request_id}">
  <saml:Issuer>#{settings.idp_entity_id}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  #{document}
</samlp:Response>
XML
  end

  private

  def soap_header(message, namespace, name)
    document = REXML::Document.new(message)
    header = envelope_part(document, "Header")
    header.elements.to_a.find { |node| node.namespace == namespace && node.name == name }
  end

  def soap_body_node(message, namespace, name)
    document = REXML::Document.new(message)
    body = envelope_part(document, "Body")
    body.elements.to_a.find { |node| node.namespace == namespace && node.name == name }
  end

  def envelope_part(document, name)
    document.root.elements.to_a.find do |node|
      node.namespace == OneLogin::RubySaml::EcpMessage::SOAP_ENVELOPE && node.name == name
    end
  end

  class FakeEcpFlow
    attr_reader :initial_request, :idp_http_request, :idp_request, :sp_http_request

    def initialize(test, options = {})
      @test = test
      @options = options
    end

    def call(request)
      case request.url
      when SP_URL
        @initial_request = request
        initial_response
      when @test.settings.idp_sso_service_url
        @idp_http_request = request
        idp_response
      when @test.settings.assertion_consumer_service_url
        @sp_http_request = request
        [200, { "Content-Type" => OneLogin::RubySaml::EcpMessage::CONTENT_TYPE }, ""]
      end
    end

    private

    def initial_response
      authn_request = OneLogin::RubySaml::Authrequest.new
      authn_request.uuid = EcpTest::REQUEST_ID
      message = OneLogin::RubySaml::EcpAuthnRequest.create(@test.settings, :authn_request => authn_request)
      [200, { "Content-Type" => OneLogin::RubySaml::EcpMessage::PAOS_CONTENT_TYPE }, message.raw_message]
    end

    def idp_response
      @idp_request = OneLogin::RubySaml::EcpIdpRequest.new(@idp_http_request.body, @test.settings)
      unless @idp_request.valid?
        raise OneLogin::RubySaml::ValidationError.new(@idp_request.errors.join(", "))
      end

      consumer_url = if @options[:wrong_consumer_url]
                       "https://attacker.example/acs"
                     else
                       @test.settings.assertion_consumer_service_url
                     end
      saml_response = @test.signed_saml_response(@idp_request.request_id)
      message = OneLogin::RubySaml::EcpResponse.create(@test.settings, saml_response, consumer_url)
      [200, { "Content-Type" => OneLogin::RubySaml::EcpMessage::CONTENT_TYPE }, message.raw_message]
    end
  end
end
