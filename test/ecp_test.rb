require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/authrequest'
require 'onelogin/ruby-saml/ecp'

class EcpTest < Minitest::Test
  SOAP_NS = OneLogin::RubySaml::Ecp::SOAP_NS
  PAOS_NS = OneLogin::RubySaml::Ecp::PAOS_NS
  ECP_NS = OneLogin::RubySaml::Ecp::ECP_NS

  class FakeServiceProvider
    include OneLogin::RubySaml

    def initialize(settings, relay_state)
      @settings = settings
      @relay_state = relay_state
    end

    def initiate(headers)
      raise OneLogin::RubySaml::ValidationError.new("PAOS request expected") unless Ecp.paos_request?(headers)

      request_document = Authrequest.new.create_authentication_xml_doc(@settings)
      request_xml = "".dup
      request_document.write(request_xml)

      {
        :status => 200,
        :headers => Ecp.sp_response_headers,
        :body => Ecp.sp_authn_request(
          request_xml,
          @settings.assertion_consumer_service_url,
          @relay_state
        )
      }
    end

    def consume(soap_message)
      message = Ecp.parse_assertion_consumer_message(soap_message)
      response = Response.new(message.body_xml, :settings => @settings)

      {
        :relay_state => message.relay_state,
        :response => response,
        :raw_response => message.body_xml
      }
    end
  end

  class FakeIdentityProvider
    include OneLogin::RubySaml

    def handle(soap_message)
      message = Ecp.parse_soap(soap_message)
      unless message.body.name == "AuthnRequest"
        raise OneLogin::RubySaml::ValidationError.new("AuthnRequest expected")
      end
      unless message.headers.empty?
        raise OneLogin::RubySaml::ValidationError.new("SP ECP headers must not be forwarded to the IdP")
      end

      response_consumer_url = message.body.attributes["AssertionConsumerServiceURL"]
      response_xml = <<-XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="_response_1"
                InResponseTo="#{message.body.attributes["ID"]}"
                Version="2.0"
                Destination="#{response_consumer_url}">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>
      XML

      {
        :status => 200,
        :headers => Ecp.idp_response_headers,
        :body => Ecp.idp_response(response_xml, response_consumer_url)
      }
    end
  end

  class FakeEcpClient
    def initialize
      @exchange = OneLogin::RubySaml::Ecp::Client.new
    end

    def authenticate(service_provider, identity_provider)
      sp_initiation = service_provider.initiate(@exchange.sp_headers)
      idp_request = @exchange.from_sp(sp_initiation[:body])

      idp_response = identity_provider.handle(idp_request[:body])
      sp_response = @exchange.from_idp(
        idp_response[:body],
        idp_request[:response_consumer_url],
        idp_request[:relay_state]
      )

      {
        :request_id => idp_request[:request_id],
        :idp_request => idp_request,
        :idp_response => idp_response,
        :sp_response => sp_response,
        :result => service_provider.consume(sp_response[:body])
      }
    end
  end

  describe "ECP" do
    let(:relay_state) { "https://sp.example/return?a=1&b=2#fragment" }
    let(:settings) do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_sso_service_url = "https://idp.example/sso"
      settings.assertion_consumer_service_url = "https://sp.example/acs"
      settings.sp_entity_id = "https://sp.example"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      settings
    end

    it "identifies PAOS requests from hash and array headers" do
      headers = OneLogin::RubySaml::Ecp.request_headers
      assert OneLogin::RubySaml::Ecp.paos_request?(headers)
      assert OneLogin::RubySaml::Ecp.paos_request?(headers.to_a)

      refute OneLogin::RubySaml::Ecp.paos_request?("Accept" => "text/html")
      refute OneLogin::RubySaml::Ecp.paos_request?(
        "Accept" => OneLogin::RubySaml::Ecp::PAOS_CONTENT_TYPE,
        "PAOS" => %Q{ver="#{PAOS_NS}"; "urn:wrong"}
      )
    end

    it "completes the SP -> ECP client -> IdP -> SP exchange without HTTP" do
      service_provider = FakeServiceProvider.new(settings, relay_state)
      identity_provider = FakeIdentityProvider.new
      client = FakeEcpClient.new

      result = client.authenticate(service_provider, identity_provider)
      idp_request = result[:idp_request]
      idp_response = result[:idp_response]
      sp_response = result[:sp_response]

      assert_equal "https://idp.example/sso", idp_request[:url]
      assert_match(/\A_[0-9a-f\-]+\z/, result[:request_id])
      assert_equal relay_state, idp_request[:relay_state]
      assert_equal(
        {
          "Content-Type" => "text/xml; charset=utf-8",
          "SOAPAction" => "http://www.oasis-open.org/committees/security"
        },
        idp_request[:headers]
      )
      refute idp_request[:headers].key?("PAOS")
      refute idp_request[:headers].key?("Accept")

      assert soap_header_nodes(idp_request[:body]).empty?
      assert idp_request[:body].include?("<samlp:AuthnRequest")

      assert_equal(
        {"Content-Type" => "text/xml; charset=utf-8"},
        idp_response[:headers]
      )
      idp_headers = soap_header_nodes(idp_response[:body])
      assert_equal 1, idp_headers.size
      assert_equal "Response", idp_headers.first.name
      assert_equal "1", idp_headers.first.attributes.get_attribute_ns(SOAP_NS, "mustUnderstand").value
      assert_nil idp_headers.first.attributes.get_attribute_ns(SOAP_NS, "actor")

      assert_equal "https://sp.example/acs", sp_response[:url]
      assert_equal(
        {"Content-Type" => "application/vnd.paos+xml"},
        sp_response[:headers]
      )
      refute sp_response[:headers].key?("SOAPAction")

      final_headers = soap_header_nodes(sp_response[:body])
      assert_equal 1, final_headers.size
      assert_equal "RelayState", final_headers.first.name
      assert_equal ECP_NS, final_headers.first.namespace
      assert_equal relay_state, final_headers.first.text
      assert_soap_control(final_headers.first)

      consumed = result[:result]
      assert_equal relay_state, consumed[:relay_state]
      assert_equal result[:request_id], consumed[:response].in_response_to
      assert_equal "https://sp.example/acs", consumed[:response].destination
      refute consumed[:raw_response].include?("RelayState")
      refute consumed[:raw_response].include?(relay_state)
    end

    it "requires the PAOS and ECP request headers in the first SOAP message" do
      auth_request = valid_authn_request
      valid_message = OneLogin::RubySaml::Ecp.sp_authn_request(
        auth_request,
        settings.assertion_consumer_service_url,
        relay_state
      )

      [
        ["paos:Request", PAOS_NS],
        ["ecp:Request", ECP_NS],
        ["ecp:RelayState", ECP_NS]
      ].each do |name, namespace|
        message = remove_soap_header(valid_message, namespace, name.split(":").last)
        if name == "ecp:RelayState"
          parsed = OneLogin::RubySaml::Ecp.parse_authn_request(message)
          assert_nil parsed.relay_state
        else
          assert_raises(OneLogin::RubySaml::ValidationError) do
            OneLogin::RubySaml::Ecp.parse_authn_request(message)
          end
        end
      end
    end

    it "verifies responseConsumerURL at both SOAP exchanges" do
      auth_request = valid_authn_request
      message = OneLogin::RubySaml::Ecp.sp_authn_request(
        auth_request,
        "https://sp.example/wrong-acs",
        relay_state
      )

      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::Ecp.parse_authn_request(message)
      end

      valid_message = OneLogin::RubySaml::Ecp.sp_authn_request(
        valid_authn_request,
        settings.assertion_consumer_service_url,
        relay_state
      )
      parsed_request = OneLogin::RubySaml::Ecp.parse_authn_request(valid_message)
      idp_message = OneLogin::RubySaml::Ecp.idp_request(parsed_request.request)
      idp_response = OneLogin::RubySaml::Ecp.idp_response(
        valid_response(parsed_request.body.attributes["ID"], "https://sp.example/wrong-acs"),
        "https://sp.example/wrong-acs"
      )

      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::Ecp::Client.new.from_idp(
          idp_response,
          "https://sp.example/acs"
        )
      end

      assert parsed_request.request.include?("<samlp:AuthnRequest")
      assert idp_message.include?("AssertionConsumerServiceURL")
    end

    it "rejects unknown mustUnderstand SOAP headers and control headers on the final hop" do
      message = OneLogin::RubySaml::Ecp.sp_authn_request(
        valid_authn_request,
        settings.assertion_consumer_service_url,
        relay_state
      )
      invalid = add_soap_header(message, "custom:Blocked", "urn:custom", "custom", "blocked")

      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::Ecp.parse_authn_request(invalid)
      end

      response = OneLogin::RubySaml::Ecp.idp_response(
        valid_response("_request_1", settings.assertion_consumer_service_url),
        settings.assertion_consumer_service_url
      )
      parsed_idp_response = OneLogin::RubySaml::Ecp.parse_response(response)
      assert_equal settings.assertion_consumer_service_url,
                   parsed_idp_response.assertion_consumer_service_url
      invalid_response = add_soap_header(response, "paos:Request", PAOS_NS, "paos", "request")

      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::Ecp.parse_response(invalid_response)
      end

      injected_relay_state = add_soap_header(
        OneLogin::RubySaml::Ecp.idp_response(
          valid_response("_request_1", settings.assertion_consumer_service_url),
          settings.assertion_consumer_service_url
        ),
        "ecp:RelayState",
        ECP_NS,
        "ecp",
        "injected"
      )

      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::Ecp.parse_response(injected_relay_state)
      end
    end

    def valid_authn_request
      <<-XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                   ID="_request_1"
                   Version="2.0"
                   Destination="https://idp.example/sso"
                   AssertionConsumerServiceURL="#{settings.assertion_consumer_service_url}">
  <saml:Issuer>#{settings.sp_entity_id}</saml:Issuer>
</samlp:AuthnRequest>
      XML
    end

    def valid_response(request_id, consumer_url)
      <<-XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="_response_1"
                InResponseTo="#{request_id}"
                Version="2.0"
                Destination="#{consumer_url}">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>
      XML
    end

    def soap_header_nodes(xml)
      document = REXML::Document.new(xml)
      REXML::XPath.match(document, "/soap:Envelope/soap:Header/*", "soap" => SOAP_NS)
    end

    def assert_soap_control(node)
      assert_equal "1", node.attributes.get_attribute_ns(SOAP_NS, "mustUnderstand").value
      assert_equal OneLogin::RubySaml::Ecp::SOAP_ACTOR,
                   node.attributes.get_attribute_ns(SOAP_NS, "actor").value
    end

    def remove_soap_header(xml, namespace, name)
      document = REXML::Document.new(xml)
      node = REXML::XPath.first(
        document,
        "//*[local-name()='#{name}' and namespace-uri()='#{namespace}']"
      )
      node.parent.delete(node)
      document.to_s
    end

    def add_soap_header(xml, tag, namespace, prefix, text)
      document = REXML::Document.new(xml)
      header = REXML::XPath.first(document, "/soap:Envelope/soap:Header", "soap" => SOAP_NS)
      document.root.add_namespace(prefix, namespace)
      node = header.add_element(tag)
      node.add_attribute("soap:mustUnderstand", "1")
      node.add_attribute("soap:actor", OneLogin::RubySaml::Ecp::SOAP_ACTOR)
      node.text = text
      document.to_s
    end
  end
end
