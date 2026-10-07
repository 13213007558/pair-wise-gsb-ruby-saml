require 'securerandom'
require 'digest/sha1'
require 'rexml/document'
require 'rexml/xpath'

# Helpers to build SAML artifacts, ArtifactResponse SOAP envelopes and
# local transport doubles for the HTTP Artifact binding tests.
#
module ArtifactHelper
  IDP_ENTITY_ID = "https://idp.example.com/saml/metadata".freeze
  SP_ENTITY_ID = "https://sp.example.com/saml/metadata".freeze
  ACS_URL = "https://sp.example.com/saml/acs".freeze
  ARTIFACT_ENDPOINT_0 = "https://idp.example.com/saml/artifact".freeze
  ARTIFACT_ENDPOINT_1 = "https://idp.example.com/saml/artifact/secondary".freeze

  SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/".freeze
  SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
  SAML = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
  STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze

  def xml_time(time)
    time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
  end

  # Builds a type 0x0004 artifact bound to the trusted IdP.
  def build_artifact(endpoint_index: 0, source_id: nil, message_handle: nil)
    source_id ||= Digest::SHA1.digest(IDP_ENTITY_ID)
    message_handle ||= SecureRandom.random_bytes(20)
    OneLogin::RubySaml::Artifact.build(endpoint_index, source_id, message_handle)
  end

  # Builds a schema-valid, response-level signed samlp:Response.
  def build_inner_response_xml(cert, key, overrides = {})
    now = Time.now.utc
    issuer = overrides.fetch(:issuer, IDP_ENTITY_ID)
    audience = overrides.fetch(:audience, SP_ENTITY_ID)
    destination = overrides.fetch(:destination, ACS_URL)
    name_id = overrides.fetch(:name_id, "user@example.com")
    not_before = overrides.fetch(:not_before, now - 60)
    not_on_or_after = overrides.fetch(:not_on_or_after, now + 300)
    response_id = "_#{SecureRandom.hex(16)}"
    assertion_id = "_#{SecureRandom.hex(16)}"

    xml = <<~XML
      <samlp:Response xmlns:samlp="#{SAMLP}" xmlns:saml="#{SAML}" ID="#{response_id}" Version="2.0" IssueInstant="#{xml_time(now)}" Destination="#{destination}">
        <saml:Issuer>#{issuer}</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="#{STATUS_SUCCESS}"/>
        </samlp:Status>
        <saml:Assertion Version="2.0" IssueInstant="#{xml_time(now)}" ID="#{assertion_id}">
          <saml:Issuer>#{issuer}</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{name_id}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData Recipient="#{destination}" NotOnOrAfter="#{xml_time(not_on_or_after)}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="#{xml_time(not_before)}" NotOnOrAfter="#{xml_time(not_on_or_after)}">
            <saml:AudienceRestriction>
              <saml:Audience>#{audience}</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="#{xml_time(now)}">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
        </saml:Assertion>
      </samlp:Response>
    XML

    document = XMLSecurity::Document.new(xml)
    document.uuid = response_id
    document.sign_document(key, cert)
    document.to_s
  end

  # Builds a SOAP envelope carrying a (by default signed) ArtifactResponse
  # that wraps the given inner SAML message.
  def build_artifact_response_soap(cert, key, resolve_id:, inner_xml:, overrides: {})
    artifact_response_id = "_#{SecureRandom.hex(16)}"
    issuer = overrides.fetch(:issuer, IDP_ENTITY_ID)
    status = overrides.fetch(:status, STATUS_SUCCESS)
    in_response_to = overrides.fetch(:in_response_to, resolve_id)
    sign = overrides.fetch(:sign, true)
    status_message = overrides[:status_message]

    status_message_xml = status_message ? "<samlp:StatusMessage>#{status_message}</samlp:StatusMessage>" : ""

    xml = <<~XML
      <samlp:ArtifactResponse xmlns:samlp="#{SAMLP}" xmlns:saml="#{SAML}" ID="#{artifact_response_id}" InResponseTo="#{in_response_to}" Version="2.0" IssueInstant="#{xml_time(Time.now.utc)}">
        <saml:Issuer>#{issuer}</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="#{status}"/>
          #{status_message_xml}
        </samlp:Status>
        #{inner_xml}
      </samlp:ArtifactResponse>
    XML

    document = XMLSecurity::Document.new(xml)
    document.uuid = artifact_response_id
    document.sign_document(key, cert) if sign

    <<~XML
      <soap-env:Envelope xmlns:soap-env="#{SOAP_ENV}">
        <soap-env:Body>
          #{document}
        </soap-env:Body>
      </soap-env:Envelope>
    XML
  end

  # Extracts the ID of the ArtifactResolve request carried by a SOAP
  # envelope, so a transport double can answer with a matching
  # InResponseTo.
  def resolve_id_from(soap_envelope)
    document = REXML::Document.new(soap_envelope)
    node = REXML::XPath.first(document, "//samlp:ArtifactResolve", "samlp" => SAMLP)
    node && node.attributes["ID"]
  end

  def artifact_settings(cert, overrides = {})
    OneLogin::RubySaml::Settings.new.tap do |settings|
      settings.idp_entity_id = IDP_ENTITY_ID
      settings.idp_cert = cert.to_pem if cert
      settings.sp_entity_id = SP_ENTITY_ID
      settings.assertion_consumer_service_url = ACS_URL
      settings.idp_artifact_resolution_services = {
        0 => ARTIFACT_ENDPOINT_0,
        1 => ARTIFACT_ENDPOINT_1
      }
      overrides.each { |key, value| settings.send("#{key}=", value) }
    end
  end

  # Local transport double. The handler block receives
  # (url, soap_envelope) and must return the SOAP response body.
  class FakeTransport
    attr_reader :requests

    def initialize(&handler)
      @handler = handler
      @requests = []
    end

    def post(url, soap_envelope)
      @requests << [url, soap_envelope]
      @handler.call(url, soap_envelope)
    end
  end
end

Minitest::Test.send(:include, ArtifactHelper)
