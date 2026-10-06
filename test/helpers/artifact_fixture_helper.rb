require 'base64'
require 'digest/sha1'
require 'securerandom'

# Builds SAML artifacts, ArtifactResponses and enclosed Responses
# for the HTTP-Artifact binding tests.
module ArtifactFixtureHelper
  extend self

  IDP_ENTITY_ID = "https://idp.example.com/saml/metadata".freeze
  SP_ENTITY_ID = "https://sp.example.com/saml/metadata".freeze
  ACS_URL = "https://sp.example.com/saml/acs".freeze
  AUTHN_REQUEST_ID = "_authn_request_1".freeze
  ARTIFACT_RESOLUTION_URL = "https://idp.example.com/saml/ars".freeze

  SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze

  def build_artifact(entity_id: IDP_ENTITY_ID, endpoint_index: 0, message_handle: "handle".ljust(20, "h"))
    Base64.strict_encode64([0x0004, endpoint_index].pack("nn") + Digest::SHA1.digest(entity_id) + message_handle)
  end

  def build_inner_response_xml(cert, key, in_response_to: AUTHN_REQUEST_ID)
    now = Time.now.utc
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = XMLSecurity::Document.new
    response_id = "_resp_#{SecureRandom.hex(8)}"
    doc.uuid = response_id

    root = doc.add_element "samlp:Response", {
        "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
        "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
    }
    root.attributes['ID'] = response_id
    root.attributes['Version'] = "2.0"
    root.attributes['IssueInstant'] = timestamp
    root.attributes['InResponseTo'] = in_response_to
    root.attributes['Destination'] = ACS_URL

    issuer = root.add_element "saml:Issuer"
    issuer.text = IDP_ENTITY_ID

    status = root.add_element "samlp:Status"
    status_code = status.add_element "samlp:StatusCode"
    status_code.attributes['Value'] = SUCCESS

    assertion = root.add_element "saml:Assertion"
    assertion.attributes['ID'] = "_assertion_#{SecureRandom.hex(8)}"
    assertion.attributes['Version'] = "2.0"
    assertion.attributes['IssueInstant'] = timestamp

    assertion_issuer = assertion.add_element "saml:Issuer"
    assertion_issuer.text = IDP_ENTITY_ID

    subject = assertion.add_element "saml:Subject"
    name_id = subject.add_element "saml:NameID"
    name_id.text = "user@example.com"
    confirmation = subject.add_element "saml:SubjectConfirmation"
    confirmation.attributes['Method'] = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    confirmation_data = confirmation.add_element "saml:SubjectConfirmationData"
    confirmation_data.attributes['Recipient'] = ACS_URL
    confirmation_data.attributes['InResponseTo'] = in_response_to
    confirmation_data.attributes['NotOnOrAfter'] = (now + 300).strftime("%Y-%m-%dT%H:%M:%SZ")

    conditions = assertion.add_element "saml:Conditions"
    conditions.attributes['NotBefore'] = (now - 300).strftime("%Y-%m-%dT%H:%M:%SZ")
    conditions.attributes['NotOnOrAfter'] = (now + 300).strftime("%Y-%m-%dT%H:%M:%SZ")
    audience_restriction = conditions.add_element "saml:AudienceRestriction"
    audience = audience_restriction.add_element "saml:Audience"
    audience.text = SP_ENTITY_ID

    authn_statement = assertion.add_element "saml:AuthnStatement"
    authn_statement.attributes['AuthnInstant'] = timestamp
    authn_statement.attributes['SessionIndex'] = "_session_1"
    authn_context = authn_statement.add_element "saml:AuthnContext"
    class_ref = authn_context.add_element "saml:AuthnContextClassRef"
    class_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"

    doc.sign_document(key, cert)

    xml = ""
    doc.write(xml)
    xml
  end

  def build_artifact_response_xml(inner_xml, cert, key, in_response_to:, sign: true, status_value: SUCCESS)
    doc = XMLSecurity::Document.new
    response_id = "_art_resp_#{SecureRandom.hex(8)}"
    doc.uuid = response_id

    root = doc.add_element "samlp:ArtifactResponse", {
        "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
        "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
    }
    root.attributes['ID'] = response_id
    root.attributes['Version'] = "2.0"
    root.attributes['IssueInstant'] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    root.attributes['InResponseTo'] = in_response_to

    issuer = root.add_element "saml:Issuer"
    issuer.text = IDP_ENTITY_ID

    status = root.add_element "samlp:Status"
    status_code = status.add_element "samlp:StatusCode"
    status_code.attributes['Value'] = status_value

    root.add(REXML::Document.new(inner_xml).root) if inner_xml

    doc.sign_document(key, cert) if sign

    xml = ""
    doc.write(xml)
    xml
  end

  def wrap_soap(xml)
    "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>#{xml}</soap:Body></soap:Envelope>"
  end
end
