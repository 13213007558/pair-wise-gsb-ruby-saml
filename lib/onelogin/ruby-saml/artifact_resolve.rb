require "rexml/document"

require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/utils"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ArtifactResolve request (Builder)
    #
    class ArtifactResolve < SamlMessage
      SOAP_ENVELOPE_NS = "http://schemas.xmlsoap.org/soap/envelope/".freeze

      # ArtifactResolve ID
      attr_accessor :uuid

      # Initializes the ArtifactResolve request. Asigns an ID, a random uuid.
      #
      def initialize
        @uuid = OneLogin::RubySaml::Utils.uuid
      end

      def request_id
        @uuid
      end

      # Creates the samlp:ArtifactResolve document.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param samlart [String] The SAMLart parameter value received on the callback
      # @return [XMLSecurity::Document] The ArtifactResolve document
      #
      def create_xml_document(settings, samlart)
        time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        request_doc = XMLSecurity::Document.new
        request_doc.uuid = uuid

        root = request_doc.add_element "samlp:ArtifactResolve", {
          "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
          "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
        }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = "2.0"

        if settings.sp_entity_id
          issuer = root.add_element "saml:Issuer"
          issuer.text = settings.sp_entity_id
        end

        artifact = root.add_element "samlp:Artifact"
        artifact.text = samlart

        sign_document(request_doc, settings)
      end

      # Creates the SOAP envelope that carries the ArtifactResolve request
      # to the IdP Artifact Resolution Service endpoint.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param samlart [String] The SAMLart parameter value received on the callback
      # @return [String] The SOAP envelope
      #
      def create_soap_envelope(settings, samlart)
        resolve_xml = "".dup
        create_xml_document(settings, samlart).write(resolve_xml)

        envelope = "<soap:Envelope xmlns:soap=\"#{SOAP_ENVELOPE_NS}\"><soap:Body>#{resolve_xml}</soap:Body></soap:Envelope>"

        Logging.debug "Created ArtifactResolve SOAP envelope: #{envelope}"

        envelope
      end

      # Signs the ArtifactResolve document when the SP is configured to sign
      # its requests and owns a signing key pair.
      # @param document [XMLSecurity::Document] The ArtifactResolve document
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @return [XMLSecurity::Document] The (maybe signed) document
      #
      def sign_document(document, settings)
        cert, private_key = settings.get_sp_signing_pair
        if settings.security[:authn_requests_signed] && private_key && cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        document
      end
    end
  end
end
