require "rexml/document"

require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/utils"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ArtifactResolve message (Builder). Sent by the SP to the IdP
    # Artifact Resolution Service to dereference a SAML artifact
    # (HTTP-Artifact binding).
    #
    class ArtifactResolve < SamlMessage

      # ArtifactResolve ID
      attr_accessor :uuid

      # Initializes the ArtifactResolve. Assigns an ID, a random uuid.
      #
      def initialize
        @uuid = OneLogin::RubySaml::Utils.uuid
      end

      def request_id
        @uuid
      end

      # Creates the ArtifactResolve message serialized as XML.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param artifact [String] The SAMLart value to be resolved
      # @return [String] The ArtifactResolve XML message
      #
      def create(settings, artifact)
        request_doc = create_xml_document(settings, artifact)
        request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        request = "".dup
        request_doc.write(request)

        Logging.debug "Created ArtifactResolve: #{request}"

        request
      end

      # Creates the SOAP envelope that carries the ArtifactResolve message,
      # as required by the SAML SOAP binding used on the
      # Artifact Resolution Service endpoint.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param artifact [String] The SAMLart value to be resolved
      # @return [String] The SOAP envelope XML
      #
      def create_soap_envelope(settings, artifact)
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" \
          "<soap:Body>#{create(settings, artifact)}</soap:Body>" \
          "</soap:Envelope>"
      end

      # Creates the samlp:ArtifactResolve XML document.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param artifact [String] The SAMLart value to be resolved
      # @return [XMLSecurity::Document] The ArtifactResolve document
      #
      def create_xml_document(settings, artifact)
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

        artifact_element = root.add_element "samlp:Artifact"
        artifact_element.text = artifact

        sign_document(request_doc, settings)
      end

      # Embeds a signature in the ArtifactResolve message when the SP is
      # configured to sign its requests.
      # @param document [XMLSecurity::Document] The ArtifactResolve document
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @return [XMLSecurity::Document] The (possibly signed) document
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
