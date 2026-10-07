require 'onelogin/ruby-saml/saml_message'
require 'onelogin/ruby-saml/utils'
require 'xml_security'

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ArtifactResolve protocol message, sent over SOAP to the IdP
    # ArtifactResolutionService endpoint to dereference a SAML artifact.
    #
    class ArtifactResolve < SamlMessage
      SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/".freeze

      attr_reader :settings, :artifact

      # OneLogin::RubySaml::Settings Toolkit settings
      # OneLogin::RubySaml::Artifact The artifact to resolve
      def initialize(settings, artifact)
        @settings = settings
        @artifact = artifact
      end

      # @return [String] The ID of the ArtifactResolve request, used later
      #   to match the InResponseTo of the ArtifactResponse.
      def uuid
        @uuid ||= OneLogin::RubySaml::Utils.uuid
      end

      # @return [String] The ArtifactResolve request as XML. The request
      #   is signed when security[:authn_requests_signed] is enabled and
      #   an SP signing certificate is configured.
      def to_xml
        document = create_xml_document
        sign_document(document)
        document.to_s
      end

      # @return [String] The ArtifactResolve request wrapped in a SOAP
      #   envelope, ready to be posted to the resolution endpoint.
      def to_soap
        envelope = REXML::Document.new
        envelope.add_element("soap-env:Envelope", "xmlns:soap-env" => SOAP_ENV)
        body = envelope.root.add_element("soap-env:Body")
        body.add_element(REXML::Document.new(to_xml).root)
        envelope.to_s
      end

      private

      def create_xml_document
        time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        request_doc = XMLSecurity::Document.new
        request_doc.uuid = uuid

        root = request_doc.add_element "samlp:ArtifactResolve", {
          "xmlns:samlp" => SamlMessage::PROTOCOL,
          "xmlns:saml" => SamlMessage::ASSERTION
        }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = "2.0"

        if settings.sp_entity_id
          issuer = root.add_element "saml:Issuer"
          issuer.text = settings.sp_entity_id
        end

        artifact_element = root.add_element "samlp:Artifact"
        artifact_element.text = artifact.to_s

        request_doc
      end

      def sign_document(document)
        cert, private_key = settings.get_sp_signing_pair
        if settings.security[:authn_requests_signed] && private_key && cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        document
      end
    end
  end
end
