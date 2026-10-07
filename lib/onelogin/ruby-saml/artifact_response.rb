require 'onelogin/ruby-saml/saml_message'
require 'onelogin/ruby-saml/artifact_error'
require 'onelogin/ruby-saml/utils'
require 'xml_security'
require 'rexml/document'
require 'rexml/xpath'

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ArtifactResponse protocol message, received as the body of the
    # SOAP reply of the IdP ArtifactResolutionService endpoint. It carries
    # the actual SAML protocol message (usually a samlp:Response) that the
    # artifact referenced.
    #
    class ArtifactResponse < SamlMessage
      DSIG = "http://www.w3.org/2000/09/xmldsig#".freeze
      SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/".freeze
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze

      SOAP_NAMESPACES = { "soap-env" => SOAP_ENV }.freeze
      SAML_NAMESPACES = { "samlp" => SamlMessage::PROTOCOL, "saml" => SamlMessage::ASSERTION, "ds" => DSIG }.freeze

      attr_reader :settings

      # @param soap_body [String] The SOAP envelope returned by the
      #   ArtifactResolutionService endpoint.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings.
      def initialize(soap_body, settings)
        if soap_body.nil? || soap_body.empty?
          raise ArtifactResolutionError.new("Blank ArtifactResponse")
        end

        @settings = settings
        @document = parse_envelope(soap_body)
        @artifact_response = extract_artifact_response(@document)
      end

      # Validates the ArtifactResponse envelope itself: InResponseTo,
      # Issuer, Status and Signature. The inner SAML message is validated
      # separately by the standard validation chain.
      # @param resolve_id [String] The ID of the ArtifactResolve request
      #   this response must answer.
      # @return [Boolean] true
      # @raise [ArtifactResolutionError] if any check fails.
      def validate!(resolve_id)
        validate_in_response_to(resolve_id)
        validate_issuer
        validate_status
        validate_signature
        true
      end

      # @return [String|nil] The XML of the SAML protocol message carried
      #   by the ArtifactResponse, or nil if there is none.
      def inner_message_xml
        node = inner_message_node
        node.nil? ? nil : node.to_s
      end

      private

      def parse_envelope(soap_body)
        REXML::Document.new(soap_body)
      rescue REXML::ParseException => error
        raise ArtifactResolutionError.new("Invalid SOAP envelope: #{error.message}")
      end

      def extract_artifact_response(document)
        node = REXML::XPath.first(
          document,
          "/soap-env:Envelope/soap-env:Body/samlp:ArtifactResponse",
          SOAP_NAMESPACES.merge(SAML_NAMESPACES)
        )
        # Tolerate responses without a SOAP envelope
        node ||= REXML::XPath.first(document, "/samlp:ArtifactResponse", SAML_NAMESPACES)

        if node.nil?
          raise ArtifactResolutionError.new("SOAP body does not contain an ArtifactResponse")
        end

        node
      end

      def validate_in_response_to(resolve_id)
        in_response_to = @artifact_response.attributes['InResponseTo']
        if in_response_to.nil? || in_response_to.empty?
          raise ArtifactResolutionError.new("Missing InResponseTo attribute on ArtifactResponse")
        end
        unless in_response_to == resolve_id
          raise ArtifactResolutionError.new(
            "The InResponseTo of the ArtifactResponse (#{in_response_to}) does not match the ArtifactResolve ID (#{resolve_id})"
          )
        end
      end

      def validate_issuer
        return if settings.idp_entity_id.nil?

        issuer_node = REXML::XPath.first(@artifact_response, "./saml:Issuer", SAML_NAMESPACES)
        issuer = issuer_node && OneLogin::RubySaml::Utils.element_text(issuer_node)
        if issuer.nil? || issuer.empty?
          raise ArtifactResolutionError.new("Missing Issuer on ArtifactResponse")
        end
        unless OneLogin::RubySaml::Utils.uri_match?(issuer, settings.idp_entity_id)
          raise ArtifactResolutionError.new(
            "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>"
          )
        end
      end

      def validate_status
        status_node = REXML::XPath.first(@artifact_response, "./samlp:Status/samlp:StatusCode", SAML_NAMESPACES)
        if status_node.nil?
          raise ArtifactResolutionError.new("Missing Status on ArtifactResponse")
        end

        code = status_node.attributes['Value']
        return if code == SUCCESS

        status_message_node = REXML::XPath.first(@artifact_response, "./samlp:Status/samlp:StatusMessage", SAML_NAMESPACES)
        status_message = status_message_node && OneLogin::RubySaml::Utils.element_text(status_message_node)
        raise ArtifactResolutionError.new(
          OneLogin::RubySaml::Utils.status_error_msg(
            "The status code of the ArtifactResponse was not Success", code, status_message
          )
        )
      end

      def validate_signature
        sig_elements = REXML::XPath.match(@artifact_response, "./ds:Signature", SAML_NAMESPACES)

        if sig_elements.empty?
          if settings.security[:want_artifact_response_signed]
            raise ArtifactResolutionError.new("ArtifactResponse is not signed")
          end
          return
        end

        signed_document = XMLSecurity::SignedDocument.new(@artifact_response.to_s)

        idp_certs = settings.get_idp_cert_multi
        if idp_certs.nil? || idp_certs[:signing].empty?
          opts = {}
          opts[:fingerprint_alg] = settings.idp_cert_fingerprint_algorithm
          opts[:cert] = settings.get_idp_cert
          fingerprint = settings.get_fingerprint

          unless fingerprint && signed_document.validate_document(fingerprint, true, opts)
            raise ArtifactResolutionError.new("Invalid Signature on ArtifactResponse")
          end
        else
          valid = idp_certs[:signing].any? do |idp_cert|
            signed_document.validate_document_with_cert(idp_cert, true)
          end
          unless valid
            raise ArtifactResolutionError.new("Invalid Signature on ArtifactResponse")
          end
        end
      end

      def inner_message_node
        children = @artifact_response.elements.to_a
        status_index = children.index { |element| element.name == 'Status' }
        return nil if status_index.nil?

        children[(status_index + 1)..]&.first
      end
    end
  end
end
