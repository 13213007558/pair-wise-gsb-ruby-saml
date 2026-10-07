require "xml_security"
require "onelogin/ruby-saml/saml_message"

module OneLogin
  module RubySaml
    class ManageNameIDResponse < SamlMessage
      include ErrorHandling

      attr_accessor :settings
      attr_accessor :soft
      attr_reader :document
      attr_reader :response
      attr_reader :options

      def initialize(response, settings = nil, options = {})
        raise ArgumentError.new("ManageNameIDResponse cannot be nil") if response.nil?
        @errors = []
        @settings = settings
        @options = options
        @soft = settings.nil? || settings.soft.nil? ? true : settings.soft

        raw = SamlMessage.extract_saml_from_soap(response) || response
        @response = decode_raw_saml(raw, settings)
        @document = XMLSecurity::SignedDocument.new(@response)
      end

      def response_id
        id(document)
      end

      def success?
        status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
      end

      def in_response_to
        root_node.nil? ? nil : root_node.attributes["InResponseTo"]
      end

      def destination
        root_node.nil? ? nil : root_node.attributes["Destination"]
      end

      def issuer
        @issuer ||= Utils.element_text(REXML::XPath.first(document, "/p:ManageNameIDResponse/a:Issuer", namespaces))
      end

      def status_code
        @status_code ||= begin
          nodes = REXML::XPath.match(document, "/p:ManageNameIDResponse/p:Status/p:StatusCode", namespaces)
          top = nodes.first
          code = top && top.attributes["Value"]
          if code && code != "urn:oasis:names:tc:SAML:2.0:status:Success"
            inner = REXML::XPath.match(document, "/p:ManageNameIDResponse/p:Status/p:StatusCode/p:StatusCode", namespaces).map { |node| node.attributes["Value"] }
            code = ([code] + inner).join(" | ") unless inner.empty?
          end
          code
        end
      end

      def status_message
        @status_message ||= Utils.element_text(REXML::XPath.first(document, "/p:ManageNameIDResponse/p:Status/p:StatusMessage", namespaces))
      end

      def validate(collect_errors = false)
        reset_errors!
        validations = [
          :valid_state?,
          :validate_id,
          :validate_version,
          :validate_structure,
          :validate_in_response_to,
          :validate_issuer,
          :validate_xml_signature
        ]

        if collect_errors
          validations.each { |validation| send(validation) }
          @errors.empty?
        else
          validations.all? { |validation| send(validation) }
        end
      end

      private

      def namespaces
        { "p" => PROTOCOL, "a" => ASSERTION }
      end

      def root_node
        @root_node ||= REXML::XPath.first(document, "/p:ManageNameIDResponse", namespaces)
      end

      def valid_state?
        return append_error("Blank ManageNameID response") if response.nil? || response.empty?
        return append_error("No settings on ManageNameID response") if settings.nil?
        return append_error("No sp_entity_id in settings of the ManageNameID response") if settings.sp_entity_id.nil?
        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil? && settings.idp_cert_multi.nil?
          return append_error("No fingerprint or certificate on settings of the ManageNameID response")
        end
        true
      end

      def validate_id
        response_id ? true : append_error("Missing ID attribute on ManageNameID Response")
      end

      def validate_version
        version(document) == "2.0" ? true : append_error("Unsupported SAML version")
      end

      def validate_structure
        return true if valid_saml?(document, soft, check_malformed_doc?(settings))
        append_error("Invalid SAML ManageNameID Response. Not match the saml-schema-protocol-2.0.xsd")
      end

      def validate_in_response_to
        expected = options[:matches_request_id]
        return true if expected.nil? || expected == in_response_to
        append_error("The InResponseTo of the ManageNameID Response: #{in_response_to}, does not match the ID of the ManageNameID Request: #{expected}")
      end

      def validate_issuer
        return true if settings.idp_entity_id.nil? || issuer.nil? || Utils.uri_match?(issuer, settings.idp_entity_id)
        append_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
      end

      def validate_xml_signature
        signatures = REXML::XPath.match(document, "/p:ManageNameIDResponse/ds:Signature", { "p" => PROTOCOL, "ds" => Utils::DSIG })
        return append_error("Missing Signature on ManageNameID Response") unless signatures.size == 1
        return append_error("Multiple Signatures on ManageNameID Response") if signatures.size > 1

        reference = REXML::XPath.first(signatures.first, "./ds:SignedInfo/ds:Reference", { "ds" => Utils::DSIG })
        reference_id = reference && reference.attributes["URI"]
        if reference_id.nil? || reference_id.sub(/\A#/, "") != response_id
          return append_error("Invalid Signature reference on ManageNameID Response")
        end

        idp_certs = settings.get_idp_cert_multi
        if idp_certs.nil? || idp_certs[:signing].empty?
          idp_cert = settings.get_idp_cert
          fingerprint = settings.get_fingerprint
          valid = document.validate_document(fingerprint, @soft, { :fingerprint_alg => settings.idp_cert_fingerprint_algorithm, :cert => idp_cert })
          if valid && settings.security[:check_idp_cert_expiration] && idp_cert && Utils.is_cert_expired(idp_cert)
            return append_error("IdP x509 certificate expired")
          end
          return append_error("Invalid Signature on ManageNameID Response") unless valid
        else
          valid = false
          idp_certs[:signing].each do |idp_cert|
            if document.validate_document_with_cert(idp_cert, true)
              return append_error("IdP x509 certificate expired") if settings.security[:check_idp_cert_expiration] && Utils.is_cert_expired(idp_cert)
              valid = true
              break
            end
          end
          return append_error("Invalid Signature on ManageNameID Response") unless valid
        end
        true
      end
    end
  end
end
