require "rexml/document"
require "rexml/xpath"

require "xml_security"
require "onelogin/ruby-saml/error_handling"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/utils"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ArtifactResponse. Received from the IdP Artifact Resolution
    # Service (SOAP binding) as the answer of an ArtifactResolve request.
    # Carries the actual SAML message (usually a samlp:Response) that the
    # artifact referenced.
    #
    class ArtifactResponse < SamlMessage
      include ErrorHandling

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      DSIG      = "http://www.w3.org/2000/09/xmldsig#"
      SOAP_ENVELOPE_NS = "http://schemas.xmlsoap.org/soap/envelope/"
      SAML_NAMESPACES = {
        "p" => PROTOCOL,
        "a" => ASSERTION
      }.freeze

      # OneLogin::RubySaml::Settings Toolkit settings
      attr_accessor :settings

      attr_reader :document
      attr_reader :response
      attr_reader :options

      attr_accessor :soft

      # Constructs the SAML ArtifactResponse.
      # @param response [String] The body returned by the Artifact Resolution
      #                          Service (a SOAP envelope or a bare samlp:ArtifactResponse)
      # @param options  [Hash]   :settings to provide the OneLogin::RubySaml::Settings object
      #                          and :matches_request_id to validate that the InResponseTo
      #                          attribute matches the ID of the ArtifactResolve request sent
      #
      def initialize(response, options = {})
        raise ArgumentError.new("ArtifactResponse cannot be nil") if response.nil?

        @errors = []

        @options = options
        @soft = true
        unless options[:settings].nil?
          @settings = options[:settings]
          unless @settings.soft.nil?
            @soft = @settings.soft
          end
        end

        @response = response
        @document = XMLSecurity::SignedDocument.new(unwrap_envelope(@response), @errors)
      end

      # Validates the SAML ArtifactResponse with the default values (soft = true)
      # @param collect_errors [Boolean] Stop validation when the first error appears or keep validating. (if soft=true)
      # @return [Boolean] TRUE if the SAML ArtifactResponse is valid
      #
      def is_valid?(collect_errors = false)
        validate(collect_errors)
      end

      # @return [String|nil] Gets the Version attribute from the ArtifactResponse if exists.
      #
      def version(document)
        @version ||= begin
          node = REXML::XPath.first(
            document,
            "/p:ArtifactResponse",
            { "p" => PROTOCOL }
          )
          node.nil? ? nil : node.attributes['Version']
        end
      end

      # @return [String|nil] Gets the ID attribute from the ArtifactResponse if exists.
      #
      def id(document)
        @id ||= begin
          node = REXML::XPath.first(
            document,
            "/p:ArtifactResponse",
            { "p" => PROTOCOL }
          )
          node.nil? ? nil : node.attributes['ID']
        end
      end

      # @return [String|nil] The ID of the ArtifactResponse
      #
      def artifact_response_id
        id(document)
      end

      # @return [String|nil] The InResponseTo attribute of the ArtifactResponse
      #
      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(
            document,
            "/p:ArtifactResponse",
            { "p" => PROTOCOL }
          )
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      # @return [Array] The Issuer elements of the ArtifactResponse
      #
      def issuers
        @issuers ||= begin
          nodes = REXML::XPath.match(
            document,
            "/p:ArtifactResponse/a:Issuer",
            SAML_NAMESPACES
          )
          nodes.map { |node| Utils.element_text(node) }.reject(&:empty?).uniq
        end
      end

      # Checks if the Status has the "Success" code
      # @return [Boolean] True if the StatusCode is Success
      #
      def success?
        status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
      end

      # @return [String] StatusCode value from the ArtifactResponse.
      #
      def status_code
        @status_code ||= begin
          nodes = REXML::XPath.match(
            document,
            "/p:ArtifactResponse/p:Status/p:StatusCode",
            { "p" => PROTOCOL }
          )
          if nodes.size == 1
            node = nodes[0]
            node.attributes["Value"] if node && node.attributes
          end
        end
      end

      # @return [String] the StatusMessage value from the ArtifactResponse.
      #
      def status_message
        @status_message ||= begin
          nodes = REXML::XPath.match(
            document,
            "/p:ArtifactResponse/p:Status/p:StatusMessage",
            { "p" => PROTOCOL }
          )
          if nodes.size == 1
            Utils.element_text(nodes.first)
          end
        end
      end

      # @return [REXML::Element|nil] The inner SAML message (samlp:Response)
      #   referenced by the artifact
      #
      def inner_response_node
        REXML::XPath.first(
          document,
          "/p:ArtifactResponse/p:Response",
          { "p" => PROTOCOL }
        )
      end

      # @return [String|nil] The serialized inner SAML message
      #
      def inner_response
        node = inner_response_node
        return nil if node.nil?

        node.to_s
      end

      private

      # Extracts the samlp:ArtifactResponse element from the SOAP envelope,
      # when the received body is a SOAP message.
      # @param xml [String] The body returned by the Artifact Resolution Service
      # @return [String] The samlp:ArtifactResponse document
      # @raise [ValidationError] If no samlp:ArtifactResponse element is found
      #
      def unwrap_envelope(xml)
        raise ValidationError.new("Blank artifact resolution response") if xml.nil? || xml.empty?

        doc = REXML::Document.new(xml)
        root = doc.root

        if root && root.name == "Envelope"
          artifact_response = REXML::XPath.first(
            root,
            "soap:Body/samlp:ArtifactResponse",
            { "soap" => SOAP_ENVELOPE_NS, "samlp" => PROTOCOL }
          )
          if artifact_response.nil?
            raise ValidationError.new("No samlp:ArtifactResponse found on the SOAP response")
          end

          return artifact_response.to_s
        end

        xml
      rescue REXML::ParseException => error
        raise ValidationError.new("Invalid XML received from the artifact resolution endpoint: #{error.message}")
      end

      # Validates the SAML ArtifactResponse (calls several validation methods)
      # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
      # @return [Boolean] True if the SAML ArtifactResponse is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(collect_errors = false)
        reset_errors!
        return false unless validate_response_state

        validations = [
          :validate_version,
          :validate_id,
          :validate_success_status,
          :validate_in_response_to,
          :validate_issuer,
          :validate_num_inner_response,
          :validate_signature
        ]

        if collect_errors
          validations.each { |validation| send(validation) }
          @errors.empty?
        else
          validations.all? { |validation| send(validation) }
        end
      end

      # Validates that the ArtifactResponse provided in the initialization is not empty,
      # also checks that the settings and the IdP cert were also provided
      # @return [Boolean] True if the required info is found, false otherwise
      #
      def validate_response_state
        return append_error("Blank response") if response.nil? || response.empty?

        return append_error("No settings on response") if settings.nil?

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil? && settings.idp_cert_multi.nil?
          return append_error("No fingerprint or certificate on settings")
        end

        true
      end

      # Validates the SAML version (2.0)
      # @return [Boolean] True if the ArtifactResponse is 2.0, otherwise returns False
      #
      def validate_version
        unless version(document) == "2.0"
          return append_error("Unsupported SAML version")
        end

        true
      end

      # Validates that the ArtifactResponse contains an ID
      # @return [Boolean] True if the ArtifactResponse contains an ID, otherwise returns False
      #
      def validate_id
        unless artifact_response_id
          return append_error("Missing ID attribute on SAML ArtifactResponse")
        end

        true
      end

      # Validates the Status of the ArtifactResponse
      # @return [Boolean] True if the ArtifactResponse contains a Success code, otherwise False if soft == false
      #
      def validate_success_status
        return true if success?

        error_msg = 'The status code of the ArtifactResponse was not Success'
        status_error_msg = OneLogin::RubySaml::Utils.status_error_msg(error_msg, status_code, status_message)
        append_error(status_error_msg)
      end

      # Validates that the InResponseTo matches the ID of the ArtifactResolve
      # request that was sent (when provided on the :matches_request_id option)
      # @return [Boolean] True if it matches, otherwise False if soft=True
      #
      def validate_in_response_to
        return true unless options.has_key? :matches_request_id
        return true if options[:matches_request_id].nil?
        return true unless options[:matches_request_id] != in_response_to

        error_msg = "The InResponseTo of the ArtifactResponse: #{in_response_to}, does not match the ID of the ArtifactResolve sent by the SP: #{options[:matches_request_id]}"
        append_error(error_msg)
      end

      # Validates the Issuer of the ArtifactResponse against the trusted IdP entityID
      # @return [Boolean] True if the Issuer matches the IdP entityId, otherwise False if soft=True
      #
      def validate_issuer
        return true if settings.idp_entity_id.nil?

        if issuers.empty?
          return append_error("Issuer of the ArtifactResponse not found")
        end

        issuers.each do |issuer|
          unless OneLogin::RubySaml::Utils.uri_match?(issuer, settings.idp_entity_id)
            error_msg = "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>"
            return append_error(error_msg)
          end
        end

        true
      end

      # Validates that the ArtifactResponse carries exactly one inner SAML message
      # @return [Boolean] True if one inner samlp:Response is found, otherwise False
      #
      def validate_num_inner_response
        responses = REXML::XPath.match(
          document,
          "/p:ArtifactResponse/p:Response",
          { "p" => PROTOCOL }
        )

        unless responses.size == 1
          return append_error("SAML ArtifactResponse must contain 1 inner Response")
        end

        true
      end

      # Validates the Signature of the ArtifactResponse, when signed.
      # An unsigned ArtifactResponse relies on the confidentiality and
      # authenticity of the transport channel (TLS).
      # @return [Boolean] True if not signed or if the Signature is valid, otherwise False if soft=True
      #
      def validate_signature
        error_msg = "Invalid Signature on SAML ArtifactResponse"

        # Only a Signature that is a direct child of the ArtifactResponse
        # element is considered. Signatures of the inner message are
        # validated later by the OneLogin::RubySaml::Response chain.
        sig_elements = REXML::XPath.match(
          document,
          "/p:ArtifactResponse/ds:Signature",
          { "p" => PROTOCOL, "ds" => DSIG }
        )

        return true if sig_elements.empty?

        if sig_elements.size > 1
          append_error("Signed element id ##{document.signed_element_id} is found more than once")
          return append_error(error_msg)
        end

        unless document.signed_element_id == artifact_response_id
          append_error("Signed element id ##{document.signed_element_id} is not the ArtifactResponse id")
          return append_error(error_msg)
        end

        old_errors = @errors.clone

        idp_certs = settings.get_idp_cert_multi
        if idp_certs.nil? || idp_certs[:signing].empty?
          opts = {}
          opts[:fingerprint_alg] = settings.idp_cert_fingerprint_algorithm
          opts[:cert] = settings.get_idp_cert
          fingerprint = settings.get_fingerprint

          unless fingerprint && document.validate_document(fingerprint, @soft, opts)
            return append_error(error_msg)
          end
        else
          valid = false
          idp_certs[:signing].each do |idp_cert|
            valid = document.validate_document_with_cert(idp_cert, true)
            if valid
              @errors = old_errors
              break
            end
          end

          unless valid
            @errors = @errors.uniq
            return append_error(error_msg)
          end
        end

        true
      end
    end
  end
end
