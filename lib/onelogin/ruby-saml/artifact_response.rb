require "xml_security"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/error_handling"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ArtifactResponse (Parser). Returned by the IdP Artifact Resolution
    # Service in response to an ArtifactResolve message (HTTP-Artifact binding).
    # It carries the protocol message (usually a samlp:Response) that the
    # artifact referenced.
    #
    class ArtifactResponse < SamlMessage
      include ErrorHandling

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
      DSIG      = "http://www.w3.org/2000/09/xmldsig#".freeze
      SOAP_ENV  = "http://schemas.xmlsoap.org/soap/envelope/".freeze

      # Elements of the ArtifactResponse itself; the first child element
      # that is not one of these is the dereferenced protocol message.
      NON_MESSAGE_ELEMENTS = %w[Issuer Signature Extensions Status].freeze

      # OneLogin::RubySaml::Settings Toolkit settings
      attr_accessor :settings

      attr_reader :document
      attr_reader :response
      attr_reader :options

      attr_accessor :soft

      # Constructs the ArtifactResponse.
      # @param response [String] The raw XML of the ArtifactResponse, either bare
      #                          or wrapped in a SOAP envelope (as returned by the
      #                          Artifact Resolution Service).
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param options  [Hash] Extra parameters.
      #                        :matches_request_id It will validate that the ArtifactResponse
      #                        matches the ID of the ArtifactResolve sent by the SP.
      #
      # @raise [ArgumentError] if response is nil
      #
      def initialize(response, settings = nil, options = {})
        @errors = []
        raise ArgumentError.new("ArtifactResponse cannot be nil") if response.nil?
        @settings = settings

        if settings.nil? || settings.soft.nil?
          @soft = true
        else
          @soft = settings.soft
        end

        @options = options
        @response = response
        @document = XMLSecurity::SignedDocument.new(unwrap_soap_envelope(response))
      end

      def response_id
        id(document)
      end

      # Checks if the Status has the "Success" code
      # @return [Boolean] True if the StatusCode is Success
      #
      def success?
        status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
      end

      # @return [String|nil] Gets the InResponseTo attribute from the ArtifactResponse if exists.
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

      # @return [String] Gets the Issuer from the ArtifactResponse.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(
            document,
            "/p:ArtifactResponse/a:Issuer",
            { "p" => PROTOCOL, "a" => ASSERTION }
          )
          Utils.element_text(node)
        end
      end

      # @return [String] Gets the StatusCode from the ArtifactResponse.
      #
      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:ArtifactResponse/p:Status/p:StatusCode", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      # @return [String] Gets the StatusMessage from the ArtifactResponse.
      #
      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(
            document,
            "/p:ArtifactResponse/p:Status/p:StatusMessage",
            { "p" => PROTOCOL }
          )
          Utils.element_text(node)
        end
      end

      # @return [REXML::Element|nil] The protocol message carried by the
      #   ArtifactResponse (the dereferenced samlp:Response), if any.
      #
      def protocol_message
        root = document.root
        return nil if root.nil? || root.name != "ArtifactResponse"

        root.elements.find { |element| !NON_MESSAGE_ELEMENTS.include?(element.name) }
      end

      # @return [String] The XML of the protocol message carried by the ArtifactResponse.
      # @raise [ValidationError] if the ArtifactResponse carries no protocol message
      #
      def protocol_message_xml
        message = protocol_message
        raise ValidationError.new("The ArtifactResponse does not contain a protocol message") if message.nil?

        message.to_s
      end

      # Aux function to validate the ArtifactResponse
      # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
      # @return [Boolean] TRUE if the ArtifactResponse is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(collect_errors = false)
        reset_errors!

        validations = [
          :valid_state?,
          :validate_version,
          :validate_id,
          :validate_success_status,
          :validate_structure,
          :valid_in_response_to?,
          :valid_issuer?,
          :validate_protocol_message,
          :validate_signature
        ]

        if collect_errors
          validations.each { |validation| send(validation) }
          @errors.empty?
        else
          validations.all? { |validation| send(validation) }
        end
      end

      def is_valid?(collect_errors = false)
        validate(collect_errors)
      end

      private

      # Removes the SOAP envelope if the message arrived wrapped in one.
      # @param xml [String] The raw response body
      # @return [String] The bare ArtifactResponse XML
      #
      def unwrap_soap_envelope(xml)
        document = REXML::Document.new(xml)
        root = document.root
        return xml unless root && root.name == "Envelope"

        body = REXML::XPath.first(root, "soap:Body", { "soap" => SOAP_ENV })
        raise ValidationError.new("The SOAP Envelope does not contain a Body") if body.nil?

        message = body.elements.first
        raise ValidationError.new("The SOAP Body does not contain a SAML message") if message.nil?

        message.to_s
      rescue REXML::ParseException => error
        raise ValidationError.new("Invalid XML on ArtifactResponse: #{error.message}")
      end

      # Validates that the ArtifactResponse provided in the initialization is not empty,
      # also check that the settings and the IdP cert were also provided
      # @return [Boolean] True if the required info is found, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_state?
        return append_error("Blank artifact response") if response.nil? || response.empty?

        return append_error("No settings on artifact response") if settings.nil?

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil? && settings.idp_cert_multi.nil?
          return append_error("No fingerprint or certificate on settings of the artifact response")
        end

        true
      end

      # Validates that the ArtifactResponse contains an ID
      # @return [Boolean] True if the ArtifactResponse contains an ID, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_id
        unless response_id
          return append_error("Missing ID attribute on ArtifactResponse")
        end

        true
      end

      # Validates the SAML version (2.0)
      # @return [Boolean] True if the ArtifactResponse is 2.0, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_version
        unless version(document) == "2.0"
          return append_error("Unsupported SAML version")
        end

        true
      end

      # Validates the Status of the ArtifactResponse
      # @return [Boolean] True if the ArtifactResponse contains a Success code, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_success_status
        return true if success?

        error_msg = 'The status code of the ArtifactResponse was not Success'
        status_error_msg = OneLogin::RubySaml::Utils.status_error_msg(error_msg, status_code, status_message)
        append_error(status_error_msg)
      end

      # Validates the ArtifactResponse against the specified schema.
      # @return [Boolean] True if the XML is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_structure
        check_malformed_doc = check_malformed_doc?(settings)
        unless valid_saml?(document, soft, check_malformed_doc)
          return append_error("Invalid SAML ArtifactResponse. Not match the saml-schema-protocol-2.0.xsd")
        end

        true
      end

      # Validates if a provided :matches_request_id matches the InResponseTo value,
      # correlating the ArtifactResponse with the ArtifactResolve sent by the SP.
      # @return [Boolean] True if there is no request_id or it matches, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_in_response_to?
        return true unless options.has_key? :matches_request_id
        return true if options[:matches_request_id].nil?
        return true unless options[:matches_request_id] != in_response_to

        error_msg = "The InResponseTo of the ArtifactResponse: #{in_response_to}, does not match the ID of the ArtifactResolve sent by the SP: #{options[:matches_request_id]}"
        append_error(error_msg)
      end

      # Validates the Issuer of the ArtifactResponse
      # @return [Boolean] True if the Issuer matches the IdP entityId, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_issuer?
        return true if settings.idp_entity_id.nil? || issuer.nil?

        unless OneLogin::RubySaml::Utils.uri_match?(issuer, settings.idp_entity_id)
          return append_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
        end
        true
      end

      # Validates that the ArtifactResponse carries a protocol message
      # @return [Boolean] True if a protocol message is present, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_protocol_message
        if protocol_message.nil?
          return append_error("The ArtifactResponse does not contain a protocol message")
        end

        true
      end

      # Validates the Signature of the ArtifactResponse if it exists.
      # When the SP requires a signed ArtifactResponse
      # (security[:want_artifact_response_signed]), a missing signature is an error.
      # @return [Boolean] True if there is no Signature or the Signature is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_signature
        sig_elements = REXML::XPath.match(
          document,
          "/p:ArtifactResponse/ds:Signature",
          { "p" => PROTOCOL, "ds" => DSIG }
        )

        if sig_elements.empty?
          if settings.security[:want_artifact_response_signed]
            return append_error("The ArtifactResponse is not signed and the SP requires it")
          end
          return true
        end

        error_msg = "Invalid Signature on ArtifactResponse"

        idp_certs = settings.get_idp_cert_multi
        if idp_certs.nil? || idp_certs[:signing].empty?
          opts = {}
          opts[:fingerprint_alg] = settings.idp_cert_fingerprint_algorithm
          idp_cert = settings.get_idp_cert
          fingerprint = settings.get_fingerprint
          opts[:cert] = idp_cert

          if fingerprint && document.validate_document(fingerprint, @soft, opts)
            if settings.security[:check_idp_cert_expiration] && OneLogin::RubySaml::Utils.is_cert_expired(idp_cert)
              return append_error("IdP x509 certificate expired")
            end
          else
            return append_error(error_msg)
          end
        else
          valid = false
          expired = false
          idp_certs[:signing].each do |idp_cert|
            valid = document.validate_document_with_cert(idp_cert, true)
            if valid
              if settings.security[:check_idp_cert_expiration] && OneLogin::RubySaml::Utils.is_cert_expired(idp_cert)
                expired = true
              end
              break
            end
          end

          if expired
            return append_error("IdP x509 certificate expired")
          end
          unless valid
            return append_error(error_msg)
          end
        end

        true
      end
    end
  end
end
