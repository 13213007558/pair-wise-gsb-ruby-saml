require "onelogin/ruby-saml/logging"

require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/utils"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ManageNameID Response (SP initiated, Parser)
    #
    # Only documents whose root element is samlp:ManageNameIDResponse are
    # accepted. Login (samlp:Response) and logout (samlp:LogoutResponse)
    # documents, or objects of those APIs, cannot be used to impersonate a
    # ManageNameID Response.
    #
    class ManageNameIdResponse < SamlMessage
      include ErrorHandling

      DSIG = "http://www.w3.org/2000/09/xmldsig#".freeze
      SOAP_ENVELOPE_NS = "http://schemas.xmlsoap.org/soap/envelope/".freeze

      # OneLogin::RubySaml::Settings Toolkit settings
      attr_accessor :settings

      attr_reader :document
      attr_reader :response
      attr_reader :options

      attr_accessor :soft

      # Constructs the ManageNameID Response. A ManageNameIdResponse Object that
      # is an extension of the SamlMessage class.
      # @param response [String] A UUEncoded ManageNameID response from the IdP.
      #                          A SOAP envelope wrapping the response is also accepted.
      # @param options [Hash]  :settings to provide the OneLogin::RubySaml::Settings object
      #                        Or :matches_request_id It will validate that the response matches the ID of the request.
      #                        Or :relax_signature_validation to accept signatures if no IdP certificate registered on settings
      #
      # @raise [ArgumentError] If response is nil or is not a String
      # @raise [ValidationError] If the document is not a samlp:ManageNameIDResponse
      #
      def initialize(response, options = {})
        raise ArgumentError.new("ManageNameIdResponse cannot be nil") if response.nil?
        unless response.is_a?(String)
          raise ArgumentError.new("ManageNameIdResponse must be built from a String, #{response.class} objects cannot impersonate a ManageNameID Response")
        end

        @errors = []
        @options = options
        @settings = options[:settings]
        @soft = true
        unless settings.nil?
          @soft = settings.soft unless settings.soft.nil?
        end

        @response = self.class.unwrap_soap_envelope(decode_raw_saml(response, settings))
        @document = XMLSecurity::SignedDocument.new(@response)

        root = @document.root
        unless root && root.name == "ManageNameIDResponse" && root.namespace == PROTOCOL
          raise ValidationError.new("Invalid SAML message. Expected a samlp:ManageNameIDResponse document, but was: <#{root && root.name}>")
        end
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

      # @return [String|nil] Gets the InResponseTo attribute from the ManageNameID Response if exists.
      #
      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(
            document,
            "/p:ManageNameIDResponse",
            { "p" => PROTOCOL }
          )
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      # @return [String] Gets the Issuer from the ManageNameID Response.
      #
      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(
            document,
            "/p:ManageNameIDResponse/a:Issuer",
            { "p" => PROTOCOL, "a" => ASSERTION }
          )
          Utils.element_text(node)
        end
      end

      # @return [String] Gets the StatusCode from a ManageNameID Response.
      #
      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:ManageNameIDResponse/p:Status/p:StatusCode", { "p" => PROTOCOL })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      # @return [String] Gets the StatusMessage from a ManageNameID Response.
      #
      def status_message
        @status_message ||= begin
          node = REXML::XPath.first(
            document,
            "/p:ManageNameIDResponse/p:Status/p:StatusMessage",
            { "p" => PROTOCOL }
          )
          Utils.element_text(node)
        end
      end

      # Aux function to validate the ManageNameID Response
      # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
      # @return [Boolean] TRUE if the ManageNameID Response is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(collect_errors = false)
        reset_errors!

        validations = [
          :valid_state?,
          :validate_success_status,
          :validate_structure,
          :valid_in_response_to?,
          :valid_issuer?,
          :validate_signature
        ]

        run_validations(validations, collect_errors)
      end

      # Validates the response envelope (state, structure, correlation ID,
      # peer issuer and signature) without requiring a Success status, so a
      # denial coming from a verified peer can be told apart from an invalid
      # response.
      # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
      # @return [Boolean] TRUE if the ManageNameID Response message is valid
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_message(collect_errors = false)
        reset_errors!

        validations = [
          :valid_state?,
          :validate_structure,
          :valid_in_response_to?,
          :valid_issuer?,
          :validate_signature
        ]

        run_validations(validations, collect_errors)
      end

      # Extracts the SAML message from a SOAP envelope when present.
      # @param xml [String] The SAML message, optionally wrapped in a SOAP envelope
      # @return [String] The plain SAML message
      # @raise [ValidationError] If the SOAP envelope has no Body or the Body is empty
      #
      def self.unwrap_soap_envelope(xml)
        doc = REXML::Document.new(xml)
        root = doc.root
        return xml unless root && root.name == "Envelope" && root.namespace.to_s.start_with?(SOAP_ENVELOPE_NS)

        body = REXML::XPath.first(root, "./soap:Body", { "soap" => root.namespace })
        raise ValidationError.new("SOAP Envelope without Body") if body.nil?

        message = nil
        body.each_element { |element| message = element; break }
        raise ValidationError.new("SOAP Body does not contain a SAML message") if message.nil?

        message.to_s
      rescue REXML::ParseException
        xml
      end

      private

      def run_validations(validations, collect_errors)
        if collect_errors
          validations.each { |validation| send(validation) }
          @errors.empty?
        else
          validations.all? { |validation| send(validation) }
        end
      end

      # Validates the Status of the ManageNameID Response
      # If fails, the error is added to the errors array, including the StatusCode returned and the Status Message.
      # @return [Boolean] True if the ManageNameID Response contains a Success code, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_success_status
        return true if success?

        error_msg = 'The status code of the ManageNameID Response was not Success'
        status_error_msg = OneLogin::RubySaml::Utils.status_error_msg(error_msg, status_code, status_message)
        append_error(status_error_msg)
      end

      # Validates the ManageNameID Response against the specified schema.
      # @return [Boolean] True if the XML is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_structure
        check_malformed_doc = check_malformed_doc?(settings)
        unless valid_saml?(document, soft, check_malformed_doc)
          return append_error("Invalid SAML ManageNameID Response. Not match the saml-schema-protocol-2.0.xsd")
        end

        true
      end

      # Validates that the ManageNameID Response provided in the initialization is not empty,
      # also check that the settings and the IdP cert were also provided
      # @return [Boolean] True if the required info is found, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_state?
        return append_error("Blank manage name id response") if response.empty?

        return append_error("No settings on manage name id response") if settings.nil?

        return append_error("No sp_entity_id in settings of the manage name id response") if settings.sp_entity_id.nil?

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil? && settings.idp_cert_multi.nil?
          return append_error("No fingerprint or certificate on settings of the manage name id response")
        end

        true
      end

      # Validates if a provided :matches_request_id matches the inResponseTo value.
      # @return [Boolean] True if there is no request_id or it matches, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_in_response_to?
        return true unless options.has_key? :matches_request_id
        return true if options[:matches_request_id].nil?
        return true unless options[:matches_request_id] != in_response_to

        error_msg = "The InResponseTo of the ManageNameID Response: #{in_response_to}, does not match the ID of the ManageNameID Request sent by the SP: #{options[:matches_request_id]}"
        append_error(error_msg)
      end

      # Validates the Issuer of the ManageNameID Response
      # @return [Boolean] True if the Issuer matches the IdP entityId, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def valid_issuer?
        return true if settings.nil?
        return true if settings.idp_entity_id.nil? || issuer.nil?

        unless OneLogin::RubySaml::Utils.uri_match?(issuer, settings.idp_entity_id)
          return append_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
        end
        true
      end

      # Validates the embedded Signature if it exists
      # @return [Boolean] True if not contains a Signature or if the Signature is valid, otherwise False if soft=True
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate_signature
        return true if settings.nil?

        sig_elements = REXML::XPath.match(
          document,
          "/p:ManageNameIDResponse/ds:Signature",
          { "p" => PROTOCOL, "ds" => DSIG }
        )

        if sig_elements.nil? || sig_elements.empty?
          if settings.security[:want_manage_name_id_responses_signed]
            return append_error("Signature not found on ManageNameID Response")
          end
          return true
        end

        error_msg = "Invalid Signature on ManageNameID Response"

        idp_cert = settings.get_idp_cert
        idp_certs = settings.get_idp_cert_multi

        if idp_cert.nil? && (idp_certs.nil? || idp_certs[:signing].empty?)
          return options.has_key? :relax_signature_validation
        end

        expired = false
        if idp_certs.nil? || idp_certs[:signing].empty?
          valid = document.validate_document_with_cert(idp_cert, true)
          if valid && settings.security[:check_idp_cert_expiration]
            if OneLogin::RubySaml::Utils.is_cert_expired(idp_cert)
              expired = true
            end
          end
        else
          valid = false
          idp_certs[:signing].each do |signing_idp_cert|
            valid = document.validate_document_with_cert(signing_idp_cert, true)
            if valid
              if settings.security[:check_idp_cert_expiration]
                if OneLogin::RubySaml::Utils.is_cert_expired(signing_idp_cert)
                  expired = true
                end
              end
              break
            end
          end
        end

        if expired
          return append_error("IdP x509 certificate expired")
        end
        unless valid
          return append_error(error_msg)
        end

        true
      end
    end
  end
end
