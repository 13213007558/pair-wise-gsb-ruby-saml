require "xml_security"
require "onelogin/ruby-saml/saml_message"

module OneLogin
  module RubySaml
    class SloManageNameIDRequest < SamlMessage
      include ErrorHandling

      attr_accessor :settings
      attr_accessor :soft
      attr_reader :document
      attr_reader :request
      attr_reader :options

      def initialize(request, options = {})
        raise ArgumentError.new("ManageNameID request cannot be nil") if request.nil?
        @errors = []
        @options = options
        @settings = options[:settings]
        @soft = settings.nil? || settings.soft.nil? ? true : settings.soft
        raw = SamlMessage.extract_saml_from_soap(request) || request
        @request = decode_raw_saml(raw, settings)
        @document = XMLSecurity::SignedDocument.new(@request)
      end

      def request_id
        id(document)
      end

      def issuer
        @issuer ||= Utils.element_text(REXML::XPath.first(document, "/p:ManageNameIDRequest/a:Issuer", namespaces))
      end

      def destination
        root_node.nil? ? nil : root_node.attributes["Destination"]
      end

      def old_name_id_node
        @old_name_id_node ||= begin
          encrypted = REXML::XPath.first(document, "/p:ManageNameIDRequest/a:EncryptedID", namespaces)
          encrypted ? decrypt_element(encrypted, /(.*<\/(\w+:)?NameID>)/m) : REXML::XPath.first(document, "/p:ManageNameIDRequest/a:NameID", namespaces)
        end
      end

      def old_name_id
        Utils.element_text(old_name_id_node)
      end

      alias_method :name_id, :old_name_id
      alias_method :nameid, :old_name_id

      def old_name_id_format
        attribute_from_old_name_id("Format")
      end

      def old_name_qualifier
        attribute_from_old_name_id("NameQualifier")
      end

      def old_sp_name_qualifier
        attribute_from_old_name_id("SPNameQualifier")
      end

      def old_identity
        {
          :name_id => old_name_id,
          :format => old_name_id_format,
          :name_qualifier => old_name_qualifier,
          :sp_name_qualifier => old_sp_name_qualifier
        }
      end

      def new_id
        @new_id ||= begin
          encrypted_new = REXML::XPath.first(document, "/p:ManageNameIDRequest/p:NewEncryptedID", namespaces)
          if encrypted_new
            node = decrypt_element(encrypted_new, /(.*<\/(\w+:)?NewID>)/m)
            Utils.element_text(node)
          else
            Utils.element_text(REXML::XPath.first(document, "/p:ManageNameIDRequest/p:NewID", namespaces))
          end
        end
      end

      def new_identity
        return nil unless new_id
        {
          :name_id => new_id,
          :format => old_name_id_format,
          :name_qualifier => old_name_qualifier,
          :sp_name_qualifier => old_sp_name_qualifier
        }
      end

      def terminate?
        !REXML::XPath.first(document, "/p:ManageNameIDRequest/p:Terminate", namespaces).nil?
      end

      def action
        return :terminate if terminate?
        return :new_encrypted_id if REXML::XPath.first(document, "/p:ManageNameIDRequest/p:NewEncryptedID", namespaces)
        :new_id
      end

      def is_valid?(collect_errors = false)
        validate(collect_errors)
      end

      def validate(collect_errors = false)
        reset_errors!
        validations = [
          :valid_state?,
          :validate_id,
          :validate_version,
          :validate_structure,
          :validate_choices,
          :validate_target_identity,
          :validate_destination,
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
        { "p" => PROTOCOL, "a" => ASSERTION, "xenc" => Utils::XENC, "ds" => Utils::DSIG }
      end

      def root_node
        @root_node ||= REXML::XPath.first(document, "/p:ManageNameIDRequest", namespaces)
      end

      def attribute_from_old_name_id(name)
        node = old_name_id_node
        node && node.attribute(name) ? node.attribute(name).value : nil
      end

      def decrypt_element(encrypted_node, regexp)
        if settings.nil? || settings.get_sp_decryption_keys.nil? || settings.get_sp_decryption_keys.empty?
          raise ValidationError.new("An encrypted identifier was found and no SP private key found on the settings to decrypt it")
        end
        plaintext = Utils.decrypt_multi(encrypted_node, settings.get_sp_decryption_keys)
        plaintext = plaintext.match(regexp)[0]
        wrapped = "<node xmlns:saml=\"#{ASSERTION}\" xmlns:samlp=\"#{PROTOCOL}\">#{plaintext}</node>"
        REXML::Document.new(wrapped).root[0]
      end

      def valid_state?
        return append_error("Blank ManageNameID request") if request.nil? || request.empty?
        return append_error("No settings on ManageNameID request") if settings.nil?
        true
      end

      def validate_id
        request_id ? true : append_error("Missing ID attribute on ManageNameID Request")
      end

      def validate_version
        version(document) == "2.0" ? true : append_error("Unsupported SAML version")
      end

      def validate_structure
        return true if valid_saml?(document, soft, check_malformed_doc?(settings))
        append_error("Invalid SAML ManageNameID Request. Not match the saml-schema-protocol-2.0.xsd")
      end

      def validate_choices
        count = [
          REXML::XPath.match(document, "/p:ManageNameIDRequest/p:NewID", namespaces).size,
          REXML::XPath.match(document, "/p:ManageNameIDRequest/p:NewEncryptedID", namespaces).size,
          REXML::XPath.match(document, "/p:ManageNameIDRequest/p:Terminate", namespaces).size
        ].inject(0) { |total, value| total + value }
        count == 1 ? true : append_error("NewID, NewEncryptedID and Terminate are mutually exclusive")
      end

      def validate_target_identity
        if old_name_id.nil? || old_name_id.to_s.empty?
          return append_error("Old NameID is required on ManageNameID Request")
        end
        unless settings.sp_entity_id.nil? || old_sp_name_qualifier == settings.sp_entity_id
          return append_error("Old NameID SPNameQualifier does not match the SP entity ID")
        end
        true
      end

      def validate_destination
        expected = settings.sp_manage_name_id_service_url
        return true if expected.nil? || expected.empty? || destination.nil? || destination == expected
        append_error("The Destination of the ManageNameID Request: #{destination}, does not match the SP ManageNameID service: #{expected}")
      end

      def validate_issuer
        return true if settings.idp_entity_id.nil? || issuer.nil? || Utils.uri_match?(issuer, settings.idp_entity_id)
        append_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
      end

      def validate_xml_signature
        return true unless settings.security[:want_manage_name_id_requests_signed]

        signatures = REXML::XPath.match(document, "/p:ManageNameIDRequest/ds:Signature", namespaces)
        return append_error("Missing Signature on ManageNameID Request") if signatures.empty?
        return append_error("Multiple Signatures on ManageNameID Request") if signatures.size > 1

        reference = REXML::XPath.first(signatures.first, "./ds:SignedInfo/ds:Reference", namespaces)
        reference_id = reference && reference.attributes["URI"]
        if reference_id.nil? || reference_id.sub(/\A#/, "") != request_id
          return append_error("Invalid Signature reference on ManageNameID Request")
        end

        idp_certs = settings.get_idp_cert_multi
        if idp_certs.nil? || idp_certs[:signing].empty?
          idp_cert = settings.get_idp_cert
          return append_error("No fingerprint or certificate on settings of the ManageNameID request") if idp_cert.nil? && settings.get_fingerprint.nil?
          valid = document.validate_document(settings.get_fingerprint, @soft, { :fingerprint_alg => settings.idp_cert_fingerprint_algorithm, :cert => idp_cert })
          if valid && settings.security[:check_idp_cert_expiration] && Utils.is_cert_expired(idp_cert)
            return append_error("IdP x509 certificate expired")
          end
          return append_error("Invalid Signature on ManageNameID Request") unless valid
        else
          valid = false
          idp_certs[:signing].each do |idp_cert|
            if document.validate_document_with_cert(idp_cert, true)
              return append_error("IdP x509 certificate expired") if settings.security[:check_idp_cert_expiration] && Utils.is_cert_expired(idp_cert)
              valid = true
              break
            end
          end
          return append_error("Invalid Signature on ManageNameID Request") unless valid
        end
        true
      end
    end
  end
end
