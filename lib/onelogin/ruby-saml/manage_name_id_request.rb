require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/utils"
require "onelogin/ruby-saml/setting_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ManageNameID Request (SP initiated, Builder).
    #
    # The first version of the ManageNameID support only implements the
    # SOAP binding, so the produced message is wrapped in a SOAP envelope
    # ready to be POSTed to the IdP ManageNameID service.
    #
    class ManageNameIdRequest < SamlMessage
      SOAP_ENVELOPE_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/".freeze

      # ManageNameID Request ID
      attr_accessor :uuid

      # Initializes the ManageNameID Request. A ManageNameIdRequest Object that
      # is an extension of the SamlMessage class.
      # Asigns an ID, a random uuid.
      #
      def initialize
        @uuid = OneLogin::RubySaml::Utils.uuid
      end

      def request_id
        @uuid
      end

      # Creates the ManageNameID Request SOAP envelope string.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param options [Hash] The identifier change options, see create_xml_document
      # @return [String] SOAP envelope that embeds the ManageNameIDRequest
      #
      def create(settings, options = {})
        envelope = create_soap_envelope(settings, options)

        Logging.debug "Created ManageNameID Request (SOAP envelope): #{envelope}"

        envelope
      end

      # Creates the SOAP envelope that embeds the ManageNameID Request.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param options [Hash] The identifier change options, see create_xml_document
      # @return [String] SOAP envelope that embeds the ManageNameIDRequest
      #
      def create_soap_envelope(settings, options = {})
        request_doc = create_manage_name_id_request_xml_doc(settings, options)
        request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        request = "".dup
        request_doc.write(request)

        "<soap:Envelope xmlns:soap=\"#{SOAP_ENVELOPE_NAMESPACE}\"><soap:Body>#{request}</soap:Body></soap:Envelope>"
      end

      # Creates the ManageNameIDRequest XML document, signed if required.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param options [Hash] The identifier change options, see create_xml_document
      # @return [XMLSecurity::Document] The ManageNameIDRequest document
      #
      def create_manage_name_id_request_xml_doc(settings, options = {})
        document = create_xml_document(settings, options)
        sign_document(document, settings)
      end

      # Creates the ManageNameIDRequest XML document.
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param options [Hash] The identifier change options:
      #   :name_identifier [OneLogin::RubySaml::NameIdentifier] The current (old)
      #     identifier. Its Format, NameQualifier and SPNameQualifier are part of
      #     the identity and are emitted on the saml:NameID element. Required.
      #   :new_id [String] The new identifier value (rename).
      #   :new_encrypted_id [String] An XML fragment with the new identifier,
      #     either a samlp:NewEncryptedID element or a xenc:EncryptedData
      #     element (wrapped in samlp:NewEncryptedID).
      #   :terminate [Boolean] True to ask the IdP to terminate the identifier.
      #   Exactly one of :new_id, :new_encrypted_id or :terminate must be given,
      #   they are mutually exclusive choices.
      # @return [XMLSecurity::Document] The ManageNameIDRequest document
      #
      def create_xml_document(settings, options = {})
        name_identifier = options[:name_identifier]
        if name_identifier.nil?
          raise ArgumentError.new("A :name_identifier option with the current identifier is required")
        end

        action = resolve_action(options)

        time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        request_doc = XMLSecurity::Document.new
        request_doc.uuid = uuid

        root = request_doc.add_element "samlp:ManageNameIDRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol", "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Version'] = "2.0"
        destination = settings.idp_manage_name_id_service_url
        root.attributes['Destination'] = destination unless destination.nil? or destination.empty?

        if settings.sp_entity_id
          issuer = root.add_element "saml:Issuer"
          issuer.text = settings.sp_entity_id
        end

        nameid = root.add_element "saml:NameID"
        nameid.attributes['Format'] = name_identifier.format unless name_identifier.format.nil?
        nameid.attributes['NameQualifier'] = name_identifier.name_qualifier unless name_identifier.name_qualifier.nil?
        nameid.attributes['SPNameQualifier'] = name_identifier.sp_name_qualifier unless name_identifier.sp_name_qualifier.nil?
        nameid.text = name_identifier.value

        case action[0]
        when :new_id
          new_id = root.add_element "samlp:NewID"
          new_id.text = action[1]
        when :new_encrypted_id
          fragment = REXML::Document.new(action[1]).root
          if fragment.nil?
            raise ArgumentError.new(":new_encrypted_id must contain a samlp:NewEncryptedID or xenc:EncryptedData element")
          end
          if fragment.name == "NewEncryptedID"
            root.add_element(fragment)
          elsif fragment.name == "EncryptedData"
            new_encrypted_id = root.add_element "samlp:NewEncryptedID"
            new_encrypted_id.add_element(fragment)
          else
            raise ArgumentError.new(":new_encrypted_id must contain a samlp:NewEncryptedID or xenc:EncryptedData element")
          end
        when :terminate
          root.add_element "samlp:Terminate"
        end

        request_doc
      end

      # Signs the ManageNameIDRequest document when the settings require it.
      # @param document [XMLSecurity::Document] The ManageNameIDRequest document
      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @return [XMLSecurity::Document] The (possibly signed) document
      #
      def sign_document(document, settings)
        cert, private_key = settings.get_sp_signing_pair
        if settings.security[:manage_name_id_requests_signed] && private_key && cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        document
      end

      private

      # NewID, NewEncryptedID and Terminate are mutually exclusive choices.
      # @param options [Hash] The identifier change options
      # @return [Array] A pair with the action name and its value
      # @raise [ArgumentError] If none or more than one action is provided
      #
      def resolve_action(options)
        actions = []
        actions << [:new_id, options[:new_id]] unless options[:new_id].nil?
        actions << [:new_encrypted_id, options[:new_encrypted_id]] unless options[:new_encrypted_id].nil?
        actions << [:terminate, true] if options[:terminate]

        if actions.empty?
          raise ArgumentError.new("One of :new_id, :new_encrypted_id or :terminate must be provided")
        end
        if actions.size > 1
          raise ArgumentError.new(":new_id, :new_encrypted_id and :terminate are mutually exclusive")
        end

        actions.first
      end
    end
  end
end
