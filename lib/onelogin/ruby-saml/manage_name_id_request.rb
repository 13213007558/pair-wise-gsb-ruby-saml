require "xml_security"
require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/setting_error"

module OneLogin
  module RubySaml
    class ManageNameIDRequest < SamlMessage
      attr_accessor :uuid
      attr_accessor :old_name_id
      attr_accessor :old_name_id_format
      attr_accessor :old_name_qualifier
      attr_accessor :old_sp_name_qualifier
      attr_accessor :old_encrypted_id
      attr_accessor :new_id
      attr_accessor :new_encrypted_id
      attr_accessor :terminate

      def initialize(params = {})
        @uuid = params[:request_id] || params[:id] || OneLogin::RubySaml::Utils.uuid
        @old_name_id = params[:old_name_id] || params[:name_id] || params[:name_identifier_value]
        @old_name_id_format = params[:old_name_id_format] || params[:name_id_format]
        @old_name_qualifier = params[:old_name_qualifier]
        @old_sp_name_qualifier = params[:old_sp_name_qualifier]
        @old_encrypted_id = params[:old_encrypted_id]
        @new_id = params[:new_id]
        @new_encrypted_id = params[:new_encrypted_id]
        @terminate = params[:terminate] == true
      end

      def request_id
        @uuid
      end

      def create_soap(settings, options = {})
        prepare_new_encrypted_id(settings, options)
        prepare_old_encrypted_id(settings, options)
        validate_choices!
        destination = options[:url] || settings.idp_manage_name_id_service_url
        raise SettingError.new("Invalid settings, idp_manage_name_id_service_url is not set!") if destination.nil? || destination.empty?

        document = create_xml_document(settings, options, destination)
        document = sign_document(document, settings)
        SamlMessage.soap_envelope(document.to_s)
      end

      def create_xml(settings, options = {})
        create_soap(settings, options)
      end

      def create_xml_document(settings, options = {}, destination = nil)
        validate_choices!
        destination ||= options[:url] || settings.idp_manage_name_id_service_url

        document = XMLSecurity::Document.new
        document.uuid = uuid
        root = document.add_element("samlp:ManageNameIDRequest", {
          "xmlns:samlp" => PROTOCOL,
          "xmlns:saml" => ASSERTION
        })
        root.attributes["ID"] = uuid
        root.attributes["Version"] = "2.0"
        root.attributes["IssueInstant"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        root.attributes["Destination"] = destination unless destination.nil? || destination.empty?

        issuer = root.add_element("saml:Issuer")
        issuer.text = settings.sp_entity_id

        if old_encrypted_id
          encrypted_old = root.add_element("saml:EncryptedID")
          encrypted_old.add(encrypted_node(old_encrypted_id))
        else
          old_node = root.add_element("saml:NameID")
          old_node.attributes["Format"] = old_name_id_format if old_name_id_format
          old_node.attributes["NameQualifier"] = old_name_qualifier if old_name_qualifier
          old_node.attributes["SPNameQualifier"] = old_sp_name_qualifier if old_sp_name_qualifier
          old_node.text = old_name_id.to_s
        end

        if terminate
          root.add_element("samlp:Terminate")
        elsif new_encrypted_id
          encrypted = root.add_element("samlp:NewEncryptedID")
          encrypted.add(encrypted_node(new_encrypted_id))
        else
          new_node = root.add_element("samlp:NewID")
          new_node.text = new_id.to_s
        end

        document
      end

      def validate_choices!
        choices = [!new_id.nil?, !new_encrypted_id.nil?, terminate ? true : false]
        raise ArgumentError.new("NewID, NewEncryptedID and Terminate are mutually exclusive") unless choices.select { |choice| choice }.size == 1
        raise ArgumentError.new("old_name_id is required") if old_name_id.nil? || old_name_id.to_s.empty?
        true
      end

      private

      def encrypted_node(value)
        return value if value.is_a?(REXML::Element)
        REXML::Document.new(value.to_s).root
      end

      def prepare_new_encrypted_id(settings, options)
        return unless options[:encrypt_new_id]
        return if terminate || new_encrypted_id
        cert = settings.get_idp_encryption_cert
        raise SettingError.new("No IdP encryption certificate is configured for NewEncryptedID") if cert.nil?

        new_id_element = "<samlp:NewID xmlns:samlp=\"#{PROTOCOL}\">#{REXML::Text.normalize(new_id.to_s)}</samlp:NewID>"
        @new_encrypted_id = OneLogin::RubySaml::Utils.encrypt_element(new_id_element, cert)
        @new_id = nil
      end

      def prepare_old_encrypted_id(settings, options)
        return unless options[:encrypt_old_id]
        return if old_encrypted_id
        cert = settings.get_idp_encryption_cert
        raise SettingError.new("No IdP encryption certificate is configured for EncryptedID") if cert.nil?

        name_id = "<saml:NameID xmlns:saml=\"#{ASSERTION}\""
        name_id << " Format=\"#{REXML::Text.normalize(old_name_id_format.to_s)}\"" if old_name_id_format
        name_id << " NameQualifier=\"#{REXML::Text.normalize(old_name_qualifier.to_s)}\"" if old_name_qualifier
        name_id << " SPNameQualifier=\"#{REXML::Text.normalize(old_sp_name_qualifier.to_s)}\"" if old_sp_name_qualifier
        name_id << ">#{REXML::Text.normalize(old_name_id.to_s)}</saml:NameID>"
        @old_encrypted_id = OneLogin::RubySaml::Utils.encrypt_element(name_id, cert)
      end

      def sign_document(document, settings)
        cert, private_key = settings.get_sp_signing_pair
        if settings.security[:manage_name_id_requests_signed] && private_key && cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end
        document
      end
    end
  end
end
