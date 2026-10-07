require "xml_security"
require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/saml_message"

module OneLogin
  module RubySaml
    class SloManageNameIDResponse < SamlMessage
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze
      REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester".freeze
      RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder".freeze
      VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch".freeze

      attr_accessor :uuid

      def initialize
        @uuid = OneLogin::RubySaml::Utils.uuid
      end

      def response_id
        @uuid
      end

      def create_soap(settings, request_id = nil, status_code = SUCCESS, status_message = nil, secondary_status_code = nil)
        document = create_xml_document(settings, request_id, status_code, status_message, secondary_status_code)
        SamlMessage.soap_envelope(document.to_s)
      end

      def create_xml(settings, request_id = nil, status_code = SUCCESS, status_message = nil, secondary_status_code = nil)
        create_soap(settings, request_id, status_code, status_message, secondary_status_code)
      end

      def create_xml_document(settings, request_id = nil, status_code = SUCCESS, status_message = nil, secondary_status_code = nil)
        document = XMLSecurity::Document.new
        document.uuid = uuid
        root = document.add_element("samlp:ManageNameIDResponse", {
          "xmlns:samlp" => PROTOCOL,
          "xmlns:saml" => ASSERTION
        })
        root.attributes["ID"] = uuid
        root.attributes["Version"] = "2.0"
        root.attributes["IssueInstant"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        root.attributes["InResponseTo"] = request_id unless request_id.nil?
        root.attributes["Destination"] = settings.idp_entity_id unless settings.idp_entity_id.nil? || settings.idp_entity_id.empty?

        issuer = root.add_element("saml:Issuer")
        issuer.text = settings.sp_entity_id

        status = root.add_element("samlp:Status")
        status_code_element = status.add_element("samlp:StatusCode")
        status_code_element.attributes["Value"] = status_code || SUCCESS
        unless secondary_status_code.nil?
          secondary_status_code_element = status_code_element.add_element("samlp:StatusCode")
          secondary_status_code_element.attributes["Value"] = secondary_status_code
        end
        unless status_message.nil?
          status_message_element = status.add_element("samlp:StatusMessage")
          status_message_element.text = status_message
        end

        sign_document(document, settings)
      end

      private

      def sign_document(document, settings)
        cert, private_key = settings.get_sp_signing_pair
        if settings.security[:manage_name_id_responses_signed] && private_key && cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end
        document
      end
    end
  end
end
