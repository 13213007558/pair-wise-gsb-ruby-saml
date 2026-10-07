require "rexml/document"
require "nokogiri"

require "onelogin/ruby-saml/error_handling"
require "onelogin/ruby-saml/authrequest"
require "onelogin/ruby-saml/response"
require "onelogin/ruby-saml/setting_error"

module OneLogin
  module RubySaml
    class EcpMessage < SamlMessage
      include ErrorHandling

      SOAP_ENVELOPE = "http://schemas.xmlsoap.org/soap/envelope/"
      ECP_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
      PAOS_NAMESPACE = "urn:liberty:paos:2003-08"
      SOAP_ACTOR_NEXT = "http://schemas.xmlsoap.org/soap/actor/next"
      CONTENT_TYPE = "text/xml; charset=utf-8"
      PAOS_CONTENT_TYPE = "application/vnd.paos+xml"
      SOAP_ACTION = "http://www.oasis-open.org/committees/security"
      SOAP_MEDIA_TYPE = "text/xml"

      attr_reader :document, :raw_message, :settings
      attr_accessor :soft

      def initialize(message = nil, settings = nil)
        @settings = settings
        @soft = settings.nil? || settings.soft.nil? ? true : settings.soft
        @errors = []
        @document = nil
        @raw_message = ""
        load_message(message) unless message.nil?
      end

      def valid?
        reset_errors!
        validate_message
        @errors.empty?
      end

      private

      def load_message(message)
        @raw_message = decode_raw_saml(message.to_s, settings || Settings.new)
        return append_error("Blank SOAP message") if @raw_message.strip.empty?
        begin
          XMLSecurity::BaseDocument.safe_load_xml(@raw_message, check_malformed_doc?(settings))
          @document = REXML::Document.new(@raw_message)
        rescue StandardError => error
          append_error("Invalid SOAP XML: #{error.message}")
        end
      end

      def validate_message
        return false unless document && element?(document.root, SOAP_ENVELOPE, "Envelope")
        return false unless soap_part("Header") && soap_part("Body")
        true
      end

      def soap_part(name)
        return unless document && document.root
        document.root.elements.to_a.find { |node| element?(node, SOAP_ENVELOPE, name) }
      end

      def soap_header
        soap_part("Header")
      end

      def soap_body
        soap_part("Body")
      end

      def header_child(namespace, name)
        header = soap_header
        return unless header
        header.elements.to_a.find { |node| element?(node, namespace, name) }
      end

      def body_child(namespace, name)
        body = soap_body
        return unless body
        body.elements.to_a.find { |node| element?(node, namespace, name) }
      end

      def element?(node, namespace, name)
        node.is_a?(REXML::Element) && node.namespace == namespace && node.name == name
      end

      def attribute(node, namespace, name)
        return unless node
        node.attributes.each_attribute do |attribute|
          unqualified = namespace.nil? && attribute.namespace.to_s.empty?
          qualified = namespace && attribute.namespace == namespace
          return attribute.value if attribute.name == name && (unqualified || qualified)
        end
        nil
      end

      def soap_attribute(node, name)
        attribute(node, SOAP_ENVELOPE, name) || attribute(node, nil, name)
      end

      def actor(node)
        soap_attribute(node, "actor") || soap_attribute(node, "role")
      end

      def next_actor?(node)
        value = actor(node)
        value.nil? || value.empty? || value == SOAP_ACTOR_NEXT
      end

      def must_understand?(node)
        ["1", "true"].include?(soap_attribute(node, "mustUnderstand"))
      end

      def saml_message_xml(node)
        xml = XMLSecurity::BaseDocument.safe_load_xml(raw_message, check_malformed_doc?(settings))
        target = nokogiri_node(xml.root, document.root, node)
        duplicate = target.dup
        namespaces_for(target).each do |prefix, href|
          next if prefix == "xml"
          next if duplicate.xpath('.//namespace::*').any? { |namespace| namespace.prefix == prefix }
          duplicate.add_namespace(prefix, href)
        end
        duplicate.to_xml
      end

      def nokogiri_node(nokogiri_parent, rexml_parent, rexml_node)
        nokogiri_children = nokogiri_parent.children.select { |node| node.element? }
        rexml_children = rexml_parent.elements.to_a
        rexml_children.each do |child|
          index = rexml_children.index(child)
          nokogiri_child = nokogiri_children[index]
          if child == rexml_node
            return nokogiri_child
          elsif contains_node?(child, rexml_node)
            return nokogiri_node(nokogiri_child, child, rexml_node)
          end
        end
        nil
      end

      def contains_node?(parent, node)
        parent == node || parent.elements.to_a.any? { |child| contains_node?(child, node) }
      end

      def namespaces_for(target)
        used = {}
        [target, *target.xpath('.//*')].each do |node|
          add_namespace_usage(used, node.namespace) if node.namespace
          node.attribute_nodes.each { |attribute| add_namespace_usage(used, attribute.namespace) if attribute.namespace }
        end
        available = {}
        target.ancestors.reverse.each do |ancestor|
          next unless ancestor.respond_to?(:namespace_definitions)
          ancestor.namespace_definitions.each { |namespace| available[namespace.prefix] ||= namespace.href }
        end
        target.namespace_definitions.each { |namespace| available[namespace.prefix] ||= namespace.href }
        result = {}
        used.each { |prefix, href| result[prefix] = href if available[prefix] == href }
        result
      end

      def add_namespace_usage(used, namespace)
        used[namespace.prefix] = namespace.href unless used.key?(namespace.prefix)
      end

      def soap_document
        document = REXML::Document.new
        envelope = document.add_element("soap:Envelope")
        envelope.add_namespace("soap", SOAP_ENVELOPE)
        envelope.add_namespace("samlp", PROTOCOL)
        envelope.add_namespace("saml", ASSERTION)
        envelope.add_namespace("ecp", ECP_NAMESPACE)
        envelope.add_namespace("paos", PAOS_NAMESPACE)
        envelope.add_element("soap:Header")
        envelope.add_element("soap:Body")
        document
      end

      def remove_unused_namespace(document, prefix, namespace)
        return if REXML::XPath.first(document, "//*[namespace-uri()='#{namespace}']")
        root = document.root
        root.attributes.delete("xmlns:#{prefix}") if root.namespaces[prefix] == namespace
      end
    end

    class EcpAuthnRequest < EcpMessage
      attr_reader :authn_request, :request_id

      def self.create(settings, params = {})
        new.create(settings, params)
      end

      def create(settings, params = {})
        if settings.assertion_consumer_service_url.nil? || settings.assertion_consumer_service_url.empty?
          raise SettingError.new("Invalid settings, assertion_consumer_service_url is not set!")
        end

        authn = params[:authn_request] || Authrequest.new
        ecp_settings = Marshal.load(Marshal.dump(settings))
        ecp_settings.protocol_binding = Utils::BINDINGS[:paos]
        ecp_settings.idp_sso_service_url = nil

        request_doc = authn.create_authentication_xml_doc(ecp_settings)
        consumer_url = ecp_settings.assertion_consumer_service_url
        document = soap_document
        envelope = document.root
        header = soap_part_from(envelope, "Header")
        body = soap_part_from(envelope, "Body")

        ecp_request = header.add_element("ecp:Request", {
          "IsPassive" => settings.passive == true ? "1" : "0",
          "responseConsumerURL" => consumer_url
        })
        ecp_request.add_attribute("soap:actor", SOAP_ACTOR_NEXT)
        ecp_request.add_attribute("soap:mustUnderstand", "1")
        unless settings.sp_entity_id.nil? || settings.sp_entity_id.to_s.empty?
          ecp_request.add_element("ecp:Issuer").text = settings.sp_entity_id
        end

        paos_request = header.add_element("paos:Request", {
          "responseConsumerURL" => consumer_url,
          "service" => Utils::BINDINGS[:paos]
        })
        paos_request.add_attribute("soap:actor", SOAP_ACTOR_NEXT)
        paos_request.add_attribute("soap:mustUnderstand", "1")
        body.add(request_doc.root)

        @settings = settings
        @request_id = authn.uuid
        @raw_message = document.to_s
        @document = REXML::Document.new(@raw_message)
        @authn_request = body_child(PROTOCOL, "AuthnRequest")
        self
      end

      def to_idp_request
        idp_document = REXML::Document.new(raw_message)
        header = soap_part_from(idp_document.root, "Header")
        header.elements.to_a.each do |node|
          node.remove if element?(node, PAOS_NAMESPACE, "Request")
        end
        remove_unused_namespace(idp_document, "paos", PAOS_NAMESPACE)
        idp_document.to_s
      end

      private

      def soap_part_from(envelope, name)
        envelope.elements.to_a.find { |node| element?(node, SOAP_ENVELOPE, name) }
      end

      def requires_paos_request?
        true
      end

      def validate_message
        return false unless super

        ecp_request = header_child(ECP_NAMESPACE, "Request")
        paos_request = header_child(PAOS_NAMESPACE, "Request")
        @authn_request = body_child(PROTOCOL, "AuthnRequest")
        return append_error("Missing ECP Request SOAP header") unless ecp_request
        if requires_paos_request? && !paos_request
          return append_error("Missing PAOS Request SOAP header")
        end
        return append_error("Missing SAML AuthnRequest") unless @authn_request
        unless next_actor?(ecp_request) && must_understand?(ecp_request)
          return append_error("ECP Request must target the next SOAP actor and must be understood")
        end
        if requires_paos_request? && !(next_actor?(paos_request) && must_understand?(paos_request))
          return append_error("PAOS Request must target the next SOAP actor and must be understood")
        end

        ecp_url = attribute(ecp_request, nil, "responseConsumerURL")
        paos_url = requires_paos_request? ? attribute(paos_request, nil, "responseConsumerURL") : ecp_url
        acs_url = @authn_request.attributes["AssertionConsumerServiceURL"]
        if ecp_url.to_s.empty? || acs_url.to_s.empty? || (requires_paos_request? && paos_url.to_s.empty?)
          return append_error("responseConsumerURL and AssertionConsumerServiceURL are required")
        end
        unless ecp_url == paos_url && paos_url == acs_url
          return append_error("responseConsumerURL must match AssertionConsumerServiceURL")
        end
        unless @authn_request.attributes["Version"] == "2.0"
          return append_error("Unsupported AuthnRequest version")
        end
        unless @authn_request.attributes["ProtocolBinding"] == Utils::BINDINGS[:paos]
          return append_error("AuthnRequest ProtocolBinding must be PAOS")
        end
        if REXML::XPath.first(document, "//*[local-name()='RelayState']")
          return append_error("RelayState must not be carried in the ECP SOAP message")
        end

        request_xml = saml_message_xml(@authn_request)
        unless valid_saml?(REXML::Document.new(request_xml), soft, check_malformed_doc?(settings))
          return append_error("Invalid SAML AuthnRequest")
        end
        @request_id = @authn_request.attributes["ID"]
        true
      end
    end

    class EcpIdpRequest < EcpAuthnRequest
      private

      def requires_paos_request?
        false
      end
    end

    class EcpResponse < EcpMessage
      attr_reader :response, :assertion_consumer_service_url

      def self.create(settings, saml_response, response_consumer_url = settings.assertion_consumer_service_url)
        new.create(settings, saml_response, response_consumer_url)
      end

      def create(settings, saml_response, response_consumer_url = settings.assertion_consumer_service_url)
        if response_consumer_url.nil? || response_consumer_url.empty?
          raise SettingError.new("Invalid settings, assertion_consumer_service_url is not set!")
        end
        XMLSecurity::BaseDocument.safe_load_xml(saml_response, settings.check_malformed_doc)
        document = soap_document
        envelope = document.root
        header = envelope.elements.to_a.find { |node| element?(node, SOAP_ENVELOPE, "Header") }
        body = envelope.elements.to_a.find { |node| element?(node, SOAP_ENVELOPE, "Body") }

        ecp_response = header.add_element("ecp:Response", {
          "AssertionConsumerServiceURL" => response_consumer_url
        })
        ecp_response.add_attribute("soap:actor", SOAP_ACTOR_NEXT)
        ecp_response.add_attribute("soap:mustUnderstand", "1")
        body.add(REXML::Document.new(saml_response).root)

        @settings = settings
        @assertion_consumer_service_url = response_consumer_url
        @raw_message = document.to_s
        @document = REXML::Document.new(@raw_message)
        @response = body_child(PROTOCOL, "Response")
        self
      end

      def to_sp_request
        sp_document = REXML::Document.new(raw_message)
        header = sp_document.root.elements.to_a.find { |node| element?(node, SOAP_ENVELOPE, "Header") }
        header.elements.to_a.each do |node|
          node.remove if element?(node, ECP_NAMESPACE, "Response")
        end
        remove_unused_namespace(sp_document, "ecp", ECP_NAMESPACE)
        sp_document.to_s
      end

      def saml_response(settings = @settings, options = {})
        Response.new(saml_response_xml, options.merge(:settings => settings))
      end

      def saml_response_xml
        saml_message_xml(response)
      end

      def validate_response_consumer_url(url)
        if assertion_consumer_service_url.nil? || url.nil? || assertion_consumer_service_url != url
          return append_error("ECP Response AssertionConsumerServiceURL does not match responseConsumerURL")
        end
        true
      end

      private

      def validate_message
        return false unless super
        ecp_response = header_child(ECP_NAMESPACE, "Response")
        @response = body_child(PROTOCOL, "Response")
        return append_error("Missing ECP Response SOAP header") unless ecp_response
        return append_error("Missing SAML Response") unless @response
        unless next_actor?(ecp_response) && must_understand?(ecp_response)
          return append_error("ECP Response must target the next SOAP actor and must be understood")
        end

        @assertion_consumer_service_url = attribute(ecp_response, nil, "AssertionConsumerServiceURL")
        return append_error("Missing ECP Response AssertionConsumerServiceURL") if @assertion_consumer_service_url.to_s.empty?
        return append_error("Unsupported SAML Response version") unless @response.attributes["Version"] == "2.0"
        if REXML::XPath.first(document, "//*[local-name()='RelayState']")
          return append_error("RelayState must not be carried in the ECP SOAP message")
        end

        response_xml = saml_message_xml(@response)
        unless valid_saml?(REXML::Document.new(response_xml), soft, check_malformed_doc?(settings))
          return append_error("Invalid SAML Response")
        end
        true
      end
    end

    class EcpSpResponse < EcpMessage
      def response(settings, options = {})
        @response ||= Response.new(response_xml, options.merge(:settings => settings))
      end

      def response_xml
        @response_xml ||= saml_message_xml(body_child(PROTOCOL, "Response"))
      end

      private

      def validate_message
        return false unless super
        if header_child(ECP_NAMESPACE, "Response")
          return append_error("Processed ECP Response header must not be sent to the SP")
        end
        unless body_child(PROTOCOL, "Response")
          return append_error("Missing SAML Response")
        end
        if REXML::XPath.first(document, "//*[local-name()='RelayState']")
          return append_error("RelayState must not be carried in the SAML SOAP message")
        end
        response_xml
        true
      end
    end

    class PaosRequest
      PAOS_HEADER_NAME = "PAOS"
      ACCEPT_HEADER_NAME = "Accept"
      RELAY_STATE_HEADER_NAME = "RelayState"

      attr_reader :accept, :paos, :relay_state, :services

      def self.identify?(headers)
        new(headers).ecp?
      end

      def initialize(headers = {}, relay_state = nil)
        normalized = normalize_headers(headers)
        @accept = normalized["accept"].to_s
        @paos = normalized["paos"].to_s
        @relay_state = relay_state.nil? ? normalized["relaystate"] : relay_state
        @services = quoted_values(@paos)
      end

      def ecp?
        accepts_paos? && services.include?(Utils::BINDINGS[:paos])
      end
      alias paos? ecp?

      def accepts_paos?
        media_types.any? { |media_type| media_type == EcpMessage::PAOS_CONTENT_TYPE }
      end

      def media_types
        accept.split(/\s*,\s*/).map { |value| value.split(";", 2).first.to_s.strip }
      end

      def client_headers
        headers = {
          ACCEPT_HEADER_NAME => EcpMessage::PAOS_CONTENT_TYPE,
          PAOS_HEADER_NAME => "ver=\"#{EcpMessage::PAOS_NAMESPACE}\";\"#{Utils::BINDINGS[:paos]}\""
        }
        headers[RELAY_STATE_HEADER_NAME] = relay_state unless relay_state.nil?
        headers
      end

      private

      def normalize_headers(headers)
        normalized = {}
        headers.each do |name, value|
          header_name = name.to_s.sub(/\AHTTP_/, "").tr("_", "-").downcase
          normalized[header_name] = value.to_s
        end
        normalized
      end

      def quoted_values(value)
        value.scan(/"([^"]+)"/).flatten
      end
    end

    class EcpHttpRequest
      attr_reader :url, :headers, :body

      def initialize(url, headers = {}, body = nil)
        @url = url
        @headers = headers
        @body = body
      end
    end

    class EcpHttpResponse
      attr_reader :status, :headers, :body

      def initialize(status, headers, body)
        @status = status.to_i
        @headers = {}
        headers.each { |name, value| @headers[name.to_s.downcase] = value.to_s }
        @body = body.to_s
      end

      def success?
        status >= 200 && status < 300
      end

      def content_type
        headers["content-type"].to_s.split(";", 2).first.to_s.strip
      end
    end

    class EcpResult
      attr_reader :authn_request, :idp_response, :sp_response, :relay_state, :request_id, :http_requests

      def initialize(authn_request, idp_response, sp_response, relay_state, http_requests)
        @authn_request = authn_request
        @idp_response = idp_response
        @sp_response = sp_response
        @relay_state = relay_state
        @request_id = authn_request.request_id
        @http_requests = http_requests
      end
    end

class EcpClient
      attr_reader :transport

      def initialize(&transport)
        @transport = transport
      end

      def authenticate(settings, options = {})
        transport = options[:transport] || @transport
        raise ArgumentError.new("A transport block is required") unless transport

        relay_state = options[:relay_state]
        http_requests = []
        initial_response = options[:initial_response]

        if initial_response.nil?
          initial_request = EcpHttpRequest.new(
            options.fetch(:sp_url, settings.assertion_consumer_service_url),
            PaosRequest.new(options[:headers] || {}, relay_state).client_headers
          )
          http_requests << initial_request
          initial_http_response = invoke(transport, initial_request)
          ensure_response!(initial_http_response, EcpMessage::PAOS_CONTENT_TYPE)
          initial_response = initial_http_response.body
        end

        authn_request = EcpAuthnRequest.new(initial_response, settings)
        unless authn_request.valid?
          raise ValidationError.new(authn_request.errors.join(", "))
        end

        if settings.idp_sso_service_url.nil? || settings.idp_sso_service_url.empty?
          raise SettingError.new("Invalid settings, idp_sso_service_url is not set!")
        end

        idp_request = EcpHttpRequest.new(settings.idp_sso_service_url, idp_headers(relay_state), authn_request.to_idp_request)
        http_requests << idp_request
        idp_http_response = invoke(transport, idp_request)
        ensure_response!(idp_http_response, EcpMessage::SOAP_MEDIA_TYPE)

        idp_response = EcpResponse.new(idp_http_response.body, settings)
        consumer_url = authn_request.authn_request.attributes["AssertionConsumerServiceURL"]
        unless idp_response.valid? && idp_response.validate_response_consumer_url(consumer_url)
          raise ValidationError.new(idp_response.errors.join(", "))
        end

        sp_request = EcpHttpRequest.new(idp_response.assertion_consumer_service_url, sp_headers(relay_state), idp_response.to_sp_request)
        http_requests << sp_request
        sp_http_response = invoke(transport, sp_request)
        sp_soap = EcpSpResponse.new(sp_request.body, settings)
        unless sp_soap.valid?
          raise ValidationError.new(sp_soap.errors.join(", "))
        end
        response = sp_soap.response(settings, response_options(options, authn_request.request_id))
        if !sp_http_response.body.to_s.empty?
          ensure_response!(sp_http_response, EcpMessage::SOAP_MEDIA_TYPE)
        end

        EcpResult.new(authn_request, idp_response, response, relay_state, http_requests)
      end

      private

      def invoke(transport, request)
        result = transport.call(request)
        return result if result.is_a?(EcpHttpResponse)
        if result.is_a?(Array)
          EcpHttpResponse.new(result[0], result[1] || {}, result[2].to_s)
        else
          EcpHttpResponse.new(200, {}, result.to_s)
        end
      end

      def ensure_response!(response, content_type)
        unless response.success?
          raise ValidationError.new("ECP HTTP request failed with status #{response.status}")
        end
        unless response.content_type == content_type
          raise ValidationError.new("Unexpected ECP Content-Type #{response.content_type}, expected #{content_type}")
        end
      end

      def idp_headers(relay_state)
        # RelayState is opaque transport state for the non-browser client. It is
        # intentionally kept out of both SAML messages and Response validation.
        headers = { "Content-Type" => EcpMessage::CONTENT_TYPE, "SOAPAction" => EcpMessage::SOAP_ACTION }
        headers["RelayState"] = relay_state unless relay_state.nil?
        headers
      end

      def sp_headers(relay_state)
        idp_headers(relay_state)
      end

      def response_options(options, request_id)
        response_options = options[:response_options] ? options[:response_options].dup : {}
        response_options[:matches_request_id] = request_id unless response_options.key?(:matches_request_id)
        response_options
      end
    end

  end
end
