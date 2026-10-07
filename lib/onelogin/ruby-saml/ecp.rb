require "rexml/document"

require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/validation_error"

module OneLogin
  module RubySaml
    class Ecp
      include REXML

      SOAP_NS    = "http://schemas.xmlsoap.org/soap/envelope/".freeze
      PAOS_NS    = "urn:liberty:paos:2003-08".freeze
      ECP_NS     = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp".freeze
      SERVICE    = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp".freeze
      SOAP_ACTOR = "http://schemas.xmlsoap.org/soap/actor/next".freeze

      PAOS_CONTENT_TYPE = "application/vnd.paos+xml".freeze
      SOAP_CONTENT_TYPE = "text/xml; charset=utf-8".freeze
      SOAP_ACTION       = "http://www.oasis-open.org/committees/security".freeze

      NAMESPACES = {
        "soap" => SOAP_NS,
        "paos" => PAOS_NS,
        "ecp" => ECP_NS,
        "samlp" => SamlMessage::PROTOCOL
      }.freeze

      class Message
        include REXML

        attr_reader :document, :headers, :body

        def initialize(xml)
          begin
            @document = REXML::Document.new(xml)
            envelope = XPath.first(@document, "/soap:Envelope", Ecp::NAMESPACES)
            raise ValidationError.new("Expected a SOAP Envelope") if envelope.nil?

            @headers = XPath.match(envelope, "soap:Header/*", Ecp::NAMESPACES)
            body_elements = XPath.match(envelope, "soap:Body/*", Ecp::NAMESPACES)
            unless body_elements.size == 1
              raise ValidationError.new("Expected exactly one SOAP body element")
            end

            @body = body_elements.first
          rescue REXML::ParseException => error
            raise ValidationError.new("Invalid SOAP XML: #{error.message}")
          end
        end

        def header(namespace, name)
          @headers.detect do |element|
            element.name == name && element.namespace == namespace
          end
        end

        def body_xml
          node_to_xml(@body)
        end

        def relay_state
          node = header(Ecp::ECP_NS, "RelayState")
          node.nil? ? nil : node.text
        end

        def validate_must_understand_headers!(*allowed_headers)
          @headers.each do |node|
            next unless must_understand?(node) && actor?(node)

            allowed = allowed_headers.any? do |namespace, name|
              node.namespace == namespace && node.name == name
            end
            next if allowed

            raise ValidationError.new("Unexpected mustUnderstand SOAP header #{node.name}")
          end
        end

        def unique_header!(namespace, name)
          nodes = @headers.select do |element|
            element.namespace == namespace && element.name == name
          end
          return if nodes.empty?

          if nodes.size > 1
            raise ValidationError.new("Expected at most one SOAP header #{name}")
          end

          nodes.first
        end

        private

        def node_to_xml(node)
          document = REXML::Document.new
          document.add_element(node.deep_clone)
          Ecp.send(:to_xml, document)
        end

        def must_understand?(node)
          attribute = node.attributes.get_attribute_ns(Ecp::SOAP_NS, "mustUnderstand")
          !attribute.nil? && ["1", "true"].include?(attribute.value)
        end

        def actor?(node)
          attribute = node.attributes.get_attribute_ns(Ecp::SOAP_NS, "actor")
          !attribute.nil? && attribute.value == Ecp::SOAP_ACTOR
        end

        def soap_actor_omitted?(node)
          node.attributes.get_attribute_ns(Ecp::SOAP_NS, "actor").nil?
        end

        def require_header!(namespace, name)
          node = header(namespace, name)
          if node.nil? || !must_understand?(node) || !actor?(node)
            raise ValidationError.new("Required SOAP header #{name} is missing or invalid")
          end
          node
        end

        def require_response_header!(namespace, name)
          node = header(namespace, name)
          valid_actor = !node.nil? && (actor?(node) || soap_actor_omitted?(node))
          if node.nil? || !must_understand?(node) || !valid_actor
            raise ValidationError.new("Required SOAP header #{name} is missing or invalid")
          end
          node
        end

        def require_optional_header!(namespace, name)
          node = header(namespace, name)
          return nil if node.nil?

          unless must_understand?(node) && actor?(node)
            raise ValidationError.new("SOAP header #{name} is invalid")
          end
          node
        end
      end

      class AuthnRequestMessage < Message
        attr_reader :request, :response_consumer_url, :idp_url

        def initialize(xml)
          super

          validate_must_understand_headers!(
            [PAOS_NS, "Request"],
            [ECP_NS, "Request"],
            [ECP_NS, "RelayState"]
          )

          unless @body.name == "AuthnRequest" && @body.namespace == SamlMessage::PROTOCOL
            raise ValidationError.new("Expected a SAML AuthnRequest in the SOAP body")
          end

          paos_request = require_header!(PAOS_NS, "Request")
          ecp_request = require_header!(ECP_NS, "Request")
          unique_header!(PAOS_NS, "Request")
          unique_header!(ECP_NS, "Request")
          relay_state_header = unique_header!(ECP_NS, "RelayState")
          require_optional_header!(ECP_NS, "RelayState") unless relay_state_header.nil?

          issuer = REXML::XPath.first(ecp_request, "saml:Issuer", NAMESPACES.merge("saml" => SamlMessage::ASSERTION))
          if issuer.nil?
            raise ValidationError.new("ECP request is missing the SAML Issuer")
          end

          if paos_request.attributes["service"] != SERVICE
            raise ValidationError.new("PAOS request does not target the SAML ECP service")
          end

          @response_consumer_url = paos_request.attributes["responseConsumerURL"]
          if @response_consumer_url.nil? || @response_consumer_url.empty?
            raise ValidationError.new("PAOS request is missing responseConsumerURL")
          end

          assertion_consumer_service_url = @body.attributes["AssertionConsumerServiceURL"]
          if assertion_consumer_service_url && assertion_consumer_service_url != @response_consumer_url
            raise ValidationError.new("responseConsumerURL does not match AssertionConsumerServiceURL")
          end

          @idp_url = @body.attributes["Destination"]
          if @idp_url.nil? || @idp_url.empty?
            raise ValidationError.new("AuthnRequest is missing Destination")
          end
          @request = body_xml
        end
      end

      class ResponseMessage < Message
        attr_reader :response, :assertion_consumer_service_url

        def initialize(xml)
          super

          validate_must_understand_headers!([ECP_NS, "Response"])

          unless @body.name == "Response" && @body.namespace == SamlMessage::PROTOCOL
            raise ValidationError.new("Expected a SAML Response in the SOAP body")
          end

          ecp_response = require_response_header!(ECP_NS, "Response")
          unique_header!(ECP_NS, "Response")

          unless header(PAOS_NS, "Request").nil?
            raise ValidationError.new("PAOS Request must not be sent to the assertion consumer service")
          end

          unless header(ECP_NS, "Request").nil?
            raise ValidationError.new("ECP Request must not be included in the IdP response")
          end

          unless header(ECP_NS, "RelayState").nil?
            raise ValidationError.new("ECP RelayState must only be returned to the responseConsumerURL")
          end

          @assertion_consumer_service_url = ecp_response.attributes["AssertionConsumerServiceURL"]
          if @assertion_consumer_service_url.nil? || @assertion_consumer_service_url.empty?
            raise ValidationError.new("ECP response is missing AssertionConsumerServiceURL")
          end

          @response = body_xml
        end

        def response_consumer_url_matches?(url)
          assertion_consumer_service_url == url
        end
      end

      class AssertionConsumerMessage < Message
        attr_reader :response

        def initialize(xml)
          super

          validate_must_understand_headers!([ECP_NS, "RelayState"])

          unless @body.name == "Response" && @body.namespace == SamlMessage::PROTOCOL
            raise ValidationError.new("Expected a SAML Response in the SOAP body")
          end

          [
            [PAOS_NS, "Request"],
            [ECP_NS, "Request"],
            [ECP_NS, "Response"]
          ].each do |namespace, name|
            unless header(namespace, name).nil?
              raise ValidationError.new("SOAP header #{name} must not be sent to the assertion consumer service")
            end
          end

          relay_state_node = unique_header!(ECP_NS, "RelayState")
          require_optional_header!(ECP_NS, "RelayState") unless relay_state_node.nil?

          @response = body_xml
        end
      end

      class << self
        def paos_request?(headers)
          accept = header_value(headers, "Accept", "HTTP_ACCEPT")
          paos = header_value(headers, "PAOS", "HTTP_PAOS")

          accept.to_s.include?(PAOS_CONTENT_TYPE) &&
            paos.to_s =~ /ver="#{Regexp.escape(PAOS_NS)}"\s*;\s*"#{Regexp.escape(SERVICE)}"/ ? true : false
        end

        def request_headers
          {
            "Accept" => "text/html, #{PAOS_CONTENT_TYPE}",
            "PAOS" => %Q{ver="#{PAOS_NS}"; "#{SERVICE}"}
          }
        end

        def idp_request_headers
          {
            "Content-Type" => SOAP_CONTENT_TYPE,
            "SOAPAction" => SOAP_ACTION
          }
        end

        def sp_response_headers
          {
            "Content-Type" => PAOS_CONTENT_TYPE
          }
        end

        def parse_authn_request(xml)
          AuthnRequestMessage.new(xml)
        end

        def parse_response(xml)
          ResponseMessage.new(xml)
        end

        def parse_assertion_consumer_message(xml)
          AssertionConsumerMessage.new(xml)
        end

        def idp_response_headers
          {
            "Content-Type" => SOAP_CONTENT_TYPE
          }
        end

        def parse_soap(xml)
          Message.new(xml)
        end

        def idp_response(response_xml, assertion_consumer_service_url)
          response = root_element(response_xml, "Response")
          envelope_document = new_envelope
          header = envelope_document.root.add_element("soap:Header")

          ecp_response = header.add_element("ecp:Response")
          ecp_response.add_attribute("soap:mustUnderstand", "1")
          ecp_response.attributes["AssertionConsumerServiceURL"] = assertion_consumer_service_url

          envelope_document.root.add_element("soap:Body").add_element(response.deep_clone)
          to_xml(envelope_document)
        end

        def idp_request(authn_request_xml)
          request = root_element(authn_request_xml, "AuthnRequest")
          envelope_document = new_envelope
          envelope_document.root.add_element("soap:Body").add_element(request.deep_clone)
          to_xml(envelope_document)
        end

        def sp_authn_request(authn_request_xml, response_consumer_url, relay_state = nil)
          request = root_element(authn_request_xml, "AuthnRequest")
          envelope_document = new_envelope
          header = envelope_document.root.add_element("soap:Header")

          paos_request = header.add_element("paos:Request")
          add_soap_attributes(paos_request)
          paos_request.attributes["responseConsumerURL"] = response_consumer_url
          paos_request.attributes["service"] = SERVICE

          ecp_request = header.add_element("ecp:Request")
          add_soap_attributes(ecp_request)
          issuer = REXML::XPath.first(request, "saml:Issuer", "saml" => SamlMessage::ASSERTION)
          if issuer.nil?
            raise ValidationError.new("AuthnRequest is missing the SAML Issuer")
          end
          ecp_request.add_element(issuer.deep_clone)

          if relay_state
            relay_state_element = header.add_element("ecp:RelayState")
            add_soap_attributes(relay_state_element)
            relay_state_element.text = relay_state
          end

          envelope_document.root.add_element("soap:Body").add_element(request.deep_clone)
          to_xml(envelope_document)
        end

        def sp_response(response_xml, relay_state = nil)
          response = root_element(response_xml, "Response")
          envelope_document = new_envelope
          header = envelope_document.root.add_element("soap:Header")

          if relay_state
            relay_state_element = header.add_element("ecp:RelayState")
            add_soap_attributes(relay_state_element)
            relay_state_element.text = relay_state
          end

          envelope_document.root.add_element("soap:Body").add_element(response.deep_clone)
          to_xml(envelope_document)
        end

        private

        def header_value(headers, name, rack_name = nil)
          return nil if headers.nil?

          if headers.is_a?(Hash)
            headers[name] || headers[name.downcase] || headers[name.upcase] ||
              (rack_name && (headers[rack_name] || headers[rack_name.downcase] || headers[rack_name.to_sym]))
          else
            headers.each do |key, value|
              return value if key.to_s.downcase == name.downcase
            end
            nil
          end
        end

        def root_element(xml, name)
          document = REXML::Document.new(xml)
          root = document.root
          if root.nil? || root.name != name
            raise ValidationError.new("Expected a SAML #{name}")
          end
          root
        end

        def new_envelope
          document = REXML::Document.new
          envelope = document.add_element("soap:Envelope")
          envelope.add_namespace("soap", SOAP_NS)
          envelope.add_namespace("paos", PAOS_NS)
          envelope.add_namespace("ecp", ECP_NS)
          envelope.add_namespace("samlp", SamlMessage::PROTOCOL)
          envelope.add_namespace("saml", SamlMessage::ASSERTION)
          document
        end

        def add_soap_attributes(element)
          element.add_attribute("soap:mustUnderstand", "1")
          element.add_attribute("soap:actor", SOAP_ACTOR)
        end

        def to_xml(document)
          xml = "".dup
          document.write(xml)
          xml
        end
      end

      class Exchange
        attr_reader :sp_headers, :idp_request_headers, :sp_response_headers

        def initialize
          @sp_headers = Ecp.request_headers
          @idp_request_headers = Ecp.idp_request_headers
          @sp_response_headers = Ecp.sp_response_headers
        end

        def from_sp(soap_message)
          message = Ecp.parse_authn_request(soap_message)
          {
            :url => message.idp_url,
            :headers => idp_request_headers,
            :body => Ecp.idp_request(message.request),
            :response_consumer_url => message.response_consumer_url,
            :relay_state => message.relay_state,
            :request_id => message.body.attributes["ID"]
          }
        end

        def from_idp(soap_message, response_consumer_url, relay_state = nil)
          message = Ecp.parse_response(soap_message)
          unless message.response_consumer_url_matches?(response_consumer_url)
            raise ValidationError.new(
              "responseConsumerURL #{response_consumer_url} does not match AssertionConsumerServiceURL #{message.assertion_consumer_service_url}"
            )
          end

          {
            :url => response_consumer_url,
            :headers => sp_response_headers,
            :body => Ecp.sp_response(message.response, relay_state),
            :response => message.response,
            :relay_state => relay_state
          }
        end
        alias_method :relay_sp_response, :from_idp
      end

      Client = Exchange
    end
  end
end
