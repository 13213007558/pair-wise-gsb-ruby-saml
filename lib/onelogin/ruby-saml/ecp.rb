require 'cgi'
require 'nokogiri'

require "onelogin/ruby-saml/saml_message"

module OneLogin
  module RubySaml
    # Client side of the SAML 2.0 ECP (Enhanced Client or Proxy) basic
    # profile.
    #
    # The client accepts a PAOS-wrapped AuthnRequest from a Service
    # Provider, delivers it to the configured Identity Provider and
    # returns the IdP response to the Service Provider. All network I/O
    # is performed by a caller supplied adapter, so the client never
    # opens connections itself.
    #
    # ECP 2.0 extensions (channel bindings, holder-of-key confirmation,
    # ...) are intentionally not implemented.
    module ECP
      SOAP_ENV   = "http://schemas.xmlsoap.org/soap/envelope/".freeze
      PAOS       = "urn:liberty:paos:2003-08".freeze
      ECP_NS     = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp".freeze
      ACTOR_NEXT = "http://schemas.xmlsoap.org/soap/actor/next".freeze

      NAMESPACES = {
        'soap'  => SOAP_ENV,
        'paos'  => PAOS,
        'ecp'   => ECP_NS,
        'samlp' => SamlMessage::PROTOCOL
      }.freeze

      # Base class for ECP errors.
      class Error < StandardError; end

      # A failure that must be reported to the Service Provider as a SOAP
      # fault. Fault strings are intentionally generic: they never carry
      # credentials, assertions or full message payloads.
      class SOAPFaultError < Error
        attr_reader :fault_code

        def initialize(fault_code, fault_string)
          @fault_code = fault_code
          super(fault_string)
        end

        # Renders the fault as a SOAP 1.1 envelope that can be returned
        # to the Service Provider.
        # @return [String] The SOAP fault envelope
        def to_soap
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +          "<env:Envelope xmlns:env=\"#{SOAP_ENV}\">" +          "<env:Body><env:Fault>" +          "<faultcode>#{fault_code}</faultcode>" +          "<faultstring>#{CGI.escapeHTML(message)}</faultstring>" +          "</env:Fault></env:Body></env:Envelope>\n"
        end
      end

      # Implements the ECP basic profile message exchange.
      class Client
        SOAP_CONTENT_TYPE = "application/soap+xml; charset=utf-8".freeze

        attr_reader :idp_url, :idp_credentials, :provider_name, :is_passive

        # @param idp_url [String] ECP endpoint of the Identity Provider.
        # @param http_adapter [#post] Performs the HTTP exchange with the
        #   IdP. It must respond to +post(url, body, headers, credentials)+
        #   and return an object exposing +status+ and +body+.
        # @param idp_credentials [Object] Authentication material for the
        #   IdP leg only (e.g. basic-auth credentials). It is passed
        #   verbatim to the adapter and is never used on the Service
        #   Provider leg, which keeps SP and IdP credentials separated.
        # @param provider_name [String, nil] Optional human readable SP
        #   name sent to the IdP in the ECP Request header.
        # @param is_passive [Boolean] Whether the IdP must not interact
        #   with the user (ECP Request IsPassive flag).
        def initialize(idp_url:, http_adapter:, idp_credentials: nil, provider_name: nil, is_passive: false)
          raise ArgumentError, "idp_url is required" if idp_url.nil? || idp_url.to_s.empty?
          unless http_adapter.respond_to?(:post)
            raise ArgumentError, "http_adapter must respond to #post"
          end

          @idp_url = idp_url
          @http_adapter = http_adapter
          @idp_credentials = idp_credentials
          @provider_name = provider_name
          @is_passive = is_passive ? true : false
        end

        # Handles one ECP exchange.
        #
        # @param sp_soap_xml [String] PAOS AuthnRequest received from the SP
        # @return [String] SOAP envelope to deliver back to the SP
        # @raise [SOAPFaultError] render #to_soap and return it to the SP
        def handle_sp_request(sp_soap_xml)
          request = parse_sp_request(sp_soap_xml)
          idp_response_xml = request_idp_response(build_idp_request(request))
          idp_document = parse_idp_response(idp_response_xml, request)
          build_sp_response(idp_document, request.relay_state)
        end

        private

        SpRequest = Struct.new(:document, :authn_request, :acs_url, :relay_state)

        # Parses and validates the PAOS AuthnRequest sent by the SP.
        # @return [SpRequest]
        def parse_sp_request(sp_soap_xml)
          document = parse_envelope(sp_soap_xml, 'env:Sender')
          header = required_header(document, 'env:Sender')
          paos_node, relay_node = validate_sp_headers(header)
          body = required_body(document, 'env:Sender')
          authn_request = only_child(body, 'AuthnRequest', 'env:Sender')

          acs_url = authn_request['AssertionConsumerServiceURL']
          if acs_url.nil? || acs_url.empty?
            raise SOAPFaultError.new('env:Sender', 'AuthnRequest does not declare an AssertionConsumerServiceURL')
          end

          response_consumer_url = paos_node['responseConsumerURL']
          if response_consumer_url.nil? || response_consumer_url.empty?
            raise SOAPFaultError.new('env:Sender', 'PAOS Request header does not declare a responseConsumerURL')
          end
          if response_consumer_url != acs_url
            raise SOAPFaultError.new('env:Sender', 'PAOS responseConsumerURL does not match the AuthnRequest AssertionConsumerServiceURL')
          end

          SpRequest.new(document, authn_request, acs_url, relay_node && relay_node.text)
        end

        # Validates the PAOS and ECP RelayState headers of the SP message.
        # @return [Array(Nokogiri::XML::Element, Nokogiri::XML::Element|nil)]
        def validate_sp_headers(header)
          paos_nodes = []
          relay_nodes = []
          header.element_children.each do |node|
            namespace = node.namespace && node.namespace.href
            if namespace == PAOS && node.name == 'Request'
              paos_nodes << node
            elsif namespace == ECP_NS && node.name == 'RelayState'
              relay_nodes << node
            elsif must_understand?(node) && ecp_actor?(node)
              raise SOAPFaultError.new('env:MustUnderstand', 'Unsupported mandatory SOAP header')
            end
          end

          if paos_nodes.empty?
            raise SOAPFaultError.new('env:Sender', 'Missing PAOS Request header')
          end
          if paos_nodes.size > 1
            raise SOAPFaultError.new('env:Sender', 'Duplicate PAOS Request headers')
          end
          if relay_nodes.size > 1
            raise SOAPFaultError.new('env:Sender', 'Duplicate ECP RelayState headers')
          end

          paos_node = paos_nodes.first
          unless actor(paos_node) == ACTOR_NEXT && must_understand?(paos_node)
            raise SOAPFaultError.new('env:Sender', 'PAOS Request header has an invalid actor or mustUnderstand value')
          end

          relay_node = relay_nodes.first
          if relay_node && !(actor(relay_node) == ECP_NS && must_understand?(relay_node))
            raise SOAPFaultError.new('env:Sender', 'ECP RelayState header has an invalid actor or mustUnderstand value')
          end

          [paos_node, relay_node]
        end

        # Builds the SOAP message sent to the IdP: the SP envelope without
        # the consumed PAOS and ECP RelayState headers, plus an optional
        # ECP Request header.
        # @return [String]
        def build_idp_request(request)
          document = request.document
          header = document.at_xpath('/soap:Envelope/soap:Header', NAMESPACES)
          header.element_children.each do |node|
            namespace = node.namespace && node.namespace.href
            if (namespace == PAOS && node.name == 'Request') ||
               (namespace == ECP_NS && node.name == 'RelayState')
              node.remove
            end
          end
          add_ecp_request_header(header) if provider_name || is_passive
          header.remove if header.element_children.empty?
          document.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
        end

        def add_ecp_request_header(header)
          fragment = +"<ecp:Request xmlns:ecp=\"#{ECP_NS}\" xmlns:soap=\"#{SOAP_ENV}\" " +                      "xmlns:samlp=\"#{SamlMessage::PROTOCOL}\" soap:mustUnderstand=\"1\" soap:actor=\"#{ACTOR_NEXT}\">"
          fragment << "<samlp:IsPassive>true</samlp:IsPassive>" if is_passive
          fragment << "<samlp:ProviderName>#{CGI.escapeHTML(provider_name)}</samlp:ProviderName>" if provider_name
          fragment << "</ecp:Request>"
          header.add_child(Nokogiri::XML::DocumentFragment.parse(fragment))
        end

        # Delivers the AuthnRequest to the IdP through the adapter. The IdP
        # credentials travel with this call only.
        # @return [String] The SOAP envelope returned by the IdP
        def request_idp_response(idp_request_xml)
          response = begin
            @http_adapter.post(idp_url, idp_request_xml, idp_request_headers, idp_credentials)
          rescue StandardError
            raise SOAPFaultError.new('env:Receiver', 'Failed to reach the identity provider')
          end

          status = response.respond_to?(:status) ? response.status.to_i : 0
          unless status >= 200 && status < 300
            raise SOAPFaultError.new('env:Receiver', 'Identity provider did not return a successful response')
          end

          response.body.to_s
        end

        def idp_request_headers
          { 'Content-Type' => SOAP_CONTENT_TYPE, 'Accept' => SOAP_CONTENT_TYPE }
        end

        # Parses and validates the IdP response, including the ECP Response
        # header whose AssertionConsumerServiceURL must match the address
        # declared by the SP.
        # @return [Nokogiri::XML::Document]
        def parse_idp_response(idp_response_xml, request)
          document = parse_envelope(idp_response_xml, 'env:Receiver')
          header = required_header(document, 'env:Receiver')
          ecp_response = validate_idp_headers(header)

          acs_url = ecp_response['AssertionConsumerServiceURL']
          if acs_url.nil? || acs_url.empty?
            raise SOAPFaultError.new('env:Receiver', 'Identity provider response does not declare an AssertionConsumerServiceURL')
          end
          if acs_url != request.acs_url
            raise SOAPFaultError.new('env:Receiver', 'Identity provider response consumer URL does not match the service provider assertion consumer service URL')
          end

          body = required_body(document, 'env:Receiver')
          only_child(body, 'Response', 'env:Receiver')

          document
        end

        # Validates the ECP Response header of the IdP message.
        # @return [Nokogiri::XML::Element]
        def validate_idp_headers(header)
          ecp_response_nodes = []
          header.element_children.each do |node|
            namespace = node.namespace && node.namespace.href
            if namespace == ECP_NS && node.name == 'Response'
              ecp_response_nodes << node
            elsif must_understand?(node) && ecp_actor?(node)
              raise SOAPFaultError.new('env:MustUnderstand', 'Unsupported mandatory SOAP header')
            end
          end

          if ecp_response_nodes.empty?
            raise SOAPFaultError.new('env:Receiver', 'Identity provider response is missing the ECP Response header')
          end
          if ecp_response_nodes.size > 1
            raise SOAPFaultError.new('env:Receiver', 'Duplicate ECP Response headers')
          end

          node = ecp_response_nodes.first
          unless actor(node) == ECP_NS && must_understand?(node)
            raise SOAPFaultError.new('env:Receiver', 'ECP Response header has an invalid actor or mustUnderstand value')
          end

          node
        end

        # Builds the SOAP message returned to the SP: the IdP response with
        # the ECP Response header replaced by the RelayState header that
        # echoes the value supplied by the SP.
        # @return [String]
        def build_sp_response(idp_document, relay_state)
          header = idp_document.at_xpath('/soap:Envelope/soap:Header', NAMESPACES)
          header.children.each(&:remove)
          if relay_state
            header.add_child(Nokogiri::XML::DocumentFragment.parse(
              "<ecp:RelayState xmlns:ecp=\"#{ECP_NS}\" xmlns:soap=\"#{SOAP_ENV}\" " +              "soap:mustUnderstand=\"1\" soap:actor=\"#{ECP_NS}\">#{CGI.escapeHTML(relay_state)}</ecp:RelayState>"
            ))
          end
          header.remove if header.element_children.empty?
          idp_document.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
        end

        def parse_envelope(xml, fault_code)
          document = Nokogiri::XML(xml.to_s) { |config| config.strict.nonet }
          root = document.root
          if root.nil? || root.name != 'Envelope' || root.namespace.nil? || root.namespace.href != SOAP_ENV
            raise SOAPFaultError.new(fault_code, 'Message is not a SOAP envelope')
          end
          document
        rescue Nokogiri::XML::SyntaxError
          raise SOAPFaultError.new(fault_code, 'Malformed SOAP message')
        end

        def required_header(document, fault_code)
          header = document.at_xpath('/soap:Envelope/soap:Header', NAMESPACES)
          raise SOAPFaultError.new(fault_code, 'SOAP header is missing') if header.nil?
          header
        end

        def required_body(document, fault_code)
          body = document.at_xpath('/soap:Envelope/soap:Body', NAMESPACES)
          raise SOAPFaultError.new(fault_code, 'SOAP body is missing') if body.nil?
          body
        end

        def only_child(body, name, fault_code)
          children = body.element_children
          valid = children.size == 1 &&
                  children.first.name == name &&
                  children.first.namespace &&
                  children.first.namespace.href == SamlMessage::PROTOCOL
          unless valid
            raise SOAPFaultError.new(fault_code, "SOAP body must contain exactly one #{name}")
          end
          children.first
        end

        def actor(node)
          attribute = node.attribute_with_ns('actor', SOAP_ENV) || node.attribute('actor')
          attribute && attribute.value
        end

        def must_understand?(node)
          attribute = node.attribute_with_ns('mustUnderstand', SOAP_ENV) || node.attribute('mustUnderstand')
          !attribute.nil? && %w[1 true].include?(attribute.value.strip)
        end

        # Whether the header targets the ECP (no actor, the next SOAP node
        # or the ECP role) and therefore must be understood by us.
        def ecp_actor?(node)
          value = actor(node)
          value.nil? || value == ACTOR_NEXT || value == ECP_NS
        end
      end
    end
  end
end
