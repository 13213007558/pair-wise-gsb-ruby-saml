require 'cgi'
require 'nokogiri'

module OneLogin
  module RubySaml
    # Implements the client (ECP) side of the SAML 2.0 Enhanced Client or
    # Proxy basic profile: the ECP receives a PAOS AuthnRequest from the
    # service provider, forwards it to the configured identity provider over
    # SOAP, and delivers the resulting response back to the service provider.
    #
    # Channel bindings and other ECP 2.0 extensions are out of scope.
    module Ecp
      SOAP_ENV     = "http://schemas.xmlsoap.org/soap/envelope/".freeze
      PAOS         = "urn:liberty:paos:2003-08".freeze
      ECP_NS       = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp".freeze
      WSSE         = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd".freeze
      ACTOR_NEXT   = "http://schemas.xmlsoap.org/soap/actor/next".freeze
      PAOS_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS".freeze
      ASSERTION    = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
      PROTOCOL     = "urn:oasis:names:tc:SAML:2.0:protocol".freeze

      # SAML Bindings 3.5.3 limits RelayState to 80 bytes.
      MAX_RELAY_STATE_BYTES = 80

      FAULT_CLIENT          = "soap:Client".freeze
      FAULT_SERVER          = "soap:Server".freeze
      FAULT_MUST_UNDERSTAND = "soap:MustUnderstand".freeze

      # Base error for ECP exchange failures. Carries the stage at which the
      # exchange failed plus a stage-appropriate SOAP fault document. Neither
      # the message nor the fault ever contains credentials or assertion
      # content.
      class Error < StandardError
        attr_reader :stage, :fault_code

        def initialize(stage, fault_code, detail)
          @stage = stage
          @fault_code = fault_code
          @detail = detail
          super("ECP #{stage} exchange failed: #{detail}")
        end

        # @return [String] SOAP 1.1 fault document for the failed stage
        def fault
          <<~XML
            <?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="#{SOAP_ENV}">
              <soap:Body>
                <soap:Fault>
                  <faultcode>#{fault_code}</faultcode>
                  <faultstring>#{CGI.escapeHTML("ECP #{stage} exchange failed: #{@detail}")}</faultstring>
                </soap:Fault>
              </soap:Body>
            </soap:Envelope>
          XML
        end
      end

      # The PAOS request received from the service provider is invalid, or
      # the response could not be delivered back to it.
      class SpRequestError < Error
        def initialize(fault_code, detail)
          super(:sp, fault_code, detail)
        end
      end

      # The identity provider exchange failed or its response is invalid.
      class IdpExchangeError < Error
        def initialize(fault_code, detail)
          super(:idp, fault_code, detail)
        end
      end

      # Drives one ECP authentication exchange. Network access is delegated
      # to a caller-provided adapter so the client works in any environment
      # (background jobs, CLIs, tests).
      #
      # The adapter must respond to:
      #   post(url, body:, headers:) -> response
      # where +headers+ is a Hash of HTTP headers and +response+ responds to
      # #status (Integer) and #body (String).
      #
      # Authentication material is scoped per hop: +idp_credentials+ are only
      # sent to the identity provider and +sp_credentials+ only to the service
      # provider. Each is a Hash of HTTP header name => value.
      class Client
        # Result of a successful exchange.
        Exchange = Struct.new(
          :relay_state,                      # RelayState echoed back to the SP
          :assertion_consumer_service_url,   # consumer URL validated on both hops
          :response_document,                # samlp:Response XML from the IdP
          :sp_envelope,                      # SOAP envelope delivered to the SP
          :idp_status,                       # HTTP status of the IdP call
          :sp_status,                        # HTTP status of the SP delivery
          keyword_init: true
        )

        attr_reader :idp_sso_url

        def initialize(idp_sso_url:, adapter:, idp_credentials: {}, sp_credentials: {})
          @idp_sso_url = idp_sso_url
          @adapter = adapter
          @idp_credentials = idp_credentials || {}
          @sp_credentials = sp_credentials || {}
        end

        # Runs one ECP exchange for a PAOS AuthnRequest sent by the SP.
        #
        # @param paos_request_xml [String] SOAP envelope received from the SP
        # @return [Exchange] the completed exchange
        # @raise [SpRequestError] if the SP message is invalid or undeliverable
        # @raise [IdpExchangeError] if the IdP exchange fails
        def authenticate(paos_request_xml)
          envelope = parse_xml(paos_request_xml, SpRequestError, FAULT_CLIENT,
                               "malformed SOAP envelope from service provider")
          header, body = envelope_parts(envelope, SpRequestError, FAULT_CLIENT)

          paos_request, relay_state = validate_sp_headers(header)
          authn_request = extract_authn_request(body)
          declared_acs = resolve_declared_acs(paos_request, authn_request)

          idp_response = post(idp_sso_url, build_idp_envelope(authn_request),
                              @idp_credentials, IdpExchangeError)
          idp_document = parse_xml(idp_response.body, IdpExchangeError, FAULT_SERVER,
                                   "malformed SOAP response from identity provider")
          saml_response = validate_idp_envelope(idp_document, declared_acs)

          sp_envelope = build_sp_envelope(saml_response, relay_state)
          delivery = post(paos_request["responseConsumerURL"], sp_envelope,
                          @sp_credentials, SpRequestError)

          Exchange.new(
            relay_state: relay_state,
            assertion_consumer_service_url: declared_acs,
            response_document: saml_response.to_s,
            sp_envelope: sp_envelope,
            idp_status: http_status(idp_response),
            sp_status: http_status(delivery)
          )
        end

        private

        def parse_xml(xml, error_class, fault_code, detail)
          Nokogiri::XML(xml.to_s) { |config| config.strict.nonet }
        rescue Nokogiri::XML::SyntaxError
          raise error_class.new(fault_code, detail)
        end

        def envelope_parts(document, error_class, fault_code)
          root = document.root
          unless root && root.namespace && root.namespace.href == SOAP_ENV && root.name == "Envelope"
            raise error_class.new(fault_code, "document is not a SOAP Envelope")
          end
          header = root.element_children.find { |c| soap_element?(c, "Header") }
          body = root.element_children.find { |c| soap_element?(c, "Body") }
          raise error_class.new(fault_code, "SOAP Envelope is missing a Body") if body.nil?
          [header, body]
        end

        def soap_element?(node, name)
          node.namespace && node.namespace.href == SOAP_ENV && node.name == name
        end

        def validate_sp_headers(header)
          raise SpRequestError.new(FAULT_CLIENT, "SOAP Envelope is missing a Header") if header.nil?

          paos_request = nil
          ecp_request_seen = false
          relay_state = nil
          wsse_seen = false

          header.element_children.each do |node|
            ns = node.namespace && node.namespace.href
            case [ns, node.name]
            when [PAOS, "Request"]
              raise SpRequestError.new(FAULT_CLIENT, "duplicate paos:Request header") if paos_request
              require_profile_targeting!(node, "paos:Request", SpRequestError, FAULT_CLIENT)
              unless node["service"] == ECP_NS
                raise SpRequestError.new(FAULT_CLIENT, "paos:Request service is not the ECP profile")
              end
              paos_request = node
            when [ECP_NS, "Request"]
              raise SpRequestError.new(FAULT_CLIENT, "duplicate ecp:Request header") if ecp_request_seen
              require_profile_targeting!(node, "ecp:Request", SpRequestError, FAULT_CLIENT)
              ecp_request_seen = true
            when [ECP_NS, "RelayState"]
              raise SpRequestError.new(FAULT_CLIENT, "duplicate ecp:RelayState header") if relay_state
              require_profile_targeting!(node, "ecp:RelayState", SpRequestError, FAULT_CLIENT)
              relay_state = node.text.to_s
              if relay_state.empty? || relay_state.bytesize > MAX_RELAY_STATE_BYTES
                raise SpRequestError.new(FAULT_CLIENT, "ecp:RelayState is empty or exceeds #{MAX_RELAY_STATE_BYTES} bytes")
              end
            when [WSSE, "Security"]
              raise SpRequestError.new(FAULT_CLIENT, "duplicate wsse:Security header") if wsse_seen
              wsse_seen = true
            else
              if must_understand?(node) && targeted_at_us?(node)
                raise SpRequestError.new(FAULT_MUST_UNDERSTAND, "unsupported mustUnderstand header #{node.name.inspect}")
              end
            end
          end

          raise SpRequestError.new(FAULT_CLIENT, "missing paos:Request header") if paos_request.nil?
          raise SpRequestError.new(FAULT_CLIENT, "missing ecp:Request header") unless ecp_request_seen

          consumer_url = paos_request["responseConsumerURL"].to_s
          if consumer_url.empty?
            raise SpRequestError.new(FAULT_CLIENT, "paos:Request is missing responseConsumerURL")
          end

          [paos_request, relay_state]
        end

        def extract_authn_request(body)
          node = body.element_children.find do |child|
            child.namespace && child.namespace.href == PROTOCOL && child.name == "AuthnRequest"
          end
          raise SpRequestError.new(FAULT_CLIENT, "SOAP Body does not contain a samlp:AuthnRequest") if node.nil?

          binding = node["ProtocolBinding"]
          if binding && binding != PAOS_BINDING
            raise SpRequestError.new(FAULT_CLIENT, "AuthnRequest ProtocolBinding is not PAOS")
          end
          node
        end

        # The consumer URL declared by the SP: the paos:Request
        # responseConsumerURL, which must agree with the AuthnRequest's
        # AssertionConsumerServiceURL when both are present.
        def resolve_declared_acs(paos_request, authn_request)
          consumer_url = paos_request["responseConsumerURL"].to_s
          acs = authn_request["AssertionConsumerServiceURL"].to_s
          if !acs.empty? && acs != consumer_url
            raise SpRequestError.new(FAULT_CLIENT, "AuthnRequest AssertionConsumerServiceURL does not match paos:Request responseConsumerURL")
          end
          acs.empty? ? consumer_url : acs
        end

        def validate_idp_envelope(document, declared_acs)
          header, body = envelope_parts(document, IdpExchangeError, FAULT_SERVER)

          if (fault = body.element_children.find { |c| soap_element?(c, "Fault") })
            faultstring = fault.element_children.find { |c| c.name == "faultstring" }
            detail = faultstring ? faultstring.text.to_s.strip[0, 200] : "unspecified"
            raise IdpExchangeError.new(FAULT_SERVER, "identity provider returned a SOAP fault (#{detail})")
          end

          ecp_response = nil
          header && header.element_children.each do |node|
            if node.namespace && node.namespace.href == ECP_NS && node.name == "Response"
              raise IdpExchangeError.new(FAULT_SERVER, "duplicate ecp:Response header") if ecp_response
              require_profile_targeting!(node, "ecp:Response", IdpExchangeError, FAULT_SERVER)
              ecp_response = node
            elsif must_understand?(node) && targeted_at_us?(node)
              raise IdpExchangeError.new(FAULT_MUST_UNDERSTAND, "unsupported mustUnderstand header #{node.name.inspect} from identity provider")
            end
          end
          raise IdpExchangeError.new(FAULT_SERVER, "missing ecp:Response header") if ecp_response.nil?

          acs = ecp_response["AssertionConsumerServiceURL"].to_s
          if acs.empty?
            raise IdpExchangeError.new(FAULT_SERVER, "ecp:Response is missing AssertionConsumerServiceURL")
          end
          if acs != declared_acs
            raise IdpExchangeError.new(FAULT_SERVER, "identity provider AssertionConsumerServiceURL does not match the consumer URL declared by the service provider")
          end

          saml_response = body.element_children.find do |child|
            child.namespace && child.namespace.href == PROTOCOL && child.name == "Response"
          end
          if saml_response.nil?
            raise IdpExchangeError.new(FAULT_SERVER, "identity provider response does not contain a samlp:Response")
          end
          saml_response
        end

        # Headers such as paos:Request, ecp:Request and ecp:RelayState are
        # hop-by-hop (actor = next) and are not forwarded to the IdP.
        def build_idp_envelope(authn_request)
          <<~XML
            <?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="#{SOAP_ENV}"><soap:Body>#{authn_request.to_s}</soap:Body></soap:Envelope>
          XML
        end

        def build_sp_envelope(saml_response, relay_state)
          header = +""
          if relay_state
            header << "<soap:Header><ecp:RelayState xmlns:ecp=\"#{ECP_NS}\" " +                      "soap:mustUnderstand=\"1\" soap:actor=\"#{ACTOR_NEXT}\">" +                      "#{CGI.escapeHTML(relay_state)}</ecp:RelayState></soap:Header>"
          end
          <<~XML
            <?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="#{SOAP_ENV}">#{header}<soap:Body>#{saml_response.to_s}</soap:Body></soap:Envelope>
          XML
        end

        def post(url, body, credentials, error_class)
          headers = { "Content-Type" => "text/xml; charset=utf-8" }.merge(credentials)
          response = @adapter.post(url, body: body, headers: headers)
          status = http_status(response)
          unless status && status >= 200 && status < 300
            raise error_class.new(FAULT_SERVER, "SOAP endpoint returned HTTP #{status || "unknown"}")
          end
          response
        end

        def http_status(response)
          if response.respond_to?(:status)
            response.status.to_i
          elsif response.respond_to?(:code)
            response.code.to_i
          end
        end

        def require_profile_targeting!(node, label, error_class, fault_code)
          unless must_understand?(node)
            raise error_class.new(fault_code, "#{label} is missing soap:mustUnderstand")
          end
          actor = node.attribute_with_ns("actor", SOAP_ENV)
          unless actor && actor.value == ACTOR_NEXT
            raise error_class.new(fault_code, "#{label} does not target the next SOAP node")
          end
        end

        def must_understand?(node)
          attribute = node.attribute_with_ns("mustUnderstand", SOAP_ENV)
          attribute && (attribute.value == "1" || attribute.value == "true")
        end

        def targeted_at_us?(node)
          actor = node.attribute_with_ns("actor", SOAP_ENV)
          actor.nil? || actor.value == ACTOR_NEXT
        end
      end
    end
  end
end
