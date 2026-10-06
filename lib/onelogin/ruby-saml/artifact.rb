require "digest/sha1"
require "nokogiri"
require "rexml/document"

require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/response"
require "onelogin/ruby-saml/utils"
require "onelogin/ruby-saml/validation_error"

module OneLogin
  module RubySaml
    class Artifact < SamlMessage
      include ErrorHandling

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
      SOAP_11   = "http://schemas.xmlsoap.org/soap/envelope/".freeze
      SOAP_12   = "http://www.w3.org/2003/05/soap-envelope".freeze

      ARTIFACT_TYPE_CODE = "\x00\x04".freeze
      ARTIFACT_ENCODED_LENGTH = 60
      ARTIFACT_DECODED_LENGTH = 44

      attr_reader :artifact, :settings, :document, :response, :options
      attr_reader :request_id, :source_id, :endpoint_index, :message_handle
      attr_reader :resolve_document, :artifact_response, :endpoint
      attr_accessor :soft

      def initialize(artifact, options = {})
        raise ArgumentError.new("Artifact cannot be nil") if artifact.nil?

        @artifact = artifact.to_s
        @settings = options[:settings]
        @options = options
        @errors = []
        @soft = options[:soft].nil? ? (settings.nil? || settings.soft.nil? ? true : settings.soft) : options[:soft]
        @request_id = options[:request_id] || OneLogin::RubySaml::Utils.uuid
      end

      # Resolves a SAML 2.0 type 0x0004 artifact and validates the contained Response.
      # @param transport [#call, #post] Caller-provided SOAP transport.
      # @param artifact_store [#call, #consume] Caller-provided one-time artifact store.
      # @return [OneLogin::RubySaml::Response|false] The validated inner response.
      #
      def resolve(transport = options[:transport], artifact_store = options[:artifact_store])
        reset_errors!
        @resolve_xml = nil
        @soap_request = nil

        return false unless validate_state(transport, artifact_store)
        return false unless parse_artifact
        return false unless validate_artifact
        return false unless resolve_endpoint
        return false unless consume_artifact(artifact_store)
        return false unless validate_resolve_request

        send_resolve_request(transport)

        return false unless parse_artifact_response
        return false unless validate_artifact_response
        return false unless validate_inner_response

        @response
      end

      def create_resolve_xml
        return @resolve_xml unless @resolve_xml.nil?

        @resolve_document = XMLSecurity::Document.new
        @resolve_document.uuid = request_id
        @resolve_document.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

        root = @resolve_document.add_element(
          "samlp:ArtifactResolve",
          {
            "xmlns:samlp" => PROTOCOL,
            "xmlns:saml" => ASSERTION
          }
        )
        root.attributes["ID"] = request_id
        root.attributes["Version"] = "2.0"
        root.attributes["IssueInstant"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        root.attributes["Destination"] = endpoint[:location]

        issuer = root.add_element("saml:Issuer")
        issuer.text = settings.sp_entity_id

        artifact_element = root.add_element("samlp:Artifact")
        artifact_element.text = artifact

        sign_resolve_document

        @resolve_xml = "".dup
        @resolve_document.write(@resolve_xml)
        @resolve_xml
      end

      def create_soap_request
        return @soap_request unless @soap_request.nil?

        @soap_request = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
          "<soap11:Envelope xmlns:soap11=\"#{SOAP_11}\"><soap11:Body>" +
          create_resolve_xml +
          "</soap11:Body></soap11:Envelope>"
      end

      def request
        create_soap_request
      end

      private

      def validate_state(transport, artifact_store)
        append_error("Blank artifact") if artifact.nil? || artifact.empty?
        append_error("No settings on artifact") if settings.nil?
        append_error("No IdP entity id on settings") if settings && (settings.idp_entity_id.nil? || settings.idp_entity_id.empty?)
        append_error("No SP entity id on settings") if settings && (settings.sp_entity_id.nil? || settings.sp_entity_id.empty?)
        append_error("No transport on artifact") unless invokable?(transport)
        append_error("No artifact store on artifact") unless invokable?(artifact_store, :consume)

        if settings && settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil? && settings.idp_cert_multi.nil?
          append_error("No fingerprint or certificate on settings")
        end

        @errors.empty?
      end

      def parse_artifact
        if artifact !~ /\A[A-Za-z0-9+\/]+=*\z/ || artifact.length != ARTIFACT_ENCODED_LENGTH
          return append_error("Invalid SAML artifact format")
        end

        begin
          decoded = Base64.strict_decode64(artifact)
        rescue ArgumentError
          return append_error("Invalid SAML artifact encoding")
        end

        if decoded.bytesize != ARTIFACT_DECODED_LENGTH
          return append_error("Invalid decoded SAML artifact length")
        end

        @decoded_artifact = decoded
        @endpoint_index = decoded[2..3].unpack("n")[0]
        @source_id = decoded[4..23]
        @message_handle = decoded[24..43]
        true
      end

      def validate_artifact
        unless @decoded_artifact[0..1] == ARTIFACT_TYPE_CODE
          return append_error("Unsupported SAML artifact type code")
        end

        expected_source_id = Digest::SHA1.digest(settings.idp_entity_id)
        unless secure_compare(source_id, expected_source_id)
          return append_error("Artifact SourceID does not match the IdP entity id")
        end

        true
      end

      def resolve_endpoint
        services = settings.idp_artifact_resolution_services
        if services.nil?
          index = settings.idp_artifact_resolution_service_index.nil? ? 0 : settings.idp_artifact_resolution_service_index
          url = settings.idp_artifact_resolution_service_url
          binding = settings.idp_artifact_resolution_service_binding
          return append_error("No Artifact Resolution Service on settings") if url.nil? || url.to_s.empty?
          return append_error("ArtifactResolutionService binding must be SOAP") unless binding == Utils::BINDINGS[:soap]
          return append_error("Artifact endpoint index does not match settings") unless endpoint_index == index

          @endpoint = { :binding => binding, :location => url, :index => index }
          return true
        end

        @endpoint = services.detect do |service|
          service[:binding] == Utils::BINDINGS[:soap] && service[:index] == endpoint_index
        end

        return append_error("No Artifact Resolution Service in metadata for endpoint index #{endpoint_index}") if endpoint.nil?

        true
      end

      def consume_artifact(artifact_store)
        if invoke(artifact_store, :consume, artifact) == false
          append_error("SAML artifact has already been consumed")
        else
          true
        end
      end

      def send_resolve_request(transport)
        soap_request = create_soap_request
        params = {
          :headers => {
            "Content-Type" => "text/xml; charset=utf-8",
            "SOAPAction" => "http://www.oasis-open.org/committees/security"
          }
        }
        @soap_response = invoke(transport, :post, endpoint[:location], soap_request, params)
      end

      def parse_artifact_response
        return append_error("Blank ArtifactResponse") if @soap_response.nil? || @soap_response.to_s.empty?

        if @soap_response.to_s.bytesize > settings.message_max_bytesize
          return append_error("SOAP Message exceeds #{settings.message_max_bytesize} bytes, so was rejected")
        end

        begin
          soap_document = Nokogiri::XML(@soap_response.to_s) do |config|
            config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
          end
          raise StandardError.new(soap_document.errors.join(", ")) unless soap_document.errors.empty?
          raise StandardError.new("Dangerous XML detected. No Doctype nodes allowed") if soap_document.internal_subset
        rescue StandardError => error
          return append_error("XML load failed: #{error.message}")
        end

        if soap_document.at_xpath("//soap:Envelope/soap:Body/*[local-name()='Fault']", "soap" => SOAP_11) ||
           soap_document.at_xpath("//soap:Envelope/soap:Body/*[local-name()='Fault']", "soap" => SOAP_12)
          return append_error("SOAP Fault returned by Artifact Resolution Service")
        end

        artifact_responses = soap_document.xpath("//*[local-name()='ArtifactResponse' and namespace-uri()='#{PROTOCOL}']")
        return append_error("ArtifactResponse must contain 1 response message") unless artifact_responses.length == 1

        artifact_response_node = artifact_responses.first
        parent = artifact_response_node.parent
        return append_error("Missing ArtifactResponse in SOAP body") unless parent && parent.name == "Body" && [SOAP_11, SOAP_12].include?(parent.namespace.href)
        return append_error("Missing ArtifactResponse in SOAP envelope") unless parent.parent && parent.parent.name == "Envelope" && [SOAP_11, SOAP_12].include?(parent.parent.namespace.href)

        @artifact_response_xml = xml_element_raw(@soap_response.to_s, "ArtifactResponse", artifact_response_node.attribute("ID").value)
        return append_error("Invalid ArtifactResponse XML") if @artifact_response_xml.nil?
        @document = XMLSecurity::SignedDocument.new(@artifact_response_xml, @errors)
        @artifact_response = REXML::XPath.first(document, "/p:ArtifactResponse", { "p" => PROTOCOL })
        return append_error("Invalid ArtifactResponse root") if @artifact_response.nil?
        true
      end

      def validate_artifact_response
        return false unless validate_structure

        unless artifact_response.attributes["ID"] && artifact_response.attributes["Version"] == "2.0"
          return append_error("Invalid ArtifactResponse ID or Version")
        end

        unless artifact_response.attributes["InResponseTo"] == request_id
          return append_error("The InResponseTo of the ArtifactResponse does not match the ArtifactResolve")
        end

        unless element_text(first_child("Issuer")) == settings.idp_entity_id
          return append_error("The Issuer of the ArtifactResponse does not match the IdP entity id")
        end

        return append_error("The status code of the ArtifactResponse was not Success") unless outer_success?

        signature_nodes = REXML::XPath.match(artifact_response, "./ds:Signature", { "ds" => XMLSecurity::BaseDocument::DSIG })
        return append_error("The ArtifactResponse is not signed") unless signature_nodes.length == 1

        validate_with_settings(document) ? true : append_error("Invalid Signature on ArtifactResponse")
      end

      def validate_structure
        begin
          xml = XMLSecurity::BaseDocument.safe_load_xml(document, check_malformed_doc_enabled?)
        rescue StandardError => error
          return append_error("XML load failed: #{error.message}")
        end

        schema_errors = SamlMessage.schema.validate(xml)
        schema_errors.each do |schema_error|
          return append_error("Invalid ArtifactResponse. Not match the saml-schema-protocol-2.0.xsd: #{schema_error.message}")
        end

        true
      end

      def validate_inner_response
        inner_node = REXML::XPath.first(artifact_response, "./p:Response", { "p" => PROTOCOL })
        return append_error("ArtifactResponse must contain a SAML Response") if inner_node.nil?

        inner_id = inner_node.attributes["ID"]
        return append_error("Missing ID attribute on SAML Response") if inner_id.nil?

        inner_xml = xml_element_raw(@artifact_response_xml, "Response", inner_id)
        return append_error("ArtifactResponse must contain a SAML Response") if inner_xml.nil?
        response_options = options.dup
        response_options[:settings] = settings
        response_options[:matches_request_id] = options[:matches_request_id] unless options[:matches_request_id].nil?
        response_options[:skip_destination] = true if options[:skip_destination]

        @response = Response.new(inner_xml, response_options)
        inner_valid = response.is_valid?
        if inner_valid
          true
        else
          inner_errors = response.errors.dup
          @response = nil
          inner_errors.each { |error_message| @errors << error_message unless @errors.include?(error_message) }
          false
        end
      end

      def outer_success?
        status_code = REXML::XPath.first(
          artifact_response,
          "./p:Status/p:StatusCode/@Value",
          { "p" => PROTOCOL }
        )
        status_code && status_code.value == "urn:oasis:names:tc:SAML:2.0:status:Success"
      end

      def xml_element_raw(raw_xml, tag_name, id)
        start_index = raw_xml.index(/<([a-zA-Z][\w.-]*:)?#{Regexp.escape(tag_name)}\s[^>]*ID=["']#{Regexp.escape(id)}["'][^>]*>/m)
        return if start_index.nil?

        end_index = raw_xml.index(%r{</([a-zA-Z][\w.-]*:)?#{Regexp.escape(tag_name)}>}, start_index)
        return if end_index.nil?

        closing_index = end_index + raw_xml[end_index..-1].index(">")
        raw_xml[start_index, closing_index - start_index + 1]
      end

      def sign_resolve_document
        cert, private_key = settings.get_sp_signing_pair
        return unless settings.security[:artifact_requests_signed] && private_key && cert

        @resolve_document.sign_document(
          private_key,
          cert,
          settings.security[:signature_method],
          settings.security[:digest_method]
        )
      end

      def validate_resolve_request
        xml = XMLSecurity::BaseDocument.safe_load_xml(create_resolve_xml, check_malformed_doc_enabled?)
        SamlMessage.schema.validate(xml).each do |schema_error|
          return append_error("Invalid ArtifactResolve. Not match the saml-schema-protocol-2.0.xsd: #{schema_error.message}")
        end
        true
      rescue StandardError => error
        append_error("XML load failed: #{error.message}")
      end

      def validate_with_settings(signed_document)
        signed_document.cache_referenced_xml(true, check_malformed_doc_enabled?, "ArtifactResponse") unless signed_document.processed
        embedded_cert = embedded_certificate(signed_document)
        idp_certs = settings.get_idp_cert_multi
        if embedded_cert && idp_certs && !idp_certs[:signing].empty?
          idp_certs[:signing].any? do |idp_cert|
            cert_matches = idp_cert.to_pem == embedded_cert.to_pem
            valid = signed_document.validate_document_with_cert(idp_cert, true)
            cert_matches && valid && idp_cert_active?(idp_cert)
          end
        elsif embedded_cert
          configured_cert = settings.get_idp_cert
          configured_fingerprint = settings.get_fingerprint
          embedded_fingerprint = Digest::SHA1.hexdigest(embedded_cert.to_der).downcase.gsub(/[^a-z0-9]/, "")

          trusted = (configured_cert && configured_cert.to_pem == embedded_cert.to_pem) ||
                    (configured_fingerprint && configured_fingerprint.gsub(/[^a-zA-Z0-9]/, "").downcase == embedded_fingerprint)
          trusted && signed_document.validate_document_with_cert(embedded_cert, true) && idp_cert_active?(embedded_cert)
        elsif idp_certs.nil? || idp_certs[:signing].empty?
          fingerprint = settings.get_fingerprint
          result = signed_document.validate_document(
            fingerprint,
            true,
            :fingerprint_alg => settings.idp_cert_fingerprint_algorithm,
            :cert => settings.get_idp_cert
          )
          result && idp_cert_active?(settings.get_idp_cert)
        else
          append_error("Certificate element missing in ArtifactResponse")
          false
        end
      end

      def idp_cert_active?(cert)
        return true unless settings.security[:check_idp_cert_expiration] && cert

        !OneLogin::RubySaml::Utils.is_cert_expired(cert)
      end

      def embedded_certificate(signed_document)
        cert_element = REXML::XPath.first(
          signed_document,
          "/p:ArtifactResponse/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
          { "p" => PROTOCOL, "ds" => XMLSecurity::BaseDocument::DSIG }
        )
        return unless cert_element

        OpenSSL::X509::Certificate.new(Base64.decode64(OneLogin::RubySaml::Utils.element_text(cert_element)))
      rescue OpenSSL::X509::CertificateError
        nil
      end

      def first_child(name)
        REXML::XPath.first(artifact_response, "./a:#{name}", { "a" => ASSERTION })
      end

      def element_text(node)
        OneLogin::RubySaml::Utils.element_text(node)
      end

      def check_malformed_doc_enabled?
        check_malformed_doc?(settings)
      end

      def invokable?(object, method_name = :call)
        object.respond_to?(:call) || object.respond_to?(method_name)
      end

      def invoke(object, method_name, *args)
        if object.respond_to?(method_name)
          object.send(method_name, *args)
        else
          object.call(*args)
        end
      end

      def secure_compare(first, second)
        return false unless first.bytesize == second.bytesize

        result = 0
        first.bytes.zip(second.bytes) { |left, right| result |= left ^ right }
        result == 0
      end
    end
  end
end
