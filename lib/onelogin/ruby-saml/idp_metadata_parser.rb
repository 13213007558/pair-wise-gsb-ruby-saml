require "base64"
require "net/http"
require "net/https"
require "rexml/document"
require "rexml/xpath"
require "time"

# Only supports SAML 2.0
module OneLogin
  module RubySaml
    include REXML

    # Auxiliary class to retrieve and parse the Identity Provider Metadata
    #
    # This class does not validate in any way the URL that is introduced,
    # make sure to validate it properly before use it in a parse_remote method.
    # Read the `Security warning` section of the README.md file to get more info
    #
    class IdpMetadataParser

      module SamlMetadata
        module Vocabulary
          METADATA       = "urn:oasis:names:tc:SAML:2.0:metadata".freeze
          DSIG           = "http://www.w3.org/2000/09/xmldsig#".freeze
          NAME_FORMAT    = "urn:oasis:names:tc:SAML:2.0:attrname-format:*".freeze
          SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
        end

        NAMESPACE = {
          "md" => Vocabulary::METADATA,
          "NameFormat" => Vocabulary::NAME_FORMAT,
          "saml" => Vocabulary::SAML_ASSERTION,
          "ds" => Vocabulary::DSIG
        }.freeze
      end

      include SamlMetadata::Vocabulary
      attr_reader :document
      attr_reader :response
      attr_reader :options

      # fetch IdP descriptors from a metadata document
      def self.get_idps(metadata_document, only_entity_id=nil)
        path = "//md:EntityDescriptor#{only_entity_id && '[@entityID="' + only_entity_id + '"]'}/md:IDPSSODescriptor"
        REXML::XPath.match(
          metadata_document,
          path,
          SamlMetadata::NAMESPACE
        )
      end

      # fetch entity descriptors from a metadata document, including the
      # ones nested inside md:EntitiesDescriptor aggregates
      def self.get_entity_descriptors(metadata_document, only_entity_id=nil)
        path = "//md:EntityDescriptor#{only_entity_id && '[@entityID="' + only_entity_id + '"]'}"
        REXML::XPath.match(
          metadata_document,
          path,
          SamlMetadata::NAMESPACE
        )
      end

      # Parse the Identity Provider metadata and update the settings with the
      # IdP values
      #
      # @param url [String] Url where the XML of the Identity Provider Metadata is published.
      # @param validate_cert [Boolean] If true and the URL is HTTPS, the cert of the domain is checked.
      #
      # @param options [Hash] options used for parsing the metadata and the returned Settings instance
      # @option options [OneLogin::RubySaml::Settings, Hash] :settings the OneLogin::RubySaml::Settings object which gets the parsed metadata merged into or an hash for Settings overrides.
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When omitted, the first entity descriptor is used.
      # @option options [String, Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :name_id_format an ordered list of NameIDFormats to detect a desired value. The first NameIDFormat in the list that is included in the metadata will be used.
      # @option options [Boolean] :validate_signature when true, the XML signature of the metadata document (the signature of the root element of a trusted aggregate) is verified before parsing. Requires :signature_cert.
      # @option options [String, OpenSSL::X509::Certificate, nil] :signature_cert the certificate of the metadata signer used when :validate_signature is enabled.
      #
      # @return [OneLogin::RubySaml::Settings]
      #
      # @raise [HttpError] Failure to fetch remote IdP metadata
      def parse_remote(url, validate_cert = true, options = {})
        idp_metadata = get_idp_metadata(url, validate_cert)
        parse(idp_metadata, options)
      end

      # Parse the Identity Provider metadata and return the results as Hash
      #
      # @param url [String] Url where the XML of the Identity Provider Metadata is published.
      # @param validate_cert [Boolean] If true and the URL is HTTPS, the cert of the domain is checked.
      #
      # @param options [Hash] options used for parsing the metadata
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When omitted, the first entity descriptor is used.
      # @option options [String, Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :name_id_format an ordered list of NameIDFormats to detect a desired value. The first NameIDFormat in the list that is included in the metadata will be used.
      #
      # @return [Hash]
      #
      # @raise [HttpError] Failure to fetch remote IdP metadata
      def parse_remote_to_hash(url, validate_cert = true, options = {})
        parse_remote_to_array(url, validate_cert, options)[0]
      end

      # Parse all Identity Provider metadata and return the results as Array
      #
      # @param url [String] Url where the XML of the Identity Provider Metadata is published.
      # @param validate_cert [Boolean] If true and the URL is HTTPS, the cert of the domain is checked.
      #
      # @param options [Hash] options used for parsing the metadata
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When omitted, all found IdPs are returned.
      # @option options [String, Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :name_id_format an ordered list of NameIDFormats to detect a desired value. The first NameIDFormat in the list that is included in the metadata will be used.
      #
      # @return [Array<Hash>]
      #
      # @raise [HttpError] Failure to fetch remote IdP metadata
      def parse_remote_to_array(url, validate_cert = true, options = {})
        idp_metadata = get_idp_metadata(url, validate_cert)
        parse_to_array(idp_metadata, options)
      end

      # Parse the Identity Provider metadata and update the settings with the IdP values
      #
      # @param idp_metadata [String]
      #
      # @param options [Hash] :settings to provide the OneLogin::RubySaml::Settings object or an hash for Settings overrides
      # @option options [OneLogin::RubySaml::Settings, Hash] :settings the OneLogin::RubySaml::Settings object which gets the parsed metadata merged into or an hash for Settings overrides.
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When omitted, the first entity descriptor is used.
      # @option options [String, Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :name_id_format an ordered list of NameIDFormats to detect a desired value. The first NameIDFormat in the list that is included in the metadata will be used.
      # @option options [Boolean] :validate_signature when true, the XML signature of the metadata document (the signature of the root element of a trusted aggregate) is verified before parsing. Requires :signature_cert.
      # @option options [String, OpenSSL::X509::Certificate, nil] :signature_cert the certificate of the metadata signer used when :validate_signature is enabled.
      #
      # @return [OneLogin::RubySaml::Settings]
      def parse(idp_metadata, options = {})
        parsed_metadata = parse_to_hash(idp_metadata, options)

        unless parsed_metadata[:cache_duration].nil?
          cache_valid_until_timestamp = OneLogin::RubySaml::Utils.parse_duration(parsed_metadata[:cache_duration])
          unless cache_valid_until_timestamp.nil?
            if parsed_metadata[:valid_until].nil? || cache_valid_until_timestamp < Time.parse(parsed_metadata[:valid_until], Time.now.utc).to_i
              parsed_metadata[:valid_until] = Time.at(cache_valid_until_timestamp).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            end
          end
        end
        # Remove the cache_duration because on the settings
        # we only going to suppot valid_until 
        parsed_metadata.delete(:cache_duration)

        settings = options[:settings]

        if settings.nil?
          OneLogin::RubySaml::Settings.new(parsed_metadata)
        elsif settings.is_a?(Hash)
          OneLogin::RubySaml::Settings.new(settings.merge(parsed_metadata))
        else
          merge_parsed_metadata_into(settings, parsed_metadata)
        end
      end

      # Parse the Identity Provider metadata and return the results as Hash
      #
      # @param idp_metadata [String]
      #
      # @param options [Hash] options used for parsing the metadata and the returned Settings instance
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When omitted, the first entity descriptor is used.
      # @option options [String, Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :name_id_format an ordered list of NameIDFormats to detect a desired value. The first NameIDFormat in the list that is included in the metadata will be used.
      #
      # @return [Hash]
      def parse_to_hash(idp_metadata, options = {})
        parse_to_array(idp_metadata, options)[0]
      end

      # Parse all Identity Provider metadata and return the results as Array
      #
      # @param idp_metadata [String]
      #
      # @param options [Hash] options used for parsing the metadata and the returned Settings instance
      # @option options [String, nil] :entity_id when this is given, the entity descriptor for this ID is used. When omitted, all found IdPs are returned.
      # @option options [String, Array<String>, nil] :sso_binding an ordered list of bindings to detect the single signon URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :slo_binding an ordered list of bindings to detect the single logout URL. The first binding in the list that is included in the metadata will be used.
      # @option options [String, Array<String>, nil] :name_id_format an ordered list of NameIDFormats to detect a desired value. The first NameIDFormat in the list that is included in the metadata will be used.
      #
      # @option options [Boolean] :validate_signature when true, the XML signature of the metadata document (the signature of the root element of a trusted aggregate) is verified before parsing. Requires :signature_cert.
      # @option options [String, OpenSSL::X509::Certificate, nil] :signature_cert the certificate of the metadata signer used when :validate_signature is enabled.
      #
      # @return [Array<Hash>]
      def parse_to_array(idp_metadata, options = {})
        parse_to_idp_metadata_array(idp_metadata, options).map { |idp_md| idp_md.to_hash(options) }
      end

      # Select the entity descriptors holding an IDPSSODescriptor role from
      # the metadata document, including the entities nested inside
      # md:EntitiesDescriptor aggregates, and wrap them as IdpMetadata.
      #
      # The effective validity (validUntil / cacheDuration) of each entity is
      # constrained by its own descriptor and by every ancestor descriptor of
      # the aggregate; the earliest expiration applies.
      #
      # @raise [ArgumentError] when no IDPSSODescriptor role is found, or when
      #   several EntityDescriptor elements with the same entityID define the
      #   role in conflicting ways (all source locations are reported).
      # @raise [OneLogin::RubySaml::ValidationError] when :validate_signature
      #   is enabled and the signature of the metadata document is not valid.
      #
      # @return [Array<IdpMetadata>]
      def parse_to_idp_metadata_array(idp_metadata, options = {})
        @document = REXML::Document.new(idp_metadata)
        @options = options

        validate_metadata_signature(idp_metadata, options) if options[:validate_signature]

        entity_descriptors = self.class.get_entity_descriptors(@document, options[:entity_id]).select do |entity_descriptor|
          !idpsso_descriptor(entity_descriptor).nil?
        end
        if entity_descriptors.empty?
          raise ArgumentError.new("idp_metadata must contain an IDPSSODescriptor element")
        end

        resolve_entity_descriptor_conflicts(entity_descriptors).map do |entity_descriptor|
          IdpMetadata.new(idpsso_descriptor(entity_descriptor), entity_descriptor.attributes["entityID"])
        end
      end

      # Retrieve the remote IdP metadata from the URL or a cached copy.
      # @param url [String] Url where the XML of the Identity Provider Metadata is published.
      # @param validate_cert [Boolean] If true and the URL is HTTPS, the cert of the domain is checked.
      # @return [REXML::document] Parsed XML IdP metadata
      # @raise [HttpError] Failure to fetch remote IdP metadata
      def get_idp_metadata(url, validate_cert)
        uri = URI.parse(url)
        raise ArgumentError.new("url must begin with http or https") unless /^https?/ =~ uri.scheme
        http = Net::HTTP.new(uri.host, uri.port)

        if uri.scheme == "https"
          http.use_ssl = true
          # Most IdPs will probably use self signed certs
          http.verify_mode = validate_cert ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

          # Net::HTTP in Ruby 1.8 did not set the default certificate store
          # automatically when VERIFY_PEER was specified.
          if RUBY_VERSION < '1.9' && !http.ca_file && !http.ca_path && !http.cert_store
            http.cert_store = OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE
          end
        end

        get = Net::HTTP::Get.new(uri.request_uri)
        get.basic_auth uri.user, uri.password if uri.user
        @response = http.request(get)
        return response.body if response.is_a? Net::HTTPSuccess

        raise OneLogin::RubySaml::HttpError.new(
          "Failed to fetch idp metadata: #{response.code}: #{response.message}"
        )
      end

      private

      # Validate the signature of the whole metadata document. On an
      # aggregate file the signature of the root (Entities)Descriptor covers
      # every nested entity, so a single check is enough to trust the
      # document; the selected role is still checked afterwards for
      # certificate use and endpoint bindings.
      #
      # @param idp_metadata [String] The metadata document
      # @param options [Hash] options used for parsing the metadata
      # @option options [String, OpenSSL::X509::Certificate] :signature_cert the trusted certificate of the metadata signer
      #
      # @raise [ArgumentError] If no :signature_cert option is provided
      # @raise [ValidationError] If the signature of the metadata is not valid
      def validate_metadata_signature(idp_metadata, options)
        cert = options[:signature_cert]
        if cert.nil?
          raise ArgumentError.new("a :signature_cert option is required when :validate_signature is enabled")
        end
        cert = OpenSSL::X509::Certificate.new(cert) if cert.is_a?(String)

        signed_document = XMLSecurity::SignedDocument.new(idp_metadata)
        unless signed_document.validate_document_with_cert(cert, false)
          raise OneLogin::RubySaml::ValidationError.new("Metadata signature validation failed")
        end
      end

      # @return [REXML::Element, nil] the IDPSSODescriptor role of the entity descriptor
      def idpsso_descriptor(entity_descriptor)
        REXML::XPath.first(entity_descriptor, "md:IDPSSODescriptor", SamlMetadata::NAMESPACE)
      end

      # Reject conflicting duplicate definitions of the same entityID,
      # reporting every source location instead of silently keeping the
      # first one. Identical duplicates are collapsed.
      #
      # @return [Array<REXML::Element>] the entity descriptors to parse
      # @raise [ArgumentError] If conflicting definitions of an entityID exist
      def resolve_entity_descriptor_conflicts(entity_descriptors)
        entity_descriptors.group_by { |ed| ed.attributes["entityID"] }.flat_map do |entity_id, descriptors|
          next descriptors if descriptors.size == 1

          roles = descriptors.map { |ed| normalized_descriptor(idpsso_descriptor(ed)) }
          if roles.uniq.size == 1
            [descriptors.first]
          else
            locations = descriptors.map { |ed| element_location(ed) }
            raise ArgumentError.new(
              "Multiple conflicting EntityDescriptor definitions for entityID \"#{entity_id}\" found at: #{locations.join(', ')}"
            )
          end
        end
      end

      # Serialized form of a descriptor, normalized so that insignificant
      # whitespace does not produce false conflicts between duplicates.
      #
      # @return [String]
      def normalized_descriptor(element)
        element.to_s.gsub(/>\s+</, "><").strip
      end

      # @return [String] the path of the element within the document,
      #   e.g. /md:EntitiesDescriptor/md:EntitiesDescriptor[1]/md:EntityDescriptor[2]
      def element_location(element)
        segments = []
        current = element
        while current.is_a?(REXML::Element) && !current.is_a?(REXML::Document)
          parent = current.parent
          if parent.is_a?(REXML::Element) && !parent.is_a?(REXML::Document)
            same_name = parent.elements.select { |sibling| sibling.expanded_name == current.expanded_name }
            segments.unshift("#{current.expanded_name}[#{same_name.index(current) + 1}]")
          else
            segments.unshift(current.expanded_name)
          end
          current = parent
        end
        "/#{segments.join('/')}"
      end

      class IdpMetadata
        attr_reader :idpsso_descriptor, :entity_id

        def initialize(idpsso_descriptor, entity_id)
          @idpsso_descriptor = idpsso_descriptor
          @entity_id = entity_id
        end

        def to_hash(options = {})
          sso_binding = options[:sso_binding]
          slo_binding = options[:slo_binding]
          {
            :idp_entity_id => @entity_id,
            :name_identifier_format => idp_name_id_format(options[:name_id_format]),
            :idp_sso_service_url => single_signon_service_url(sso_binding),
            :idp_sso_service_binding => single_signon_service_binding(sso_binding),
            :idp_slo_service_url => single_logout_service_url(slo_binding),
            :idp_slo_service_binding => single_logout_service_binding(slo_binding),
            :idp_slo_response_service_url => single_logout_response_service_url(slo_binding),
            :idp_attribute_names => attribute_names,
            :idp_cert => nil,
            :idp_cert_fingerprint => nil,
            :idp_cert_multi => nil,
            :valid_until => valid_until,
            :cache_duration => cache_duration,
          }.tap do |response_hash|
            merge_certificates_into(response_hash) unless certificates.nil?
          end
        end

        # Effective 'validUntil' of the entity: the constraints of the
        # entity descriptor and of every ancestor (Entities)Descriptor of a
        # nested aggregate all apply, so the earliest expiration wins.
        #
        # @return [String|nil] 'validUntil' attribute of metadata
        #
        def valid_until
          earliest_validity_constraint('validUntil') { |raw| safe_parse_time(raw) }
        end

        # Effective 'cacheDuration' of the entity: like 'validUntil', the
        # ancestor chain of a nested aggregate is taken into account and the
        # constraint that expires first wins.
        #
        # @return [String|nil] 'cacheDuration' attribute of metadata
        #
        def cache_duration
          earliest_validity_constraint('cacheDuration') { |raw| safe_parse_duration(raw) }
        end

        # @param name_id_priority [String|Array<String>] The prioritized list of NameIDFormat values to select. Will select first value if nil.
        # @return [String|nil] IdP NameIDFormat value if exists
        #
        def idp_name_id_format(name_id_priority = nil)
          nodes = REXML::XPath.match(
            @idpsso_descriptor,
            "md:NameIDFormat",
            SamlMetadata::NAMESPACE
          )
          first_ranked_text(nodes, name_id_priority)
        end

        # @param binding_priority [String|Array<String>] The prioritized list of Binding values to select. Will select first value if nil.
        # @return [String|nil] SingleSignOnService binding if exists
        #
        def single_signon_service_binding(binding_priority = nil)
          nodes = REXML::XPath.match(
            @idpsso_descriptor,
            "md:SingleSignOnService/@Binding",
            SamlMetadata::NAMESPACE
          )
          first_ranked_value(nodes, binding_priority)
        end

        # @param binding_priority [String|Array<String>] The prioritized list of Binding values to select. Will select first value if nil.
        # @return [String|nil] SingleLogoutService binding if exists
        #
        def single_logout_service_binding(binding_priority = nil)
          nodes = REXML::XPath.match(
            @idpsso_descriptor,
            "md:SingleLogoutService/@Binding",
            SamlMetadata::NAMESPACE
          )
          first_ranked_value(nodes, binding_priority)
        end

        # @param binding_priority [String|Array<String>] The prioritized list of Binding values to select. Will select first value if nil.
        # @return [String|nil] SingleSignOnService endpoint if exists
        #
        def single_signon_service_url(binding_priority = nil)
          binding = single_signon_service_binding(binding_priority)
          return if binding.nil?

          node = REXML::XPath.first(
            @idpsso_descriptor,
            "md:SingleSignOnService[@Binding=\"#{binding}\"]/@Location",
            SamlMetadata::NAMESPACE
          )
          node.value if node
        end

        # @param binding_priority [String|Array<String>] The prioritized list of Binding values to select. Will select first value if nil.
        # @return [String|nil] SingleLogoutService endpoint if exists
        #
        def single_logout_service_url(binding_priority = nil)
          binding = single_logout_service_binding(binding_priority)
          return if binding.nil?

          node = REXML::XPath.first(
            @idpsso_descriptor,
            "md:SingleLogoutService[@Binding=\"#{binding}\"]/@Location",
            SamlMetadata::NAMESPACE
          )
          node.value if node
        end

        # @param binding_priority [String|Array<String>] The prioritized list of Binding values to select. Will select first value if nil.
        # @return [String|nil] SingleLogoutService response url if exists
        #
        def single_logout_response_service_url(binding_priority = nil)
          binding = single_logout_service_binding(binding_priority)
          return if binding.nil?

          node = REXML::XPath.first(
            @idpsso_descriptor,
            "md:SingleLogoutService[@Binding=\"#{binding}\"]/@ResponseLocation",
            SamlMetadata::NAMESPACE
          )
          node.value if node
        end

        # @return [String|nil] Unformatted Certificate if exists
        #
        def certificates
          @certificates ||= begin
            signing_nodes = REXML::XPath.match(
              @idpsso_descriptor,
              "md:KeyDescriptor[not(contains(@use, 'encryption'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
              SamlMetadata::NAMESPACE
            )

            encryption_nodes = REXML::XPath.match(
              @idpsso_descriptor,
              "md:KeyDescriptor[not(contains(@use, 'signing'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
              SamlMetadata::NAMESPACE
            )

            return nil if signing_nodes.empty? && encryption_nodes.empty?

            certs = {}
            unless signing_nodes.empty?
              certs['signing'] = []
              signing_nodes.each do |cert_node|
                certs['signing'] << Utils.element_text(cert_node)
              end
            end

            unless encryption_nodes.empty?
              certs['encryption'] = []
              encryption_nodes.each do |cert_node|
                certs['encryption'] << Utils.element_text(cert_node)
              end
            end
            certs
          end
        end

        # @return [String|nil] the fingerprint of the X509Certificate if it exists
        #
        def fingerprint(certificate, fingerprint_algorithm = XMLSecurity::Document::SHA1)
          return unless certificate

          cert = OpenSSL::X509::Certificate.new(Base64.decode64(certificate))

          fingerprint_alg = XMLSecurity::BaseDocument.new.algorithm(fingerprint_algorithm).new
          fingerprint_alg.hexdigest(cert.to_der).upcase.scan(/../).join(":")
        end

        # @return [Array] the names of all SAML attributes if any exist
        #
        def attribute_names
          nodes = REXML::XPath.match(
            @idpsso_descriptor  ,
            "saml:Attribute/@Name",
            SamlMetadata::NAMESPACE
          )
          nodes.map(&:value)
        end

        def merge_certificates_into(parsed_metadata)
          if (certificates.size == 1 &&
              (certificates_has_one('signing') || certificates_has_one('encryption'))) ||
              (certificates_has_one('signing') && certificates_has_one('encryption') &&
              certificates["signing"][0] == certificates["encryption"][0])

            if certificates.key?("signing")
              parsed_metadata[:idp_cert] = certificates["signing"][0]
              parsed_metadata[:idp_cert_fingerprint] = fingerprint(
                parsed_metadata[:idp_cert],
                parsed_metadata[:idp_cert_fingerprint_algorithm]
              )
            else
              parsed_metadata[:idp_cert] = certificates["encryption"][0]
              parsed_metadata[:idp_cert_fingerprint] = fingerprint(
                parsed_metadata[:idp_cert],
                parsed_metadata[:idp_cert_fingerprint_algorithm]
              )
            end
          end

          # symbolize keys of certificates and pass it on
          parsed_metadata[:idp_cert_multi] = Hash[certificates.map { |k, v| [k.to_sym, v] }]
        end

        def certificates_has_one(key)
          certificates.key?(key) && certificates[key].size == 1
        end

        private

        # The entity descriptor of the selected role and all its ancestor
        # elements, e.g. the nested EntitiesDescriptor levels of an aggregate.
        #
        # @return [Array<REXML::Element>]
        #
        def descriptor_chain
          chain = []
          element = @idpsso_descriptor.parent
          while element.is_a?(REXML::Element)
            chain << element
            element = element.parent
          end
          chain
        end

        # Effective value of a validity constraint attribute ('validUntil'
        # or 'cacheDuration'): every descriptor of the chain may constrain
        # the validity, so the earliest expiration applies. Returns the raw
        # attribute value of the binding constraint.
        #
        # @return [String|nil]
        #
        def earliest_validity_constraint(attribute)
          constraints = descriptor_chain.map do |element|
            raw = element.attributes[attribute]
            next if raw.nil?

            timestamp = yield(raw)
            timestamp.nil? ? nil : [timestamp, raw]
          end.compact

          earliest = constraints.min_by { |timestamp, _raw| timestamp }
          earliest && earliest[1]
        end

        def safe_parse_time(raw)
          Time.parse(raw)
        rescue StandardError
          nil
        end

        def safe_parse_duration(raw)
          Utils.parse_duration(raw)
        rescue StandardError
          nil
        end

        def first_ranked_text(nodes, priority = nil)
          return unless nodes.any?

          priority = Array(priority)
          if priority.any?
            values = nodes.map(&:text)
            priority.detect { |candidate| values.include?(candidate) }
          else
            nodes.first.text
          end
        end

        def first_ranked_value(nodes, priority = nil)
          return unless nodes.any?

          priority = Array(priority)
          if priority.any?
            values = nodes.map(&:value)
            priority.detect { |candidate| values.include?(candidate) }
          else
            nodes.first.value
          end
        end
      end

      def merge_parsed_metadata_into(settings, parsed_metadata)
        parsed_metadata.each do |key, value|
          settings.send("#{key}=".to_sym, value)
        end

        settings
      end
    end
  end
end
