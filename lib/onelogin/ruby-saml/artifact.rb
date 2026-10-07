require 'base64'
require 'digest/sha1'

require "onelogin/ruby-saml/validation_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 HTTP Artifact (Parser)
    #
    # Parses the SAMLart parameter sent by the IdP on the SP callback when
    # the HTTP Artifact binding is used. Only the type 0x0004 artifact format
    # is supported:
    #
    #   TypeCode      2 bytes (0x0004)
    #   EndpointIndex 2 bytes (index of the IdP ArtifactResolutionService
    #                 endpoint, as published on the trusted IdP metadata)
    #   SourceID      20 bytes (SHA-1 of the IdP entityID)
    #   MessageHandle remaining bytes (opaque reference to the SAML message
    #                 stored at the IdP)
    #
    # The artifact is an opaque token: it never carries the resolution URL
    # nor the message itself.
    #
    class Artifact
      TYPE_CODE = 0x0004
      SOURCE_ID_SIZE = 20
      HEADER_SIZE = 2 + 2 + SOURCE_ID_SIZE

      attr_reader :type_code
      attr_reader :endpoint_index
      attr_reader :source_id
      attr_reader :message_handle

      def initialize(type_code, endpoint_index, source_id, message_handle)
        @type_code = type_code
        @endpoint_index = endpoint_index
        @source_id = source_id
        @message_handle = message_handle
      end

      # Parses a SAMLart parameter value.
      # @param samlart [String] The base64 encoded artifact received on the callback
      # @return [OneLogin::RubySaml::Artifact] The parsed artifact
      # @raise [ValidationError] If the artifact is malformed or has an unsupported type
      #
      def self.parse(samlart)
        raise ValidationError.new("Blank artifact") if samlart.nil? || samlart.empty?

        decoded = decode(samlart)

        if decoded.bytesize <= HEADER_SIZE
          raise ValidationError.new("Invalid artifact: truncated content")
        end

        type_code, endpoint_index = decoded.unpack("nn")
        unless type_code == TYPE_CODE
          raise ValidationError.new("Unsupported artifact type: 0x#{type_code.to_s(16).rjust(4, '0')}")
        end

        source_id = decoded.byteslice(4, SOURCE_ID_SIZE)
        message_handle = decoded.byteslice(HEADER_SIZE..-1)

        new(type_code, endpoint_index, source_id, message_handle)
      end

      # Builds a raw type 0x0004 artifact. Auxiliary method mostly useful on
      # tests and on tools that emulate an IdP.
      # @param source_id [String] The 20 bytes SourceID (usually the SHA-1 of the IdP entityID)
      # @param message_handle [String] The opaque message handle
      # @param endpoint_index [Integer] The index of the IdP ArtifactResolutionService endpoint
      # @return [String] The raw artifact
      #
      def self.build(source_id, message_handle, endpoint_index = 0)
        [TYPE_CODE, endpoint_index].pack("nn") + source_id + message_handle
      end

      # Encodes a raw artifact as a SAMLart parameter value
      # @param raw_artifact [String] The raw artifact
      # @return [String] The base64 encoded artifact
      #
      def self.encode(raw_artifact)
        Base64.strict_encode64(raw_artifact)
      end

      # Checks that the SourceID of the artifact corresponds to the SHA-1
      # of the given (trusted) IdP entityID.
      # @param entity_id [String] The trusted IdP entityID
      # @return [Boolean] True if the SourceID matches
      #
      def source_id_matches?(entity_id)
        return false if entity_id.nil? || entity_id.empty?

        Digest::SHA1.digest(entity_id) == source_id
      end

      # @return [String] An hex representation of the MessageHandle,
      #   suitable to be used as a key on artifact stores
      #
      def message_handle_key
        message_handle.unpack1("H*")
      end

      # Decodes a SAMLart parameter value. Standard base64 is expected,
      # base64url is tolerated.
      # @param samlart [String] The encoded artifact
      # @return [String] The raw artifact
      # @raise [ValidationError] If the value is not base64 encoded
      #
      def self.decode(samlart)
        Base64.strict_decode64(samlart)
      rescue ArgumentError
        begin
          Base64.urlsafe_decode64(samlart)
        rescue ArgumentError
          raise ValidationError.new("Invalid artifact: not a base64 encoded value")
        end
      end
      private_class_method :decode
    end
  end
end
