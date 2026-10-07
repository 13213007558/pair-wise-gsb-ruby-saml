require 'base64'
require 'digest/sha1'
require 'onelogin/ruby-saml/artifact_error'

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Represents a SAML V2.0 artifact of type 0x0004 as carried by the
    # HTTP Artifact binding in the SAMLart query parameter.
    #
    # The 44 bytes of a type 0x0004 artifact are laid out as:
    #   - TypeCode      (2 bytes, always 0x0004)
    #   - EndpointIndex (2 bytes, selects the IdP ArtifactResolutionService)
    #   - SourceID      (20 bytes, SHA-1 of the IdP entityID)
    #   - MessageHandle (20 bytes, random reference to the stored message)
    #
    # An artifact is an opaque reference: none of its parts is a URL and
    # the artifact content must never be dereferenced as one. The
    # EndpointIndex only selects a resolution endpoint among the ones
    # published in the already trusted IdP metadata.
    #
    class Artifact
      TYPE_CODE = 0x0004
      BYTE_LENGTH = 44
      SOURCE_ID_LENGTH = 20
      MESSAGE_HANDLE_LENGTH = 20

      attr_reader :endpoint_index, :source_id, :message_handle, :raw

      # Parses a base64 encoded SAMLart parameter into an Artifact.
      # @param samlart [String] The SAMLart parameter received at the
      #   Assertion Consumer Service endpoint.
      # @return [OneLogin::RubySaml::Artifact]
      # @raise [ArtifactResolutionError] if the artifact is malformed or
      #   is not a type 0x0004 artifact.
      def self.parse(samlart)
        if samlart.nil? || samlart.to_s.empty?
          raise ArtifactResolutionError.new("Missing SAMLart parameter")
        end

        raw = begin
          Base64.strict_decode64(samlart.to_s.tr('-_', '+/'))
        rescue ArgumentError
          raise ArtifactResolutionError.new("SAMLart parameter is not valid base64")
        end

        unless raw.bytesize == BYTE_LENGTH
          raise ArtifactResolutionError.new(
            "SAML artifact must be #{BYTE_LENGTH} bytes, got #{raw.bytesize}"
          )
        end

        type_code = raw.unpack1('n')
        unless type_code == TYPE_CODE
          raise ArtifactResolutionError.new(
            format("Unsupported SAML artifact type 0x%04x, expected 0x%04x", type_code, TYPE_CODE)
          )
        end

        endpoint_index = raw[2, 2].unpack1('n')
        source_id = raw[4, SOURCE_ID_LENGTH]
        message_handle = raw[4 + SOURCE_ID_LENGTH, MESSAGE_HANDLE_LENGTH]

        new(endpoint_index, source_id, message_handle, raw)
      end

      # Builds a type 0x0004 artifact from its components.
      # @return [String] The base64 encoded artifact, ready to be used as
      #   a SAMLart parameter value.
      def self.build(endpoint_index, source_id, message_handle)
        raw = [TYPE_CODE, endpoint_index].pack('n2') + source_id + message_handle
        Base64.strict_encode64(raw)
      end

      def initialize(endpoint_index, source_id, message_handle, raw)
        @endpoint_index = endpoint_index
        @source_id = source_id
        @message_handle = message_handle
        @raw = raw
      end

      # @return [String] The base64 encoded artifact.
      def to_s
        Base64.strict_encode64(raw)
      end

      # Checks the SourceID against a trusted IdP entityID. For type
      # 0x0004 artifacts the SourceID is the SHA-1 of the IdP entityID.
      # @param entity_id [String] The trusted IdP entityID.
      # @return [Boolean]
      def source_id_matches?(entity_id)
        Digest::SHA1.digest(entity_id.to_s) == source_id
      end

      # @return [String] Stable key identifying this exact artifact for
      #   the single-use artifact store.
      def cache_key
        @cache_key ||= raw.unpack1('H*')
      end
    end
  end
end
