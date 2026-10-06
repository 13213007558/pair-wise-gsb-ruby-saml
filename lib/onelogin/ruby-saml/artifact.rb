require "base64"
require "digest/sha1"

require "onelogin/ruby-saml/validation_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 Artifact. Parses a SAML artifact (SAMLart) as defined by the
    # SAML 2.0 HTTP-Artifact binding (SAMLBind 3.6). Only the SAML 2.0
    # artifact format (type code 0x0004) is supported.
    #
    class Artifact
      # SAML 2.0 artifact type code
      SUPPORTED_TYPE_CODE = 0x0004

      # Size in bytes of a type 0x0004 artifact:
      #   2 bytes  TypeCode
      #   2 bytes  EndpointIndex
      #   20 bytes SourceID (SHA-1 of the IdP entityID)
      #   20 bytes MessageHandle
      ARTIFACT_LENGTH = 44

      SOURCE_ID_LENGTH = 20

      MESSAGE_HANDLE_LENGTH = 20

      attr_reader :raw, :type_code, :endpoint_index, :source_id, :message_handle

      # Parses a SAMLart value.
      # @param artifact [String] The base64 encoded artifact received on the SAMLart parameter
      # @return [OneLogin::RubySaml::Artifact]
      # @raise [ValidationError] if the artifact is malformed or of an unsupported type
      #
      def self.parse(artifact)
        new(artifact)
      end

      def initialize(artifact)
        raise ArgumentError.new("Artifact cannot be nil") if artifact.nil?

        @raw = artifact
        decoded = decode(artifact)

        unless decoded.bytesize == ARTIFACT_LENGTH
          raise ValidationError.new("Invalid SAML artifact: expected #{ARTIFACT_LENGTH} bytes, got #{decoded.bytesize}")
        end

        @type_code, @endpoint_index = decoded.unpack("nn")
        unless @type_code == SUPPORTED_TYPE_CODE
          raise ValidationError.new(format("Unsupported SAML artifact type code 0x%04x", @type_code))
        end

        @source_id = decoded.byteslice(4, SOURCE_ID_LENGTH)
        @message_handle = decoded.byteslice(4 + SOURCE_ID_LENGTH, MESSAGE_HANDLE_LENGTH)
      end

      # Computes the SourceID that an artifact of the given IdP must carry.
      # @param entity_id [String] The IdP entityID
      # @return [String] The binary SHA-1 of the entityID
      #
      def self.source_id_for(entity_id)
        Digest::SHA1.digest(entity_id.to_s)
      end

      # @param entity_id [String] The IdP entityID
      # @return [Boolean] True if the artifact SourceID matches the SHA-1 of the entityID
      #
      def source_id_matches?(entity_id)
        !entity_id.nil? && !entity_id.empty? && source_id == self.class.source_id_for(entity_id)
      end

      private

      def decode(artifact)
        Base64.strict_decode64(artifact.gsub(/[\r\n\s]/, ""))
      rescue ArgumentError
        raise ValidationError.new("Invalid SAML artifact: not base64 encoded")
      end
    end
  end
end
