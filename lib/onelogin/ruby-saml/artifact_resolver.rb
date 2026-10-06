require "onelogin/ruby-saml/artifact"
require "onelogin/ruby-saml/artifact_resolve"
require "onelogin/ruby-saml/artifact_response"
require "onelogin/ruby-saml/response"
require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/validation_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 HTTP-Artifact binding. Dereferences a SAML artifact (SAMLart)
    # received on the Assertion Consumer Service into the SAML Response
    # it references, by sending an ArtifactResolve message to the
    # ArtifactResolutionService endpoint published in the IdP metadata.
    #
    # The resolution endpoint is always taken from the IdP metadata
    # registered on the settings (indexed by the artifact EndpointIndex),
    # never derived from the artifact itself.
    #
    # The transport is injected: provide a :transport object that responds
    # to #call(url, body) and returns the response body of the SOAP request.
    #
    # Artifact reuse is prevented by the injected :artifact_store, which must
    # respond to #consume(artifact) and return a truthy value only the first
    # time a given artifact is seen.
    #
    class ArtifactResolver

      attr_reader :settings, :transport, :artifact_store

      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param options [Hash]
      # @option options [#call] :transport Object that performs the SOAP request.
      #   It is called as transport.call(url, soap_envelope) and must return the
      #   response body as a String.
      # @option options [#consume] :artifact_store Store used to prevent artifact
      #   reuse. consume(artifact) must return truthy the first time an artifact
      #   is presented and falsy on any later attempt.
      #
      def initialize(settings, options = {})
        raise ArgumentError.new("Settings cannot be nil") if settings.nil?

        @settings = settings
        @transport = options[:transport]
        @artifact_store = options[:artifact_store]

        unless @transport && @transport.respond_to?(:call)
          raise ArgumentError.new("A :transport responding to #call(url, body) is required to resolve SAML artifacts")
        end

        unless @artifact_store && @artifact_store.respond_to?(:consume)
          raise ArgumentError.new("An :artifact_store responding to #consume(artifact) is required to prevent SAML artifact reuse")
        end
      end

      # Resolves a SAMLart value into the SAML Response it references,
      # validating the ArtifactResponse and the enclosed Response.
      # @param samlart [String] The artifact received on the SAMLart parameter
      # @param options [Hash] Options forwarded to the inner OneLogin::RubySaml::Response,
      #   for example :matches_request_id to correlate the enclosed Response
      #   with the AuthNRequest sent by the SP.
      # @return [OneLogin::RubySaml::Response] The validated SAML Response
      # @raise [ValidationError] if the artifact, the ArtifactResponse or the
      #   enclosed Response is invalid
      #
      def resolve(samlart, options = {})
        artifact = Artifact.parse(samlart)

        unless artifact_store.consume(artifact.raw)
          raise ValidationError.new("The SAML artifact was already consumed")
        end

        validate_source_id!(artifact)
        endpoint = artifact_resolution_endpoint(artifact)

        resolve_request = ArtifactResolve.new
        envelope = resolve_request.create_soap_envelope(settings, artifact.raw)

        Logging.debug "Resolving SAML artifact at #{endpoint_url(endpoint)}"
        artifact_response_xml = transport.call(endpoint_url(endpoint), envelope)

        artifact_response = ArtifactResponse.new(
          artifact_response_xml,
          settings,
          :matches_request_id => resolve_request.request_id
        )
        unless artifact_response.is_valid?
          raise ValidationError.new("Invalid ArtifactResponse: #{artifact_response.errors.join(', ')}")
        end

        response_options = { :settings => settings }.merge(options)
        response = Response.new(artifact_response.protocol_message_xml, response_options)
        unless response.is_valid?
          raise ValidationError.new("Invalid SAML Response resolved from artifact: #{response.errors.join(', ')}")
        end

        response
      end

      private

      # The SourceID of the artifact must be the SHA-1 of the IdP entityID.
      # @raise [ValidationError] if the SourceID cannot be checked or does not match
      #
      def validate_source_id!(artifact)
        if settings.idp_entity_id.nil? || settings.idp_entity_id.empty?
          raise ValidationError.new("Cannot validate the SAML artifact SourceID: no idp_entity_id on settings")
        end

        unless artifact.source_id_matches?(settings.idp_entity_id)
          raise ValidationError.new("The SAML artifact SourceID does not match the IdP entityID")
        end
      end

      # Looks up the ArtifactResolutionService endpoint published in the IdP
      # metadata for the EndpointIndex carried by the artifact.
      # @raise [ValidationError] if no endpoint is registered for that index
      #
      def artifact_resolution_endpoint(artifact)
        endpoint = settings.artifact_resolution_service_for(artifact.endpoint_index)
        if endpoint.nil?
          raise ValidationError.new("No ArtifactResolutionService found on the IdP metadata for endpoint index #{artifact.endpoint_index}")
        end

        if endpoint_url(endpoint).nil? || endpoint_url(endpoint).empty?
          raise ValidationError.new("The ArtifactResolutionService for endpoint index #{artifact.endpoint_index} has no Location")
        end

        endpoint
      end

      def endpoint_url(endpoint)
        endpoint[:url] || endpoint['url'] || endpoint[:location] || endpoint['location']
      end
    end
  end
end
