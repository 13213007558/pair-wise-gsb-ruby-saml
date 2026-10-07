require 'base64'
require 'onelogin/ruby-saml/artifact'
require 'onelogin/ruby-saml/artifact_error'
require 'onelogin/ruby-saml/artifact_resolve'
require 'onelogin/ruby-saml/artifact_response'
require 'onelogin/ruby-saml/artifact_store'
require 'onelogin/ruby-saml/response'
require 'onelogin/ruby-saml/soap_transport'
require 'onelogin/ruby-saml/validation_error'

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Receiving side of the SAML V2.0 HTTP Artifact binding.
    #
    # When the IdP redirects the user agent back to the Assertion Consumer
    # Service with a SAMLart parameter instead of a SAMLResponse, this
    # class:
    #   1. parses the type 0x0004 artifact (SourceID, EndpointIndex and
    #      message handle),
    #   2. claims the artifact in the single-use artifact store,
    #   3. selects the ArtifactResolutionService endpoint published in the
    #      already trusted IdP metadata (never a URL taken from the
    #      artifact itself),
    #   4. dereferences the artifact through the injectable SOAP
    #      transport,
    #   5. validates the ArtifactResponse envelope (InResponseTo, Issuer,
    #      Status and Signature),
    #   6. hands the extracted SAML Response to the standard validation
    #      chain (OneLogin::RubySaml::Response).
    #
    # Failure semantics:
    #   - ArtifactTransportError: transient network failure. The artifact
    #     claim is released so the caller may retry the resolution.
    #   - ArtifactResolutionError: the artifact or the resolved message is
    #     invalid. The artifact is marked as consumed and the caller must
    #     NOT retry with the same artifact.
    #   - ArtifactReplayError: the artifact was already consumed or is
    #     being resolved concurrently.
    #
    class ArtifactReceiver
      attr_reader :settings, :transport, :store

      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings.
      # @param transport [#post] Object responding to #post(url, soap_envelope).
      #   Defaults to OneLogin::RubySaml::SoapTransport.
      # @param store [OneLogin::RubySaml::ArtifactStore] Single-use
      #   artifact store. Defaults to an in-memory store.
      def initialize(settings, transport: nil, store: nil)
        @settings = settings
        @transport = transport || SoapTransport.new
        @store = store || InMemoryArtifactStore.new
      end

      # Resolves a SAMLart parameter into a validated SAML Response.
      # @param samlart [String] The SAMLart parameter received at the ACS
      #   endpoint.
      # @param options [Hash] Extra options forwarded to
      #   OneLogin::RubySaml::Response (e.g. :matches_request_id,
      #   :allowed_clock_drift, :skip_destination).
      # @return [OneLogin::RubySaml::Response] The validated SAML Response.
      # @raise [ArtifactTransportError] on transient transport failures.
      # @raise [ArtifactResolutionError] on any validation failure.
      # @raise [ArtifactReplayError] if the artifact was already consumed.
      def resolve(samlart, options = {})
        artifact = Artifact.parse(samlart)
        verify_source!(artifact)
        endpoint = resolution_endpoint_for(artifact)

        key = artifact.cache_key
        unless store.acquire(key)
          raise ArtifactReplayError.new("SAML artifact already consumed or being resolved")
        end

        begin
          resolve_request = ArtifactResolve.new(settings, artifact)
          soap_response = transport.post(endpoint, resolve_request.to_soap)

          artifact_response = ArtifactResponse.new(soap_response, settings)
          artifact_response.validate!(resolve_request.uuid)

          inner_xml = artifact_response.inner_message_xml
          if inner_xml.nil?
            raise ArtifactResolutionError.new("ArtifactResponse did not carry a SAML message")
          end

          response = build_and_validate_response(inner_xml, options)

          store.commit(key)
          response
        rescue ArtifactTransportError
          # Transient failure: allow the caller to retry with the same
          # artifact.
          store.release(key)
          raise
        rescue Exception
          # The artifact was dereferenced (or rejected) at the IdP: it is
          # spent either way and must not be replayed.
          store.commit(key)
          raise
        end
      end

      private

      # The SourceID of a type 0x0004 artifact is the SHA-1 of the IdP
      # entityID: reject artifacts that do not belong to the trusted IdP.
      def verify_source!(artifact)
        return if settings.idp_entity_id.nil?

        unless artifact.source_id_matches?(settings.idp_entity_id)
          raise ArtifactResolutionError.new(
            "The artifact SourceID does not match the trusted IdP entityID"
          )
        end
      end

      # Selects the resolution endpoint among the ones published by the
      # trusted IdP metadata, using the artifact EndpointIndex. The
      # artifact content itself is never dereferenced as a URL.
      def resolution_endpoint_for(artifact)
        services = settings.idp_artifact_resolution_services
        if services && !services.empty?
          url = services[artifact.endpoint_index] || services[artifact.endpoint_index.to_s]
          if url.nil?
            raise ArtifactResolutionError.new(
              "No trusted ArtifactResolutionService endpoint for index #{artifact.endpoint_index}"
            )
          end
          url
        elsif settings.idp_artifact_resolution_service_url
          settings.idp_artifact_resolution_service_url
        else
          raise ArtifactResolutionError.new(
            "No IdP Artifact Resolution Service endpoint configured"
          )
        end
      end

      def build_and_validate_response(inner_xml, options)
        response = Response.new(
          Base64.strict_encode64(inner_xml),
          options.merge(:settings => settings)
        )

        valid = begin
          response.is_valid?
        rescue OneLogin::RubySaml::ValidationError => error
          raise ArtifactResolutionError.new(
            "The SAML Response obtained via artifact resolution is invalid: #{error.message}"
          )
        end

        unless valid
          raise ArtifactResolutionError.new(
            "The SAML Response obtained via artifact resolution is invalid: #{response.errors.join(', ')}"
          )
        end

        response
      end
    end
  end
end
