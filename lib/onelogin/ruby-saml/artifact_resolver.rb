require "base64"

require "onelogin/ruby-saml/artifact"
require "onelogin/ruby-saml/artifact_error"
require "onelogin/ruby-saml/artifact_resolve"
require "onelogin/ruby-saml/artifact_response"
require "onelogin/ruby-saml/artifact_store"
require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/response"
require "onelogin/ruby-saml/soap_transport"
require "onelogin/ruby-saml/validation_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 HTTP Artifact binding (Receiver)
    #
    # Resolves the SAMLart parameter received on the SP callback when the IdP
    # uses the HTTP Artifact binding instead of POSTing the SAMLResponse.
    #
    # The resolution flow:
    #   1. Parses the type 0x0004 artifact (TypeCode, EndpointIndex, SourceID,
    #      MessageHandle). The artifact is an opaque token, it never carries
    #      the resolution URL nor the message itself.
    #   2. Verifies that the SourceID matches the SHA-1 of the trusted IdP
    #      entityID from the settings.
    #   3. Enforces the one-time-use semantics through the artifact store:
    #      an artifact that was already consumed (or is being consumed by a
    #      concurrent call) is rejected as a replay.
    #   4. Selects the ArtifactResolutionService endpoint from the trusted
    #      IdP metadata (settings), using the EndpointIndex of the artifact.
    #   5. Sends an ArtifactResolve request through the (injectable) SOAP
    #      transport.
    #   6. Validates the ArtifactResponse (InResponseTo, Issuer, Status and
    #      Signature) and hands the inner SAML message to the standard
    #      OneLogin::RubySaml::Response validation chain.
    #
    # Error taxonomy (do not retry everything blindly):
    #   - ArtifactTransportError: the artifact could not be resolved due to a
    #     transport failure. The artifact handle is released, so the caller
    #     may retry the resolution.
    #   - ArtifactReplayError: the artifact was already consumed. Never retry.
    #   - ValidationError: the artifact or the ArtifactResponse are invalid
    #     (including a resolved response whose content does not verify). The
    #     artifact stays consumed, automatic retry is pointless and must not
    #     happen.
    #   When the ArtifactResponse is valid but the inner SAML Response is not,
    #   resolve returns the OneLogin::RubySaml::Response object and its
    #   is_valid? returns false: no exception, no retry, the artifact stays
    #   consumed.
    #
    class ArtifactResolver
      # OneLogin::RubySaml::Settings Toolkit settings
      attr_reader :settings

      attr_reader :options

      # Response options that are forwarded to the inner response validation
      FORWARDED_RESPONSE_OPTIONS = [
        :allowed_clock_drift, :check_duplicated_attributes, :matches_request_id, :skip_audience,
        :skip_authnstatement, :skip_conditions, :skip_destination, :skip_recipient_check,
        :skip_subject_confirmation
      ].freeze

      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param options [Hash] :soap_transport to inject the SOAP transport
      #                       (any object responding to call(url, soap_envelope)),
      #                       :artifact_store to inject the one-time-use state store,
      #                       plus any OneLogin::RubySaml::Response option forwarded
      #                       to the validation of the resolved response
      #
      def initialize(settings, options = {})
        @settings = settings
        @options = options
      end

      # Resolves a SAMLart parameter value into a OneLogin::RubySaml::Response.
      # @param samlart [String] The SAMLart parameter received on the SP callback
      # @return [OneLogin::RubySaml::Response] The resolved SAML Response, ready
      #   to be validated with the standard validation chain
      # @raise [ValidationError] If the artifact or the ArtifactResponse are invalid
      # @raise [ArtifactReplayError] If the artifact was already consumed
      # @raise [ArtifactTransportError] If the resolution failed at the transport level
      #
      def resolve(samlart)
        artifact = Artifact.parse(samlart)

        unless artifact.source_id_matches?(settings.idp_entity_id)
          raise ValidationError.new("The SourceID of the artifact does not match the trusted IdP entityID")
        end

        endpoint = resolution_endpoint(artifact.endpoint_index)

        store = artifact_store
        handle_key = artifact.message_handle_key
        unless store.consume(handle_key)
          raise ArtifactReplayError.new("The artifact was already consumed")
        end

        resolve_request = ArtifactResolve.new
        soap_envelope = resolve_request.create_soap_envelope(settings, samlart)

        body = execute_transport(endpoint, soap_envelope, store, handle_key)

        artifact_response = ArtifactResponse.new(
          body,
          :settings => settings,
          :matches_request_id => resolve_request.request_id
        )

        unless artifact_response.is_valid?(true)
          # The artifact was resolved but the ArtifactResponse is invalid.
          # The artifact stays consumed: this must not be retried.
          raise ValidationError.new(artifact_response.errors.join(", "))
        end

        Logging.debug "Artifact resolved, building the SAML Response"

        OneLogin::RubySaml::Response.new(
          Base64.strict_encode64(artifact_response.inner_response),
          response_options
        )
      end

      private

      # Selects the ArtifactResolutionService endpoint from the trusted IdP
      # metadata registered on the settings, using the EndpointIndex carried
      # by the artifact.
      # @param endpoint_index [Integer] The EndpointIndex of the artifact
      # @return [String] The endpoint URL
      # @raise [ValidationError] If no endpoint can be selected
      #
      def resolution_endpoint(endpoint_index)
        services = settings.idp_artifact_resolution_services
        if services && !services.empty?
          service = services.find do |svc|
            (svc[:index] || svc['index']).to_i == endpoint_index
          end

          if service.nil?
            raise ValidationError.new("No ArtifactResolutionService with index #{endpoint_index} found on the trusted IdP metadata")
          end

          location = service[:location] || service['location']
          return location unless location.nil? || location.empty?

          raise ValidationError.new("The ArtifactResolutionService with index #{endpoint_index} has no Location")
        end

        url = settings.idp_artifact_resolution_service_url
        if url.nil? || url.empty?
          raise ValidationError.new("No artifact resolution endpoint on settings (idp_artifact_resolution_service_url)")
        end

        url
      end

      # Delivers the ArtifactResolve request through the SOAP transport.
      # Transport failures release the artifact handle so the caller may
      # retry, anything else keeps the artifact consumed.
      #
      def execute_transport(endpoint, soap_envelope, store, handle_key)
        soap_transport.call(endpoint, soap_envelope)
      rescue ArtifactTransportError
        store.release(handle_key)
        raise
      rescue StandardError => error
        store.release(handle_key)
        raise ArtifactTransportError.new("Artifact resolution transport error: #{error.message}")
      end

      # @return [Object] The injected SOAP transport or the default one
      #
      def soap_transport
        options[:soap_transport] || SoapTransport.new
      end

      # @return [Object] The injected artifact store or a process local one
      #
      def artifact_store
        @artifact_store ||= options[:artifact_store] || ArtifactStore::Memory.new
      end

      # @return [Hash] The options forwarded to the inner Response validation
      #
      def response_options
        forwarded = {}
        FORWARDED_RESPONSE_OPTIONS.each do |key|
          forwarded[key] = options[key] if options.has_key?(key)
        end
        forwarded[:settings] = settings
        forwarded
      end
    end
  end
end
