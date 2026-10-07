# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Base class for the errors raised while resolving a SAML artifact
    # through the HTTP Artifact binding.
    #
    class ArtifactError < StandardError; end

    # Raised when the artifact could not be resolved because the
    # communication with the IdP Artifact Resolution Service failed
    # (network errors, unexpected HTTP status, malformed SOAP response...).
    #
    # When this error is raised the artifact was not necessarily consumed
    # at the IdP, so the caller may decide to retry the resolution.
    #
    class ArtifactTransportError < ArtifactError; end

    # Raised when the artifact was already consumed (one-time-use semantics)
    # either by a previous resolution or by a concurrent one.
    #
    # This error must never be retried automatically: the artifact is
    # already spent and resolving it again would be a replay.
    #
    class ArtifactReplayError < ArtifactError; end
  end
end
