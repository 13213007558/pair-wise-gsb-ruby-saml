# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Base class for errors raised while resolving a SAML artifact
    # through the HTTP Artifact binding.
    #
    class ArtifactError < StandardError; end

    # Raised when the SOAP transport fails to deliver the ArtifactResolve
    # request or to retrieve a successful response (DNS, TCP, TLS, timeouts
    # or non-success HTTP status codes).
    #
    # This kind of failure is transient: the artifact has not necessarily
    # been consumed at the Identity Provider, so the caller may retry the
    # resolution with the same artifact.
    #
    class ArtifactTransportError < ArtifactError; end

    # Raised when the artifact itself, the ArtifactResponse envelope or the
    # SAML message it carries fails validation (malformed artifact, unknown
    # endpoint, SourceID mismatch, bad InResponseTo/Issuer/Status/Signature
    # on the ArtifactResponse, or an invalid inner SAML Response).
    #
    # This kind of failure is permanent: retrying the resolution with the
    # same artifact will not produce a different outcome, so callers must
    # NOT automatically retry.
    #
    class ArtifactResolutionError < ArtifactError; end

    # Raised when the same artifact is presented for resolution more than
    # once. SAML artifacts are single-use: the artifact store rejects
    # concurrent or repeated consumption attempts with this error.
    #
    class ArtifactReplayError < ArtifactError; end
  end
end
