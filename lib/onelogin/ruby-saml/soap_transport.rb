require 'net/http'
require 'net/https'
require 'onelogin/ruby-saml/artifact_error'

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Default SOAP transport used to dereference SAML artifacts at the
    # IdP ArtifactResolutionService endpoint.
    #
    # Any object responding to #post(url, soap_envelope) and returning the
    # SOAP response body as a String can be injected instead (for tests or
    # to customize HTTP behavior). Transport implementations must raise
    # OneLogin::RubySaml::ArtifactTransportError on delivery failures so
    # that transient network errors stay distinguishable from validation
    # errors of the resolved message.
    #
    class SoapTransport
      CONTENT_TYPE = "text/xml; charset=utf-8".freeze
      SOAP_ACTION = "http://www.oasis-open.org/committees/security".freeze

      # Sends a SOAP envelope to the given endpoint.
      # @param url [String] The ArtifactResolutionService Location taken
      #   from the trusted IdP metadata.
      # @param soap_envelope [String] The SOAP envelope carrying the
      #   ArtifactResolve request.
      # @return [String] The SOAP response body.
      # @raise [ArtifactResolutionError] if the endpoint URL is not http(s).
      # @raise [ArtifactTransportError] on network failures or non-success
      #   HTTP status codes.
      def post(url, soap_envelope)
        uri = URI.parse(url.to_s)
        unless uri.is_a?(URI::HTTP)
          raise ArtifactResolutionError.new("Invalid Artifact Resolution Service URL: #{url.inspect}")
        end

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'

        request = Net::HTTP::Post.new(uri.request_uri)
        request['Content-Type'] = CONTENT_TYPE
        request['SOAPAction'] = SOAP_ACTION
        request.body = soap_envelope

        response = http.request(request)
        return response.body if response.is_a?(Net::HTTPSuccess)

        raise ArtifactTransportError.new(
          "Artifact Resolution Service replied with HTTP #{response.code}: #{response.message}"
        )
      rescue ArtifactError
        raise
      rescue StandardError => error
        raise ArtifactTransportError.new(
          "Failed to contact the Artifact Resolution Service: #{error.class}: #{error.message}"
        )
      end
    end
  end
end
