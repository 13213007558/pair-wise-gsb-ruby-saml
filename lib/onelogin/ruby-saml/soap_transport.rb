require "net/http"
require "net/https"
require "uri"

require "onelogin/ruby-saml/artifact_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Default SOAP transport used to deliver the ArtifactResolve request to
    # the IdP Artifact Resolution Service endpoint (SOAP binding).
    #
    # Any object responding to call(url, soap_envelope) and returning the
    # response body can be injected through the :soap_transport option of
    # OneLogin::RubySaml::ArtifactResolver (useful for tests and for custom
    # HTTP stacks, mutual TLS, proxies...).
    #
    class SoapTransport
      SOAP_ACTION = "http://www.oasis-open.org/committees/security".freeze

      # POSTs the SOAP envelope to the given endpoint.
      # @param url [String] The Artifact Resolution Service endpoint URL
      # @param soap_envelope [String] The SOAP envelope that wraps the ArtifactResolve request
      # @return [String] The response body
      # @raise [ArtifactTransportError] On network failures and non success HTTP statuses
      #
      def call(url, soap_envelope)
        uri = URI.parse(url)
        unless uri.is_a?(URI::HTTP)
          raise ArtifactTransportError.new("Invalid artifact resolution endpoint: #{url}")
        end

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"

        request = Net::HTTP::Post.new(uri.request_uri)
        request["Content-Type"] = "text/xml; charset=utf-8"
        request["SOAPAction"] = SOAP_ACTION
        request.body = soap_envelope

        response = http.request(request)
        unless response.is_a?(Net::HTTPSuccess)
          raise ArtifactTransportError.new("Artifact resolution failed: HTTP #{response.code}: #{response.message}")
        end

        response.body
      rescue ArtifactTransportError
        raise
      rescue StandardError => error
        raise ArtifactTransportError.new("Artifact resolution transport error: #{error.message}")
      end
    end
  end
end
