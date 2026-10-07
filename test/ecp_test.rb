require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class EcpTest < Minitest::Test

  AdapterResponse = Struct.new(:status, :body)

  # Caller-provided network adapter used by the ECP client. Records every
  # call and serves canned responses per URL.
  class RecordingAdapter
    Call = Struct.new(:url, :body, :headers)

    attr_reader :calls

    def initialize
      @calls = []
      @routes = {}
    end

    def register(url, status, body)
      @routes[url] = AdapterResponse.new(status, body)
    end

    def post(url, body:, headers:)
      @calls << Call.new(url, body, headers)
      @routes.fetch(url) { AdapterResponse.new(404, "") }
    end
  end

  IDP_SSO_URL = "https://idp.example.com/sso".freeze
  SP_ACS_URL = "https://sp.example.com/acs".freeze
  IDP_AUTHORIZATION = "Basic aWRwLXNlY3JldA==".freeze
  SP_AUTHORIZATION = "Basic c3Atc2VjcmV0".freeze

  describe "OneLogin::RubySaml::Ecp::Client" do
  def read_ecp_fixture(name)
    File.read(File.join(File.dirname(__FILE__), "ecp", name))
  end

  let(:sp_request) { read_ecp_fixture("sp_paos_request.xml") }
  let(:idp_response) { read_ecp_fixture("idp_soap_response.xml") }
  let(:adapter) do
    RecordingAdapter.new.tap do |a|
      a.register(IDP_SSO_URL, 200, idp_response)
      a.register(SP_ACS_URL, 200, "")
    end
  end
  let(:client) do
    OneLogin::RubySaml::Ecp::Client.new(
      idp_sso_url: IDP_SSO_URL,
      adapter: adapter,
      idp_credentials: { "Authorization" => IDP_AUTHORIZATION },
      sp_credentials: { "Authorization" => SP_AUTHORIZATION }
    )
  end

  describe "successful exchange" do
    it "forwards the AuthnRequest to the IdP and delivers the response to the SP" do
      exchange = client.authenticate(sp_request)

      assert_equal 2, adapter.calls.size
      assert_equal IDP_SSO_URL, adapter.calls[0].url
      assert_equal SP_ACS_URL, adapter.calls[1].url
      assert_equal 200, exchange.idp_status
      assert_equal 200, exchange.sp_status
    end

    it "returns the RelayState and the validated consumer URL" do
      exchange = client.authenticate(sp_request)

      assert_equal "relay-token-123", exchange.relay_state
      assert_equal SP_ACS_URL, exchange.assertion_consumer_service_url
      assert_includes exchange.response_document, "samlp:Response"
    end

    it "produces the expected SOAP envelope for the SP" do
      exchange = client.authenticate(sp_request)

      assert_equal read_ecp_fixture("sp_soap_response.xml"), exchange.sp_envelope
      assert_equal exchange.sp_envelope, adapter.calls[1].body
    end

    it "echoes the RelayState back to the SP without forwarding PAOS headers to the IdP" do
      client.authenticate(sp_request)

      idp_body = adapter.calls[0].body
      assert_includes idp_body, "samlp:AuthnRequest"
      refute_includes idp_body, "paos:Request"
      refute_includes idp_body, "RelayState"

      sp_body = adapter.calls[1].body
      assert_includes sp_body, "ecp:RelayState"
      assert_includes sp_body, "relay-token-123"
    end

    it "uses SP and IdP credentials on their own hops only" do
      client.authenticate(sp_request)

      idp_headers = adapter.calls[0].headers
      sp_headers = adapter.calls[1].headers

      assert_equal IDP_AUTHORIZATION, idp_headers["Authorization"]
      refute_equal SP_AUTHORIZATION, idp_headers["Authorization"]
      assert_equal SP_AUTHORIZATION, sp_headers["Authorization"]
      refute_equal IDP_AUTHORIZATION, sp_headers["Authorization"]
    end
  end

  describe "assertion consumer service URL validation" do
    it "rejects an IdP response that rewrites the AssertionConsumerServiceURL" do
      adapter.register(IDP_SSO_URL, 200, idp_response.gsub(SP_ACS_URL, "https://evil.example.com/acs"))

      error = assert_raises(OneLogin::RubySaml::Ecp::IdpExchangeError) { client.authenticate(sp_request) }
      assert_equal :idp, error.stage
      assert_includes error.fault, "soap:Server"
      assert_equal 1, adapter.calls.size, "response must not be delivered to the SP"
    end

    it "rejects an SP request whose AuthnRequest ACS differs from the paos responseConsumerURL" do
      tampered = sp_request.gsub('AssertionConsumerServiceURL="https://sp.example.com/acs"',
                                 'AssertionConsumerServiceURL="https://evil.example.com/acs"')

      error = assert_raises(OneLogin::RubySaml::Ecp::SpRequestError) { client.authenticate(tampered) }
      assert_equal :sp, error.stage
      assert_includes error.fault, "soap:Client"
      assert_empty adapter.calls
    end
  end

  describe "SOAP header validation" do
    it "rejects duplicate security headers" do
      security = '<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"/>'
      tampered = sp_request.sub("</ecp:RelayState>", "</ecp:RelayState>#{security}#{security}")

      error = assert_raises(OneLogin::RubySaml::Ecp::SpRequestError) { client.authenticate(tampered) }
      assert_equal :sp, error.stage
      assert_includes error.message, "duplicate wsse:Security"
      assert_includes error.fault, "soap:Client"
      assert_empty adapter.calls
    end

    it "rejects unknown mustUnderstand headers" do
      unknown = '<x:Unknown xmlns:x="urn:example:unknown" soap:mustUnderstand="1"/>'
      tampered = sp_request.sub("</ecp:RelayState>", "</ecp:RelayState>#{unknown}")

      error = assert_raises(OneLogin::RubySaml::Ecp::SpRequestError) { client.authenticate(tampered) }
      assert_equal :sp, error.stage
      assert_includes error.fault, "soap:MustUnderstand"
      assert_empty adapter.calls
    end

    it "rejects headers with a wrong soap:actor" do
      tampered = sp_request.gsub("http://schemas.xmlsoap.org/soap/actor/next", "http://example.com/other")

      assert_raises(OneLogin::RubySaml::Ecp::SpRequestError) { client.authenticate(tampered) }
      assert_empty adapter.calls
    end
  end

  describe "RelayState validation" do
    it "rejects RelayState longer than 80 bytes" do
      tampered = sp_request.sub("relay-token-123", "x" * 81)

      error = assert_raises(OneLogin::RubySaml::Ecp::SpRequestError) { client.authenticate(tampered) }
      assert_includes error.message, "RelayState"
      assert_empty adapter.calls
    end
  end

  describe "failure reporting" do
    it "raises an SP stage error for a malformed PAOS request" do
      error = assert_raises(OneLogin::RubySaml::Ecp::SpRequestError) { client.authenticate("<not-xml") }
      assert_equal :sp, error.stage
      assert_includes error.fault, "soap:Fault"
    end

    it "raises an IdP stage error when the IdP returns an HTTP error" do
      adapter.register(IDP_SSO_URL, 500, "internal error")

      error = assert_raises(OneLogin::RubySaml::Ecp::IdpExchangeError) { client.authenticate(sp_request) }
      assert_equal :idp, error.stage
      assert_includes error.fault, "soap:Server"
    end

    it "raises an IdP stage error when the IdP returns a SOAP fault" do
      fault = <<~XML
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <soap:Fault>
              <faultcode>soap:Server</faultcode>
              <faultstring>authentication failed</faultstring>
            </soap:Fault>
          </soap:Body>
        </soap:Envelope>
      XML
      adapter.register(IDP_SSO_URL, 200, fault)

      error = assert_raises(OneLogin::RubySaml::Ecp::IdpExchangeError) { client.authenticate(sp_request) }
      assert_includes error.message, "authentication failed"
    end

    it "does not leak credentials or assertion content into exceptions" do
      adapter.register(IDP_SSO_URL, 200, idp_response.gsub(SP_ACS_URL, "https://evil.example.com/acs"))

      error = assert_raises(OneLogin::RubySaml::Ecp::IdpExchangeError) { client.authenticate(sp_request) }
      exposed = error.message + error.fault
      refute_includes exposed, IDP_AUTHORIZATION
      refute_includes exposed, SP_AUTHORIZATION
      refute_includes exposed, "ecp-user"
      refute_includes exposed, "saml:Assertion"
    end

    it "does not leak credentials when the IdP exchange fails" do
      adapter.register(IDP_SSO_URL, 500, "boom")

      error = assert_raises(OneLogin::RubySaml::Ecp::IdpExchangeError) { client.authenticate(sp_request) }
      exposed = error.message + error.fault
      refute_includes exposed, IDP_AUTHORIZATION
      refute_includes exposed, SP_AUTHORIZATION
    end
  end
  end
end
