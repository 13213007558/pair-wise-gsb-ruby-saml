require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe "ECP Client" do
  ECP_DIR = File.join(File.dirname(__FILE__), 'ecp')
  IDP_URL = 'https://idp.example.com/saml/ecp'.freeze
  IDP_CREDENTIALS = { :username => 'ecp-user', :password => 'idp-secret' }.freeze

  # Records the calls made by the client and replays a canned IdP response.
  class FakeAdapter
    HttpResponse = Struct.new(:status, :body)

    attr_reader :calls
    attr_accessor :response

    def initialize(response)
      @response = response
      @calls = []
    end

    def post(url, body, headers, credentials = nil)
      @calls << { :url => url, :body => body, :headers => headers, :credentials => credentials }
      @response
    end
  end

  def read_ecp_fixture(name)
    File.read(File.join(ECP_DIR, name))
  end

  def sp_request
    read_ecp_fixture('sp_authn_request.xml')
  end

  def idp_response
    read_ecp_fixture('idp_response.xml')
  end

  def adapter
    @adapter ||= FakeAdapter.new(FakeAdapter::HttpResponse.new(200, idp_response))
  end

  def client
    @client ||= OneLogin::RubySaml::ECP::Client.new(
      :idp_url => IDP_URL,
      :http_adapter => adapter,
      :idp_credentials => IDP_CREDENTIALS
    )
  end

  describe "configuration" do
    it "requires an IdP URL" do
      assert_raises(ArgumentError) do
        OneLogin::RubySaml::ECP::Client.new(:idp_url => nil, :http_adapter => adapter)
      end
    end

    it "requires an adapter responding to #post" do
      assert_raises(ArgumentError) do
        OneLogin::RubySaml::ECP::Client.new(:idp_url => IDP_URL, :http_adapter => Object.new)
      end
    end
  end

  describe "successful exchange" do
    it "returns the IdP response to the SP with the RelayState header" do
      result = client.handle_sp_request(sp_request)
      assert_equal read_ecp_fixture('sp_response.xml'), result
    end

    it "sends the AuthnRequest to the IdP without the consumed PAOS/ECP headers" do
      client.handle_sp_request(sp_request)

      assert_equal 1, adapter.calls.size
      call = adapter.calls.first
      assert_equal IDP_URL, call[:url]
      assert_equal IDP_CREDENTIALS, call[:credentials]
      assert_equal 'application/soap+xml; charset=utf-8', call[:headers]['Content-Type']

      document = Nokogiri::XML(call[:body])
      namespaces = { 'paos' => OneLogin::RubySaml::ECP::PAOS, 'ecp' => OneLogin::RubySaml::ECP::ECP_NS, 'samlp' => OneLogin::RubySaml::SamlMessage::PROTOCOL }
      assert_empty document.xpath('//paos:Request', namespaces)
      assert_empty document.xpath('//ecp:RelayState', namespaces)
      assert_equal 1, document.xpath('//samlp:AuthnRequest', namespaces).size
    end

    it "keeps IdP credentials off the SP leg" do
      result = client.handle_sp_request(sp_request)
      refute_includes result, IDP_CREDENTIALS[:password]
    end

    it "omits the RelayState header when the SP did not send one" do
      without_relay = sp_request.sub(%r{[[:space:]]*<ecp:RelayState.*</ecp:RelayState>}m, '')
      result = client.handle_sp_request(without_relay)

      document = Nokogiri::XML(result)
      assert_empty document.xpath('//ecp:RelayState', 'ecp' => OneLogin::RubySaml::ECP::ECP_NS)
      assert_equal 1, document.xpath('//samlp:Response', 'samlp' => OneLogin::RubySaml::SamlMessage::PROTOCOL).size
    end
  end

  describe "assertion consumer service validation" do
    it "rejects an IdP response with a rewritten AssertionConsumerServiceURL" do
      adapter.response = FakeAdapter::HttpResponse.new(
        200,
        idp_response.sub('AssertionConsumerServiceURL="https://sp.example.com/acs"',
                         'AssertionConsumerServiceURL="https://evil.example.com/acs"')
      )

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(sp_request)
      end
      assert_equal 'env:Receiver', error.fault_code
      assert_match 'env:Receiver', error.to_soap
      refute_includes error.to_soap, 'evil.example.com'
    end

    it "rejects a PAOS responseConsumerURL that differs from the AuthnRequest ACS" do
      tampered = sp_request.sub('responseConsumerURL="https://sp.example.com/acs"',
                                'responseConsumerURL="https://evil.example.com/acs"')

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(tampered)
      end
      assert_equal 'env:Sender', error.fault_code
      assert_empty adapter.calls
    end
  end

  describe "header validation" do
    it "rejects duplicate PAOS Request headers" do
      tampered = sp_request.sub('<ecp:RelayState',
                                '<paos:Request xmlns:paos="urn:liberty:paos:2003-08" soap:mustUnderstand="1" soap:actor="http://schemas.xmlsoap.org/soap/actor/next" responseConsumerURL="https://sp.example.com/acs" service="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"/>\n    <ecp:RelayState')

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(tampered)
      end
      assert_equal 'env:Sender', error.fault_code
      assert_equal 'Duplicate PAOS Request headers', error.message
      assert_empty adapter.calls
    end

    it "rejects duplicate ECP RelayState headers" do
      tampered = sp_request.sub('</soap:Header>',
                                '<ecp:RelayState xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp" soap:mustUnderstand="1" soap:actor="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp">other</ecp:RelayState>\n  </soap:Header>')

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(tampered)
      end
      assert_equal 'env:Sender', error.fault_code
      assert_equal 'Duplicate ECP RelayState headers', error.message
      assert_empty adapter.calls
    end

    it "rejects duplicate ECP Response headers from the IdP" do
      adapter.response = FakeAdapter::HttpResponse.new(
        200,
        idp_response.sub('</soap:Header>',
                         '<ecp:Response xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp" soap:mustUnderstand="1" soap:actor="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp" AssertionConsumerServiceURL="https://sp.example.com/acs"/>\n  </soap:Header>')
      )

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(sp_request)
      end
      assert_equal 'env:Receiver', error.fault_code
      assert_equal 'Duplicate ECP Response headers', error.message
    end

    it "rejects unknown mustUnderstand headers with a MustUnderstand fault" do
      tampered = sp_request.sub('<ecp:RelayState',
                                '<x:ChannelBindings xmlns:x="urn:example:channel-bindings" soap:mustUnderstand="1" soap:actor="http://schemas.xmlsoap.org/soap/actor/next"/>\n    <ecp:RelayState')

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(tampered)
      end
      assert_equal 'env:MustUnderstand', error.fault_code
      assert_match 'env:MustUnderstand', error.to_soap
      assert_empty adapter.calls
    end

    it "rejects a PAOS Request header with a wrong actor" do
      tampered = sp_request.sub('soap:actor="http://schemas.xmlsoap.org/soap/actor/next"',
                                'soap:actor="urn:example:someone-else"')

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(tampered)
      end
      assert_equal 'env:Sender', error.fault_code
      assert_empty adapter.calls
    end
  end

  describe "IdP leg failures" do
    it "raises a Receiver fault when the IdP returns an error status" do
      adapter.response = FakeAdapter::HttpResponse.new(500, '<html>proxy error</html>')

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(sp_request)
      end
      assert_equal 'env:Receiver', error.fault_code
      refute_includes error.message, 'proxy error'
    end

    it "raises a Receiver fault when the adapter fails" do
      def adapter.post(*)
        raise IOError, "connection refused to https://user:idp-secret@idp.example.com"
      end

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(sp_request)
      end
      assert_equal 'env:Receiver', error.fault_code
      refute_includes error.message, 'idp-secret'
      refute_includes error.to_soap, 'idp-secret'
    end
  end

  describe "fault content" do
    it "never leaks credentials or assertions into fault text" do
      adapter.response = FakeAdapter::HttpResponse.new(
        200,
        idp_response.sub('AssertionConsumerServiceURL="https://sp.example.com/acs"',
                         'AssertionConsumerServiceURL="https://evil.example.com/acs"')
      )

      error = assert_raises(OneLogin::RubySaml::ECP::SOAPFaultError) do
        client.handle_sp_request(sp_request)
      end
      [error.message, error.to_soap].each do |text|
        refute_includes text, IDP_CREDENTIALS[:password]
        refute_includes text, '_assertion1'
        refute_includes text, '<saml:Assertion'
      end
    end
  end
end
