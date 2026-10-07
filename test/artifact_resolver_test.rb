require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ArtifactResolverTest < Minitest::Test
  describe "ArtifactResolver" do
    IDP_ENTITY_ID = "https://app.onelogin.com/saml2".freeze
    SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze
    RESOLUTION_ENDPOINT = "https://idp.example.com/artifact".freeze

    def resolver_settings
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = IDP_ENTITY_ID
      settings.sp_entity_id = "https://sp.example.com/saml"
      settings.idp_cert = ruby_saml_cert_text
      settings.idp_artifact_resolution_service_url = RESOLUTION_ENDPOINT
      settings
    end

    def make_artifact(handle = "handle-#{SecureRandom.hex(8)}", endpoint_index: 0, entity_id: IDP_ENTITY_ID)
      OneLogin::RubySaml::Artifact.encode(
        OneLogin::RubySaml::Artifact.build(Digest::SHA1.digest(entity_id), handle, endpoint_index)
      )
    end

    def valid_inner_response_xml
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(Base64.decode64(response_document_valid_signed))
    end

    def expired_inner_response_xml
      valid_inner_response_xml.gsub("2030-06-04T02:27:02Z", "2015-06-04T02:27:02Z")
    end

    def build_artifact_response_xml(inner_xml, id: "_ar_#{SecureRandom.hex(8)}", issuer: IDP_ENTITY_ID,
                                    in_response_to: nil, status: SUCCESS, sign: true)
      doc = XMLSecurity::Document.new
      doc.uuid = id
      root = doc.add_element "samlp:ArtifactResponse", {
        "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
        "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
      }
      root.attributes['ID'] = id
      root.attributes['Version'] = "2.0"
      root.attributes['IssueInstant'] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      root.attributes['InResponseTo'] = in_response_to if in_response_to

      issuer_element = root.add_element "saml:Issuer"
      issuer_element.text = issuer

      status_element = root.add_element "samlp:Status"
      status_code_element = status_element.add_element "samlp:StatusCode"
      status_code_element.attributes['Value'] = status

      if inner_xml
        inner = REXML::Document.new(inner_xml).root
        root.add_element(inner)
      end

      doc.sign_document(ruby_saml_key, ruby_saml_cert) if sign

      xml = "".dup
      doc.write(xml)
      xml
    end

    def soap_wrap(xml)
      "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>#{xml}</soap:Body></soap:Envelope>"
    end

    # A local transport double that emulates the IdP Artifact Resolution
    # Service: it reads the ArtifactResolve ID from the received SOAP
    # envelope and echoes it on the InResponseTo of the ArtifactResponse.
    def idp_transport(inner_xml, recorder: [], sign: true, issuer: IDP_ENTITY_ID,
                      status: SUCCESS, in_response_to: :echo, soap: true)
      lambda do |url, envelope|
        recorder << [url, envelope]
        resolve_doc = REXML::Document.new(envelope)
        resolve_id = REXML::XPath.first(
          resolve_doc,
          "//samlp:ArtifactResolve",
          { "samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
        ).attributes["ID"]
        echoed = in_response_to == :echo ? resolve_id : in_response_to
        body = build_artifact_response_xml(
          inner_xml,
          :issuer => issuer,
          :status => status,
          :in_response_to => echoed,
          :sign => sign
        )
        soap ? soap_wrap(body) : body
      end
    end

    def build_resolver(settings, options = {})
      OneLogin::RubySaml::ArtifactResolver.new(
        settings,
        { :skip_audience => true, :skip_recipient_check => true }.merge(options)
      )
    end

    it "resolves a valid artifact into a valid SAML Response" do
      requests = []
      samlart = make_artifact
      resolver = build_resolver(resolver_settings, :soap_transport => idp_transport(valid_inner_response_xml, :recorder => requests))

      response = resolver.resolve(samlart)

      assert response.is_valid?, response.errors.join(", ")
      assert_equal "test@onelogin.com", response.name_id

      # the resolution endpoint comes from the trusted settings, the
      # artifact content is never used as a URL
      assert_equal 1, requests.size
      assert_equal RESOLUTION_ENDPOINT, requests.first[0]
      assert_includes requests.first[1], "samlp:ArtifactResolve"
      assert_includes requests.first[1], "<samlp:Artifact>#{samlart}</samlp:Artifact>"
    end

    it "selects the resolution endpoint by the EndpointIndex of the artifact" do
      settings = resolver_settings
      settings.idp_artifact_resolution_services = [
        { :index => 0, :binding => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", :location => "https://idp.example.com/ars/0" },
        { :index => 1, :binding => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", :location => "https://idp.example.com/ars/1" }
      ]

      requests = []
      resolver = build_resolver(settings, :soap_transport => idp_transport(valid_inner_response_xml, :recorder => requests))
      response = resolver.resolve(make_artifact("handle-index-1", :endpoint_index => 1))

      assert response.is_valid?, response.errors.join(", ")
      assert_equal "https://idp.example.com/ars/1", requests.first[0]
    end

    it "rejects an artifact whose EndpointIndex is not on the trusted metadata" do
      settings = resolver_settings
      settings.idp_artifact_resolution_services = [
        { :index => 0, :binding => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", :location => "https://idp.example.com/ars/0" }
      ]

      requests = []
      resolver = build_resolver(settings, :soap_transport => idp_transport(valid_inner_response_xml, :recorder => requests))

      assert_raises(OneLogin::RubySaml::ValidationError) do
        resolver.resolve(make_artifact("handle-unknown-index", :endpoint_index => 7))
      end
      assert_empty requests
    end

    it "rejects an artifact whose SourceID does not match the trusted IdP" do
      requests = []
      resolver = build_resolver(resolver_settings, :soap_transport => idp_transport(valid_inner_response_xml, :recorder => requests))

      error = assert_raises(OneLogin::RubySaml::ValidationError) do
        resolver.resolve(make_artifact("handle-evil", :entity_id => "https://evil.example.com/idp"))
      end
      assert_includes error.message, "SourceID"
      assert_empty requests
    end

    it "rejects a malformed artifact without calling the transport" do
      requests = []
      resolver = build_resolver(resolver_settings, :soap_transport => idp_transport(valid_inner_response_xml, :recorder => requests))

      assert_raises(OneLogin::RubySaml::ValidationError) { resolver.resolve("!!! not an artifact !!!") }
      assert_empty requests
    end

    it "raises a ValidationError when no resolution endpoint is configured" do
      settings = resolver_settings
      settings.idp_artifact_resolution_service_url = nil
      resolver = build_resolver(settings, :soap_transport => idp_transport(valid_inner_response_xml))

      assert_raises(OneLogin::RubySaml::ValidationError) { resolver.resolve(make_artifact) }
    end

    it "raises ArtifactTransportError on network failure and releases the handle so a retry is possible" do
      store = OneLogin::RubySaml::ArtifactStore::Memory.new
      samlart = make_artifact

      failing_transport = lambda { |_url, _envelope| raise Errno::ECONNREFUSED }
      resolver = build_resolver(resolver_settings, :soap_transport => failing_transport, :artifact_store => store)

      assert_raises(OneLogin::RubySaml::ArtifactTransportError) { resolver.resolve(samlart) }

      # the handle was released: the caller may retry the same artifact
      working_resolver = build_resolver(
        resolver_settings,
        :soap_transport => idp_transport(valid_inner_response_xml),
        :artifact_store => store
      )
      response = working_resolver.resolve(samlart)
      assert response.is_valid?, response.errors.join(", ")
    end

    it "does not retry automatically a resolved but invalid ArtifactResponse" do
      store = OneLogin::RubySaml::ArtifactStore::Memory.new
      samlart = make_artifact

      # the IdP answers with a mismatched InResponseTo
      bad_transport = idp_transport(valid_inner_response_xml, :in_response_to => "_some_other_request")
      resolver = build_resolver(resolver_settings, :soap_transport => bad_transport, :artifact_store => store)

      assert_raises(OneLogin::RubySaml::ValidationError) { resolver.resolve(samlart) }

      # the artifact stays consumed: a second attempt is a replay, not a retry
      good_resolver = build_resolver(
        resolver_settings,
        :soap_transport => idp_transport(valid_inner_response_xml),
        :artifact_store => store
      )
      assert_raises(OneLogin::RubySaml::ArtifactReplayError) { good_resolver.resolve(samlart) }
    end

    it "does not produce a valid login when a correct ArtifactResponse wraps an invalid inner assertion" do
      store = OneLogin::RubySaml::ArtifactStore::Memory.new
      samlart = make_artifact
      resolver = build_resolver(
        resolver_settings,
        :soap_transport => idp_transport(expired_inner_response_xml),
        :artifact_store => store
      )

      response = resolver.resolve(samlart)

      refute response.is_valid?
      refute_empty response.errors

      # and the artifact stays consumed
      assert_raises(OneLogin::RubySaml::ArtifactReplayError) { resolver.resolve(samlart) }
    end

    it "rejects the replay of an already consumed artifact" do
      resolver = build_resolver(resolver_settings, :soap_transport => idp_transport(valid_inner_response_xml))
      samlart = make_artifact

      assert resolver.resolve(samlart).is_valid?
      assert_raises(OneLogin::RubySaml::ArtifactReplayError) { resolver.resolve(samlart) }
    end

    it "rejects concurrent duplicate consumption of the same artifact" do
      store = OneLogin::RubySaml::ArtifactStore::Memory.new
      transport = idp_transport(valid_inner_response_xml)
      samlart = make_artifact
      barrier = Queue.new

      results = Queue.new
      threads = 2.times.map do
        Thread.new do
          resolver = build_resolver(resolver_settings, :soap_transport => transport, :artifact_store => store)
          barrier.pop
          begin
            results << resolver.resolve(samlart)
          rescue StandardError => error
            results << error
          end
        end
      end
      2.times { barrier << true }
      threads.each(&:join)

      outcomes = 2.times.map { results.pop }
      valid_logins = outcomes.select { |o| o.is_a?(OneLogin::RubySaml::Response) && o.is_valid? }
      replays = outcomes.select { |o| o.is_a?(OneLogin::RubySaml::ArtifactReplayError) }

      assert_equal 1, valid_logins.size
      assert_equal 1, replays.size
    end

    it "forwards the matches_request_id option to the inner response validation" do
      resolver = build_resolver(
        resolver_settings,
        :soap_transport => idp_transport(valid_inner_response_xml),
        :matches_request_id => "_fc4a34b0-7efb-012e-caae-782bcb13bb38"
      )
      assert resolver.resolve(make_artifact).is_valid?

      other_resolver = build_resolver(
        resolver_settings,
        :soap_transport => idp_transport(valid_inner_response_xml),
        :matches_request_id => "_wrong_request_id"
      )
      refute other_resolver.resolve(make_artifact).is_valid?
    end

    it "resolves an ArtifactResponse without SOAP envelope" do
      resolver = build_resolver(
        resolver_settings,
        :soap_transport => idp_transport(valid_inner_response_xml, :soap => false)
      )

      assert resolver.resolve(make_artifact).is_valid?
    end

    it "raises ArtifactTransportError when the endpoint returns garbage and keeps the handle releasable" do
      store = OneLogin::RubySaml::ArtifactStore::Memory.new
      samlart = make_artifact
      garbage_transport = lambda { |_url, _envelope| "this is not xml" }
      resolver = build_resolver(resolver_settings, :soap_transport => garbage_transport, :artifact_store => store)

      assert_raises(OneLogin::RubySaml::ValidationError) { resolver.resolve(samlart) }
    end
  end
end
