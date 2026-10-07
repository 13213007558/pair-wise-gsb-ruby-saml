require 'test_helper'

class ArtifactReceiverTest < Minitest::Test
  describe "ArtifactReceiver" do
  let(:idp_cert_pair) { CertificateHelper.generate_pair }
  let(:idp_cert) { idp_cert_pair[0] }
  let(:idp_key) { idp_cert_pair[1] }
  let(:settings) { artifact_settings(idp_cert) }
  let(:store) { OneLogin::RubySaml::InMemoryArtifactStore.new }
  let(:samlart) { build_artifact }

  def good_transport(inner_xml)
    ArtifactHelper::FakeTransport.new do |_url, soap|
      build_artifact_response_soap(idp_cert, idp_key, resolve_id: resolve_id_from(soap), inner_xml: inner_xml)
    end
  end

  def resolve_with(transport, artifact_string = samlart, options = {})
    OneLogin::RubySaml::ArtifactReceiver.new(settings, transport: transport, store: store).resolve(artifact_string, options)
  end

  describe "successful resolution" do
    it "returns the validated inner SAML Response" do
      inner_xml = build_inner_response_xml(idp_cert, idp_key, name_id: "jane@example.com")
      response = resolve_with(good_transport(inner_xml))

      assert_kind_of OneLogin::RubySaml::Response, response
      assert_equal "jane@example.com", response.name_id
      assert response.is_valid?
    end

    it "posts a SOAP ArtifactResolve to the endpoint selected by the EndpointIndex" do
      transport = good_transport(build_inner_response_xml(idp_cert, idp_key))
      resolve_with(transport, build_artifact(endpoint_index: 1))

      assert_equal 1, transport.requests.size
      url, soap = transport.requests.first
      assert_equal ArtifactHelper::ARTIFACT_ENDPOINT_1, url
      refute_nil resolve_id_from(soap)
    end

    it "marks the artifact as consumed" do
      resolve_with(good_transport(build_inner_response_xml(idp_cert, idp_key)))

      artifact = OneLogin::RubySaml::Artifact.parse(samlart)
      assert store.consumed?(artifact.cache_key)
    end
  end

  describe "artifact and endpoint checks" do
    it "rejects an artifact whose SourceID does not match the trusted IdP" do
      transport = good_transport(build_inner_response_xml(idp_cert, idp_key))
      evil = build_artifact(source_id: Digest::SHA1.digest("https://evil.example.com"))

      assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        resolve_with(transport, evil)
      end
      assert_equal 0, transport.requests.size
    end

    it "rejects an artifact with an unknown EndpointIndex" do
      transport = good_transport(build_inner_response_xml(idp_cert, idp_key))

      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        resolve_with(transport, build_artifact(endpoint_index: 7))
      end
      assert_match(/index 7/, error.message)
      assert_equal 0, transport.requests.size
    end

    it "falls back to idp_artifact_resolution_service_url when no services are indexed" do
      settings.idp_artifact_resolution_services = nil
      settings.idp_artifact_resolution_service_url = ArtifactHelper::ARTIFACT_ENDPOINT_0
      transport = good_transport(build_inner_response_xml(idp_cert, idp_key))

      resolve_with(transport)
      assert_equal ArtifactHelper::ARTIFACT_ENDPOINT_0, transport.requests.first[0]
    end

    it "fails when no resolution endpoint is configured" do
      settings.idp_artifact_resolution_services = nil
      assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        resolve_with(good_transport(build_inner_response_xml(idp_cert, idp_key)))
      end
    end
  end

  describe "ArtifactResponse validation" do
    let(:inner_xml) { build_inner_response_xml(idp_cert, idp_key) }

    it "rejects a mismatched InResponseTo" do
      transport = ArtifactHelper::FakeTransport.new do |_url, _soap|
        build_artifact_response_soap(idp_cert, idp_key, resolve_id: "unused", inner_xml: inner_xml,
                                     overrides: { in_response_to: "_bogus" })
      end

      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) { resolve_with(transport) }
      assert_match(/InResponseTo/, error.message)
    end

    it "rejects an unexpected Issuer" do
      transport = ArtifactHelper::FakeTransport.new do |_url, soap|
        build_artifact_response_soap(idp_cert, idp_key, resolve_id: resolve_id_from(soap), inner_xml: inner_xml,
                                     overrides: { issuer: "https://evil.example.com" })
      end

      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) { resolve_with(transport) }
      assert_match(/issuer/, error.message)
    end

    it "rejects a non-success status" do
      transport = ArtifactHelper::FakeTransport.new do |_url, soap|
        build_artifact_response_soap(idp_cert, idp_key, resolve_id: resolve_id_from(soap), inner_xml: inner_xml,
                                     overrides: { status: "urn:oasis:names:tc:SAML:2.0:status:Requester",
                                                  status_message: "broken" })
      end

      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) { resolve_with(transport) }
      assert_match(/not Success/, error.message)
    end

    it "rejects an invalid signature" do
      _other_cert, other_key = CertificateHelper.generate_pair
      transport = ArtifactHelper::FakeTransport.new do |_url, soap|
        build_artifact_response_soap(idp_cert, other_key, resolve_id: resolve_id_from(soap), inner_xml: inner_xml)
      end

      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) { resolve_with(transport) }
      assert_match(/Signature/, error.message)
    end

    it "requires a signature when want_artifact_response_signed is enabled" do
      settings.security[:want_artifact_response_signed] = true
      transport = ArtifactHelper::FakeTransport.new do |_url, soap|
        build_artifact_response_soap(idp_cert, idp_key, resolve_id: resolve_id_from(soap), inner_xml: inner_xml,
                                     overrides: { sign: false })
      end

      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) { resolve_with(transport) }
      assert_match(/not signed/, error.message)
    end

    it "rejects an ArtifactResponse without inner message" do
      transport = ArtifactHelper::FakeTransport.new do |_url, soap|
        build_artifact_response_soap(idp_cert, idp_key, resolve_id: resolve_id_from(soap), inner_xml: "")
      end

      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) { resolve_with(transport) }
      assert_match(/did not carry a SAML message/, error.message)
    end
  end

  describe "inner response validation" do
    it "rejects a valid ArtifactResponse wrapping an invalid inner assertion" do
      expired_inner = build_inner_response_xml(idp_cert, idp_key, not_on_or_after: Time.now.utc - 3600)
      transport = good_transport(expired_inner)

      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) { resolve_with(transport) }
      assert_match(/invalid/, error.message)

      # A resolved-but-invalid artifact is spent: no automatic retry.
      assert_raises(OneLogin::RubySaml::ArtifactReplayError) { resolve_with(transport) }
    end

    it "rejects an inner response signed by an untrusted key" do
      other_cert, other_key = CertificateHelper.generate_pair
      evil_inner = build_inner_response_xml(other_cert, other_key)

      assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        resolve_with(good_transport(evil_inner))
      end
    end
  end

  describe "transport failures" do
    it "raises ArtifactTransportError and allows a later retry" do
      calls = 0
      inner_xml = build_inner_response_xml(idp_cert, idp_key)
      transport = ArtifactHelper::FakeTransport.new do |_url, soap|
        calls += 1
        raise OneLogin::RubySaml::ArtifactTransportError, "connection refused" if calls == 1

        build_artifact_response_soap(idp_cert, idp_key, resolve_id: resolve_id_from(soap), inner_xml: inner_xml)
      end

      assert_raises(OneLogin::RubySaml::ArtifactTransportError) { resolve_with(transport) }

      artifact = OneLogin::RubySaml::Artifact.parse(samlart)
      refute store.consumed?(artifact.cache_key)

      response = resolve_with(transport)
      assert_equal "user@example.com", response.name_id
    end
  end

  describe "single-use semantics" do
    it "rejects resolving the same artifact twice" do
      transport = good_transport(build_inner_response_xml(idp_cert, idp_key))
      resolve_with(transport)

      assert_raises(OneLogin::RubySaml::ArtifactReplayError) { resolve_with(transport) }
      assert_equal 1, transport.requests.size
    end

    it "rejects concurrent resolution of the same artifact" do
      inner_xml = build_inner_response_xml(idp_cert, idp_key)
      started = Queue.new
      proceed = Queue.new
      transport = ArtifactHelper::FakeTransport.new do |_url, soap|
        started << true
        proceed.pop
        build_artifact_response_soap(idp_cert, idp_key, resolve_id: resolve_id_from(soap), inner_xml: inner_xml)
      end
      receiver = OneLogin::RubySaml::ArtifactReceiver.new(settings, transport: transport, store: store)

      outcomes = Queue.new
      first = Thread.new do
        outcomes << begin
          receiver.resolve(samlart)
          :resolved
        rescue OneLogin::RubySaml::ArtifactError => e
          e.class
        end
      end
      started.pop # first thread is now resolving inside the transport

      second = Thread.new do
        outcomes << begin
          receiver.resolve(samlart)
          :resolved
        rescue OneLogin::RubySaml::ArtifactError => e
          e.class
        end
      end

      second.join
      proceed << true
      first.join

      results = [outcomes.pop, outcomes.pop]
      assert_equal 1, results.count(:resolved)
      assert_equal 1, results.count(OneLogin::RubySaml::ArtifactReplayError)
      assert_equal 1, transport.requests.size
    end
  end

  describe "IdP metadata integration" do
    it "parses ArtifactResolutionService endpoints from IdP metadata" do
      metadata = <<~XML
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="#{ArtifactHelper::IDP_ENTITY_ID}">
          <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="#{ArtifactHelper::ARTIFACT_ENDPOINT_0}" index="0"/>
            <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="#{ArtifactHelper::ARTIFACT_ENDPOINT_1}" index="1"/>
            <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>
      XML

      parsed = OneLogin::RubySaml::IdpMetadataParser.new.parse(metadata)
      assert_equal(
        { 0 => ArtifactHelper::ARTIFACT_ENDPOINT_0, 1 => ArtifactHelper::ARTIFACT_ENDPOINT_1 },
        parsed.idp_artifact_resolution_services
      )
    end
  end
  end
end
