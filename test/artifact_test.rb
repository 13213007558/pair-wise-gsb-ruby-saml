require 'test_helper'

class ArtifactTest < Minitest::Test
  include ArtifactHelper

  describe "Artifact.parse" do
    it "parses a type 0x0004 artifact" do
      samlart = build_artifact(endpoint_index: 3)
      artifact = OneLogin::RubySaml::Artifact.parse(samlart)

      assert_equal 3, artifact.endpoint_index
      assert_equal 20, artifact.source_id.bytesize
      assert_equal 20, artifact.message_handle.bytesize
      assert_equal samlart, artifact.to_s
    end

    it "accepts urlsafe base64" do
      artifact = OneLogin::RubySaml::Artifact.parse(build_artifact.tr('+/', '-_'))
      assert_equal 0, artifact.endpoint_index
    end

    it "matches the SourceID against the trusted IdP entityID" do
      artifact = OneLogin::RubySaml::Artifact.parse(build_artifact)

      assert artifact.source_id_matches?(ArtifactHelper::IDP_ENTITY_ID)
      refute artifact.source_id_matches?("https://evil.example.com")
    end

    it "exposes a stable cache key" do
      samlart = build_artifact
      assert_equal OneLogin::RubySaml::Artifact.parse(samlart).cache_key,
                   OneLogin::RubySaml::Artifact.parse(samlart).cache_key
      refute_equal OneLogin::RubySaml::Artifact.parse(samlart).cache_key,
                   OneLogin::RubySaml::Artifact.parse(build_artifact).cache_key
    end

    it "rejects a missing artifact" do
      assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        OneLogin::RubySaml::Artifact.parse(nil)
      end
      assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        OneLogin::RubySaml::Artifact.parse("")
      end
    end

    it "rejects non base64 content" do
      assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        OneLogin::RubySaml::Artifact.parse("not valid base64!!!")
      end
    end

    it "rejects artifacts with an invalid length" do
      assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        OneLogin::RubySaml::Artifact.parse(Base64.strict_encode64("too short"))
      end
    end

    it "rejects artifacts of a different type" do
      raw = [0x0003, 0].pack('n2') + SecureRandom.random_bytes(40)
      error = assert_raises(OneLogin::RubySaml::ArtifactResolutionError) do
        OneLogin::RubySaml::Artifact.parse(Base64.strict_encode64(raw))
      end
      assert_match(/0x0003/, error.message)
    end
  end

  describe "InMemoryArtifactStore" do
    let(:store) { OneLogin::RubySaml::InMemoryArtifactStore.new }

    it "acquires a key only once until released or committed" do
      assert store.acquire("key")
      refute store.acquire("key")
      refute store.consumed?("key")

      store.release("key")
      assert store.acquire("key")

      store.commit("key")
      refute store.acquire("key")
      assert store.consumed?("key")
    end

    it "allows only one concurrent acquisition of the same key" do
      results = Queue.new
      threads = 8.times.map do
        Thread.new { results << store.acquire("key") }
      end
      threads.each(&:join)

      wins = 8.times.map { results.pop }.count(true)
      assert_equal 1, wins
    end
  end

  describe "ArtifactResolve" do
    let(:settings) { artifact_settings(nil) }
    let(:artifact) { OneLogin::RubySaml::Artifact.parse(build_artifact(endpoint_index: 1)) }

    it "builds an ArtifactResolve request embedding the artifact" do
      resolve = OneLogin::RubySaml::ArtifactResolve.new(settings, artifact)
      document = REXML::Document.new(resolve.to_xml)

      root = document.root
      assert_equal "ArtifactResolve", root.name
      assert_equal resolve.uuid, root.attributes["ID"]
      assert_equal "2.0", root.attributes["Version"]

      issuer = REXML::XPath.first(document, "//saml:Issuer", "saml" => ArtifactHelper::SAML)
      assert_equal ArtifactHelper::SP_ENTITY_ID, issuer.text

      artifact_node = REXML::XPath.first(document, "//samlp:Artifact", "samlp" => ArtifactHelper::SAMLP)
      assert_equal artifact.to_s, artifact_node.text
    end

    it "wraps the request in a SOAP envelope" do
      resolve = OneLogin::RubySaml::ArtifactResolve.new(settings, artifact)
      document = REXML::Document.new(resolve.to_soap)

      body = REXML::XPath.first(document, "/soap-env:Envelope/soap-env:Body", "soap-env" => ArtifactHelper::SOAP_ENV)
      refute_nil body
      assert_equal resolve.uuid, resolve_id_from(resolve.to_soap)
    end

    it "signs the request when authn_requests_signed is enabled" do
      pair = CertificateHelper.generate_pair_hash
      signed_settings = artifact_settings(nil)
      signed_settings.certificate = pair[:certificate]
      signed_settings.private_key = pair[:private_key]
      signed_settings.security[:authn_requests_signed] = true

      resolve = OneLogin::RubySaml::ArtifactResolve.new(signed_settings, artifact)
      document = REXML::Document.new(resolve.to_xml)

      signature = REXML::XPath.first(document, "//ds:Signature", "ds" => "http://www.w3.org/2000/09/xmldsig#")
      refute_nil signature
    end
  end
end
