require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ArtifactTest < Minitest::Test

  IDP_ENTITY_ID = "https://idp.example.com/saml/metadata".freeze

  describe "Artifact" do
    def build_artifact(source_id: Digest::SHA1.digest(IDP_ENTITY_ID), endpoint_index: 0, message_handle: "a" * 20, type_code: 0x0004)
      Base64.strict_encode64([type_code, endpoint_index].pack("nn") + source_id + message_handle)
    end

    it "parses a type 0x0004 artifact" do
      artifact = OneLogin::RubySaml::Artifact.parse(build_artifact(endpoint_index: 3))

      assert_equal 0x0004, artifact.type_code
      assert_equal 3, artifact.endpoint_index
      assert_equal Digest::SHA1.digest(IDP_ENTITY_ID), artifact.source_id
      assert_equal "a" * 20, artifact.message_handle
    end

    it "raises ArgumentError when the artifact is nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::Artifact.parse(nil) }
    end

    it "raises ValidationError when the artifact is not base64" do
      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::Artifact.parse("!!! not base64 !!!")
      end
    end

    it "raises ValidationError when the artifact has an unexpected size" do
      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::Artifact.parse(Base64.strict_encode64("too short"))
      end
    end

    it "raises ValidationError when the type code is not 0x0004" do
      error = assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::Artifact.parse(build_artifact(type_code: 0x0001))
      end
      assert_includes error.message, "0x0001"
    end

    it "computes the SourceID as the SHA-1 of the entityID" do
      assert_equal Digest::SHA1.digest(IDP_ENTITY_ID), OneLogin::RubySaml::Artifact.source_id_for(IDP_ENTITY_ID)
    end

    it "matches the SourceID against the IdP entityID" do
      artifact = OneLogin::RubySaml::Artifact.parse(build_artifact)

      assert artifact.source_id_matches?(IDP_ENTITY_ID)
      refute artifact.source_id_matches?("https://evil.example.com/idp")
      refute artifact.source_id_matches?(nil)
      refute artifact.source_id_matches?("")
    end
  end
end
