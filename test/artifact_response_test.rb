require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ArtifactResponseTest < Minitest::Test

  RESOLVE_REQUEST_ID = "_resolve_request_1".freeze

  describe "ArtifactResponse" do
    def settings
      @settings ||= begin
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_entity_id = ArtifactFixtureHelper::IDP_ENTITY_ID
        settings.sp_entity_id = ArtifactFixtureHelper::SP_ENTITY_ID
        settings.assertion_consumer_service_url = ArtifactFixtureHelper::ACS_URL
        settings.idp_cert = ruby_saml_cert_text
        settings
      end
    end

    def artifact_response_xml(options = {})
      inner = ArtifactFixtureHelper.build_inner_response_xml(ruby_saml_cert, ruby_saml_key)
      ArtifactFixtureHelper.build_artifact_response_xml(
        inner,
        ruby_saml_cert,
        ruby_saml_key,
        **{ :in_response_to => RESOLVE_REQUEST_ID }.merge(options)
      )
    end

    it "raises ArgumentError when the response is nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::ArtifactResponse.new(nil) }
    end

    it "parses a bare ArtifactResponse" do
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(artifact_response_xml, settings)

      assert_equal RESOLVE_REQUEST_ID, artifact_response.in_response_to
      assert_equal ArtifactFixtureHelper::IDP_ENTITY_ID, artifact_response.issuer
      assert artifact_response.success?
      assert artifact_response.is_valid?
    end

    it "parses an ArtifactResponse wrapped in a SOAP envelope" do
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(
        ArtifactFixtureHelper.wrap_soap(artifact_response_xml),
        settings
      )

      assert artifact_response.is_valid?
      assert_equal ArtifactFixtureHelper::IDP_ENTITY_ID, artifact_response.issuer
    end

    it "extracts the enclosed protocol message" do
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(artifact_response_xml, settings)
      message = artifact_response.protocol_message_xml

      assert_includes message, "Response"
      response = OneLogin::RubySaml::Response.new(message, :settings => settings)
      assert_equal "user@example.com", response.name_id
    end

    it "rejects an ArtifactResponse that is not correlated with the ArtifactResolve" do
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(
        artifact_response_xml,
        settings,
        :matches_request_id => "_another_resolve_id"
      )

      refute artifact_response.is_valid?
      assert_includes artifact_response.errors.join(", "), "does not match the ID of the ArtifactResolve"
    end

    it "accepts an ArtifactResponse correlated with the ArtifactResolve" do
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(
        artifact_response_xml,
        settings,
        :matches_request_id => RESOLVE_REQUEST_ID
      )

      assert artifact_response.is_valid?
    end

    it "rejects an ArtifactResponse with a non Success status" do
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(
        artifact_response_xml(:status_value => "urn:oasis:names:tc:SAML:2.0:status:Requester"),
        settings
      )

      refute artifact_response.is_valid?
      assert_includes artifact_response.errors.join(", "), "status code of the ArtifactResponse was not Success"
    end

    it "rejects an ArtifactResponse without protocol message" do
      xml = ArtifactFixtureHelper.build_artifact_response_xml(
        nil, ruby_saml_cert, ruby_saml_key, :in_response_to => RESOLVE_REQUEST_ID
      )
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, settings)

      refute artifact_response.is_valid?
      assert_includes artifact_response.errors.join(", "), "does not contain a protocol message"
    end

    it "rejects an ArtifactResponse signed with an unknown key" do
      other_cert, other_key = CertificateHelper.generate_pair
      inner = ArtifactFixtureHelper.build_inner_response_xml(ruby_saml_cert, ruby_saml_key)
      xml = ArtifactFixtureHelper.build_artifact_response_xml(
        inner, other_cert, other_key, :in_response_to => RESOLVE_REQUEST_ID
      )
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, settings)

      refute artifact_response.is_valid?
      assert_includes artifact_response.errors.join(", "), "Invalid Signature on ArtifactResponse"
    end

    it "rejects a tampered ArtifactResponse" do
      xml = artifact_response_xml.gsub("user@example.com", "attacker@example.com")
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, settings)

      refute artifact_response.is_valid?
    end

    it "rejects an unsigned ArtifactResponse when the SP requires a signed one" do
      settings.security[:want_artifact_response_signed] = true
      inner = ArtifactFixtureHelper.build_inner_response_xml(ruby_saml_cert, ruby_saml_key)
      xml = ArtifactFixtureHelper.build_artifact_response_xml(
        inner, ruby_saml_cert, ruby_saml_key, :in_response_to => RESOLVE_REQUEST_ID, :sign => false
      )
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, settings)

      refute artifact_response.is_valid?
      assert_includes artifact_response.errors.join(", "), "not signed"
    end

    it "accepts an unsigned ArtifactResponse when a signature is not required" do
      inner = ArtifactFixtureHelper.build_inner_response_xml(ruby_saml_cert, ruby_saml_key)
      xml = ArtifactFixtureHelper.build_artifact_response_xml(
        inner, ruby_saml_cert, ruby_saml_key, :in_response_to => RESOLVE_REQUEST_ID, :sign => false
      )
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, settings)

      assert artifact_response.is_valid?
    end

    it "rejects an ArtifactResponse from an unexpected issuer" do
      settings.idp_entity_id = "https://other-idp.example.com/metadata"
      artifact_response = OneLogin::RubySaml::ArtifactResponse.new(artifact_response_xml, settings)

      refute artifact_response.is_valid?
      assert_includes artifact_response.errors.join(", "), "match the issuer"
    end

    it "raises ValidationError on malformed XML" do
      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::ArtifactResponse.new("<samlp:ArtifactResponse", settings)
      end
    end
  end
end
