require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ArtifactResolverTest < Minitest::Test

  # Transport injected on the resolver. Captures the requests and builds the
  # ArtifactResponse correlated with the received ArtifactResolve.
  class FakeArtifactTransport
    PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol".freeze

    attr_reader :requests

    def initialize(&responder)
      @responder = responder
      @requests = []
    end

    def call(url, body)
      @requests << [url, body]
      resolve_id = REXML::XPath.first(
        REXML::Document.new(body),
        "//p:ArtifactResolve",
        { "p" => PROTOCOL }
      ).attributes['ID']
      @responder.call(resolve_id)
    end
  end

  # Caller-provided store that blocks artifact reuse.
  class FakeArtifactStore
    def initialize
      @consumed = []
    end

    def consume(artifact)
      return false if @consumed.include?(artifact)

      @consumed << artifact
      true
    end
  end

  describe "ArtifactResolver" do
    def settings
      @settings ||= begin
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_entity_id = ArtifactFixtureHelper::IDP_ENTITY_ID
        settings.sp_entity_id = ArtifactFixtureHelper::SP_ENTITY_ID
        settings.assertion_consumer_service_url = ArtifactFixtureHelper::ACS_URL
        settings.idp_cert = ruby_saml_cert_text
        settings.idp_artifact_resolution_services = [
          { :index => 0, :binding => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", :url => ArtifactFixtureHelper::ARTIFACT_RESOLUTION_URL },
          { :index => 1, :binding => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", :url => "https://idp.example.com/saml/ars/1" }
        ]
        settings
      end
    end

    def artifact(options = {})
      ArtifactFixtureHelper.build_artifact(**options)
    end

    def soap_responder(&inner_builder)
      lambda do |resolve_id|
        inner = ArtifactFixtureHelper.build_inner_response_xml(ruby_saml_cert, ruby_saml_key)
        inner = inner_builder.call(inner) if inner_builder
        ArtifactFixtureHelper.wrap_soap(
          ArtifactFixtureHelper.build_artifact_response_xml(
            inner, ruby_saml_cert, ruby_saml_key, :in_response_to => resolve_id
          )
        )
      end
    end

    def build_resolver(transport, store = FakeArtifactStore.new, the_settings = settings)
      OneLogin::RubySaml::ArtifactResolver.new(
        the_settings,
        :transport => transport,
        :artifact_store => store
      )
    end

    it "requires a transport" do
      error = assert_raises(ArgumentError) do
        OneLogin::RubySaml::ArtifactResolver.new(settings, :artifact_store => FakeArtifactStore.new)
      end
      assert_includes error.message, "transport"
    end

    it "requires an artifact store" do
      error = assert_raises(ArgumentError) do
        OneLogin::RubySaml::ArtifactResolver.new(settings, :transport => FakeArtifactTransport.new { "" })
      end
      assert_includes error.message, "artifact_store"
    end

    it "resolves an artifact into a valid SAML Response" do
      transport = FakeArtifactTransport.new(&soap_responder)
      resolver = build_resolver(transport)

      response = resolver.resolve(artifact, :matches_request_id => ArtifactFixtureHelper::AUTHN_REQUEST_ID)

      assert response.is_a?(OneLogin::RubySaml::Response)
      assert_equal "user@example.com", response.name_id
    end

    it "sends the ArtifactResolve to the endpoint declared in the metadata, not derived from the artifact" do
      transport = FakeArtifactTransport.new(&soap_responder)
      resolver = build_resolver(transport)

      resolver.resolve(artifact(:endpoint_index => 1))

      assert_equal 1, transport.requests.size
      assert_equal "https://idp.example.com/saml/ars/1", transport.requests.first[0]
    end

    it "sends the artifact and the SP issuer on the ArtifactResolve" do
      transport = FakeArtifactTransport.new(&soap_responder)
      resolver = build_resolver(transport)
      samlart = artifact

      resolver.resolve(samlart)

      envelope = transport.requests.first[1]
      assert_includes envelope, "<samlp:Artifact>#{samlart}</samlp:Artifact>"
      assert_includes envelope, "<saml:Issuer>#{ArtifactFixtureHelper::SP_ENTITY_ID}</saml:Issuer>"
    end

    it "signs the ArtifactResolve when the SP signs its requests" do
      settings.security[:authn_requests_signed] = true
      settings.certificate = ruby_saml_cert_text
      settings.private_key = ruby_saml_key_text
      transport = FakeArtifactTransport.new(&soap_responder)
      resolver = build_resolver(transport)

      resolver.resolve(artifact)

      assert_includes transport.requests.first[1], "Signature"
    end

    it "rejects an artifact that was already consumed" do
      transport = FakeArtifactTransport.new(&soap_responder)
      store = FakeArtifactStore.new
      resolver = build_resolver(transport, store)
      samlart = artifact

      resolver.resolve(samlart)
      error = assert_raises(OneLogin::RubySaml::ValidationError) { resolver.resolve(samlart) }

      assert_includes error.message, "already consumed"
      assert_equal 1, transport.requests.size
    end

    it "rejects an artifact whose SourceID does not match the IdP entityID" do
      transport = FakeArtifactTransport.new(&soap_responder)
      resolver = build_resolver(transport)

      error = assert_raises(OneLogin::RubySaml::ValidationError) do
        resolver.resolve(artifact(:entity_id => "https://evil.example.com/idp"))
      end

      assert_includes error.message, "SourceID"
      assert_equal 0, transport.requests.size
    end

    it "rejects an artifact when no idp_entity_id is available to check the SourceID" do
      settings.idp_entity_id = nil
      transport = FakeArtifactTransport.new(&soap_responder)
      resolver = build_resolver(transport)

      error = assert_raises(OneLogin::RubySaml::ValidationError) { resolver.resolve(artifact) }

      assert_includes error.message, "SourceID"
    end

    it "rejects an artifact with an unknown endpoint index" do
      transport = FakeArtifactTransport.new(&soap_responder)
      resolver = build_resolver(transport)

      error = assert_raises(OneLogin::RubySaml::ValidationError) do
        resolver.resolve(artifact(:endpoint_index => 9))
      end

      assert_includes error.message, "endpoint index 9"
      assert_equal 0, transport.requests.size
    end

    it "rejects an ArtifactResponse not correlated with the ArtifactResolve" do
      transport = FakeArtifactTransport.new do |_resolve_id|
        inner = ArtifactFixtureHelper.build_inner_response_xml(ruby_saml_cert, ruby_saml_key)
        ArtifactFixtureHelper.wrap_soap(
          ArtifactFixtureHelper.build_artifact_response_xml(
            inner, ruby_saml_cert, ruby_saml_key, :in_response_to => "_bogus_resolve_id"
          )
        )
      end
      resolver = build_resolver(transport)

      error = assert_raises(OneLogin::RubySaml::ValidationError) { resolver.resolve(artifact) }

      assert_includes error.message, "does not match the ID of the ArtifactResolve"
    end

    it "rejects an ArtifactResponse with an invalid outer signature" do
      other_cert, other_key = CertificateHelper.generate_pair
      transport = FakeArtifactTransport.new do |resolve_id|
        inner = ArtifactFixtureHelper.build_inner_response_xml(ruby_saml_cert, ruby_saml_key)
        ArtifactFixtureHelper.wrap_soap(
          ArtifactFixtureHelper.build_artifact_response_xml(
            inner, other_cert, other_key, :in_response_to => resolve_id
          )
        )
      end
      resolver = build_resolver(transport)

      error = assert_raises(OneLogin::RubySaml::ValidationError) { resolver.resolve(artifact) }

      assert_includes error.message, "Invalid ArtifactResponse"
    end

    it "rejects a response whose inner correlation is wrong even when the outer signature is valid" do
      transport = FakeArtifactTransport.new do |resolve_id|
        inner = ArtifactFixtureHelper.build_inner_response_xml(
          ruby_saml_cert, ruby_saml_key, :in_response_to => "_unexpected_authn_request"
        )
        ArtifactFixtureHelper.wrap_soap(
          ArtifactFixtureHelper.build_artifact_response_xml(
            inner, ruby_saml_cert, ruby_saml_key, :in_response_to => resolve_id
          )
        )
      end
      resolver = build_resolver(transport)

      error = assert_raises(OneLogin::RubySaml::ValidationError) do
        resolver.resolve(artifact, :matches_request_id => ArtifactFixtureHelper::AUTHN_REQUEST_ID)
      end

      assert_includes error.message, "does not match the ID of the AuthNRequest"
    end

    it "reads the ArtifactResolutionService endpoints from the IdP metadata" do
      metadata = File.read(File.join(File.dirname(__FILE__), "metadata", "idp_descriptor_artifact.xml"))
      parsed_settings = OneLogin::RubySaml::IdpMetadataParser.new.parse(metadata)

      services = parsed_settings.idp_artifact_resolution_services
      assert_equal 2, services.size
      assert_equal 0, services[0][:index]
      assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", services[0][:binding]
      assert_equal "https://idp.example.com/saml/ars", services[0][:url]
      assert services[0][:is_default]
      assert_equal 1, services[1][:index]
      assert_equal "https://idp.example.com/saml/ars/1", parsed_settings.artifact_resolution_service_for(1)[:url]
      assert_nil parsed_settings.artifact_resolution_service_for(7)
    end

    it "resolves an artifact with the settings parsed from the IdP metadata" do
      metadata = File.read(File.join(File.dirname(__FILE__), "metadata", "idp_descriptor_artifact.xml"))
      parsed_settings = OneLogin::RubySaml::IdpMetadataParser.new.parse(metadata)
      parsed_settings.sp_entity_id = ArtifactFixtureHelper::SP_ENTITY_ID
      parsed_settings.assertion_consumer_service_url = ArtifactFixtureHelper::ACS_URL
      parsed_settings.idp_cert = ruby_saml_cert_text

      transport = FakeArtifactTransport.new(&soap_responder)
      resolver = build_resolver(transport, FakeArtifactStore.new, parsed_settings)

      response = resolver.resolve(artifact(:endpoint_index => 1))

      assert_equal "user@example.com", response.name_id
      assert_equal "https://idp.example.com/saml/ars/1", transport.requests.first[0]
    end
  end
end
