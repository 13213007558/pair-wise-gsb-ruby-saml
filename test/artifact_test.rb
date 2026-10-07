require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ArtifactTest < Minitest::Test
  describe "ArtifactBinding" do
    IDP_ENTITY_ID = "https://app.onelogin.com/saml2".freeze
    SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze
    DSIG = "http://www.w3.org/2000/09/xmldsig#".freeze

    def raw_artifact(handle = "handle-1234567890", endpoint_index = 0, entity_id = IDP_ENTITY_ID)
      OneLogin::RubySaml::Artifact.build(Digest::SHA1.digest(entity_id), handle, endpoint_index)
    end

    def encode_artifact(handle = "handle-1234567890", endpoint_index = 0, entity_id = IDP_ENTITY_ID)
      OneLogin::RubySaml::Artifact.encode(raw_artifact(handle, endpoint_index, entity_id))
    end

    def artifact_settings
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_entity_id = IDP_ENTITY_ID
      settings.sp_entity_id = "https://sp.example.com/saml"
      settings.idp_cert = ruby_saml_cert_text
      settings
    end

    def valid_inner_response_xml
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(Base64.decode64(response_document_valid_signed))
    end

    def build_artifact_response_xml(inner_xml, id: "_ar_#{SecureRandom.hex(8)}", issuer: IDP_ENTITY_ID,
                                    in_response_to: nil, status: SUCCESS, sign: true,
                                    signing_key: ruby_saml_key, signing_cert: ruby_saml_cert)
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

      doc.sign_document(signing_key, signing_cert) if sign

      xml = "".dup
      doc.write(xml)
      xml
    end

    def soap_wrap(xml)
      "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>#{xml}</soap:Body></soap:Envelope>"
    end

    describe "Artifact" do
      it "parses a type 0x0004 artifact" do
        artifact = OneLogin::RubySaml::Artifact.parse(encode_artifact("handle-abc", 3))

        assert_equal 0x0004, artifact.type_code
        assert_equal 3, artifact.endpoint_index
        assert_equal Digest::SHA1.digest(IDP_ENTITY_ID), artifact.source_id
        assert_equal "handle-abc", artifact.message_handle
      end

      it "matches the SourceID against the trusted IdP entityID" do
        artifact = OneLogin::RubySaml::Artifact.parse(encode_artifact)

        assert artifact.source_id_matches?(IDP_ENTITY_ID)
        refute artifact.source_id_matches?("https://evil.example.com/idp")
        refute artifact.source_id_matches?(nil)
        refute artifact.source_id_matches?("")
      end

      it "exposes a hex message handle key" do
        artifact = OneLogin::RubySaml::Artifact.parse(encode_artifact("handle-abc"))

        assert_equal "handle-abc".unpack1("H*"), artifact.message_handle_key
      end

      it "rejects a blank artifact" do
        assert_raises(OneLogin::RubySaml::ValidationError) { OneLogin::RubySaml::Artifact.parse(nil) }
        assert_raises(OneLogin::RubySaml::ValidationError) { OneLogin::RubySaml::Artifact.parse("") }
      end

      it "rejects a non base64 artifact" do
        assert_raises(OneLogin::RubySaml::ValidationError) { OneLogin::RubySaml::Artifact.parse("!!! not base64 !!!") }
      end

      it "rejects a truncated artifact" do
        truncated = Base64.strict_encode64([0x0004, 0].pack("nn") + Digest::SHA1.digest(IDP_ENTITY_ID))
        assert_raises(OneLogin::RubySaml::ValidationError) { OneLogin::RubySaml::Artifact.parse(truncated) }
      end

      it "rejects an unsupported artifact type" do
        other_type = Base64.strict_encode64([0x0003, 0].pack("nn") + Digest::SHA1.digest(IDP_ENTITY_ID) + "handle")
        error = assert_raises(OneLogin::RubySaml::ValidationError) { OneLogin::RubySaml::Artifact.parse(other_type) }
        assert_includes error.message, "0x0003"
      end

      it "does not treat the artifact content as a URL" do
        artifact = OneLogin::RubySaml::Artifact.parse(encode_artifact("https://evil.example.com/steal"))

        assert_equal "https://evil.example.com/steal", artifact.message_handle
        assert_equal 0x0004, artifact.type_code
      end
    end

    describe "ArtifactStore::Memory" do
      let(:store) { OneLogin::RubySaml::ArtifactStore::Memory.new }

      it "consumes a key only once" do
        assert store.consume("key")
        refute store.consume("key")
        assert store.consumed?("key")
      end

      it "releases a consumed key" do
        store.consume("key")
        store.release("key")

        refute store.consumed?("key")
        assert store.consume("key")
      end

      it "rejects concurrent duplicate consumption" do
        results = Queue.new
        threads = 8.times.map { Thread.new { results << store.consume("same-key") } }
        threads.each(&:join)

        outcomes = 8.times.map { results.pop }
        assert_equal 1, outcomes.count(true)
        assert_equal 7, outcomes.count(false)
      end
    end

    describe "ArtifactResolve" do
      let(:settings) { artifact_settings }
      let(:resolve) { OneLogin::RubySaml::ArtifactResolve.new }

      it "builds an ArtifactResolve request" do
        doc = resolve.create_xml_document(settings, "SAMLART123")

        assert_equal resolve.request_id, doc.root.attributes['ID']
        assert_equal "2.0", doc.root.attributes['Version']
        assert_equal "https://sp.example.com/saml", REXML::XPath.first(doc, "//saml:Issuer", { "saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }).text
        assert_equal "SAMLART123", REXML::XPath.first(doc, "//samlp:Artifact", { "samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }).text
      end

      it "wraps the request on a SOAP envelope" do
        envelope = resolve.create_soap_envelope(settings, "SAMLART123")

        assert_includes envelope, "soap:Envelope"
        assert_includes envelope, "samlp:ArtifactResolve"
        assert_includes envelope, "<samlp:Artifact>SAMLART123</samlp:Artifact>"
      end

      it "signs the request when authn_requests_signed and the SP owns a key pair" do
        settings.certificate = ruby_saml_cert_text
        settings.private_key = ruby_saml_key_text
        settings.security[:authn_requests_signed] = true

        doc = resolve.create_xml_document(settings, "SAMLART123")

        refute_nil REXML::XPath.first(doc, "//ds:Signature", { "ds" => DSIG })
      end

      it "does not sign the request by default" do
        doc = resolve.create_xml_document(settings, "SAMLART123")

        assert_nil REXML::XPath.first(doc, "//ds:Signature", { "ds" => DSIG })
      end
    end

    describe "ArtifactResponse" do
      let(:settings) { artifact_settings }

      it "is valid with a signed artifact response" do
        xml = build_artifact_response_xml(valid_inner_response_xml, in_response_to: "_resolve1")
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, :settings => settings, :matches_request_id => "_resolve1")

        assert artifact_response.is_valid?, artifact_response.errors.join(", ")
      end

      it "unwraps the SOAP envelope" do
        xml = soap_wrap(build_artifact_response_xml(valid_inner_response_xml, in_response_to: "_resolve1"))
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, :settings => settings, :matches_request_id => "_resolve1")

        assert artifact_response.is_valid?, artifact_response.errors.join(", ")
        assert_includes artifact_response.inner_response, "samlp:Response"
      end

      it "accepts an unsigned artifact response" do
        xml = build_artifact_response_xml(valid_inner_response_xml, sign: false)
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, :settings => settings)

        assert artifact_response.is_valid?, artifact_response.errors.join(", ")
      end

      it "rejects a mismatched InResponseTo" do
        xml = build_artifact_response_xml(valid_inner_response_xml, in_response_to: "_other")
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, :settings => settings, :matches_request_id => "_resolve1")

        refute artifact_response.is_valid?
        assert_includes artifact_response.errors.join(", "), "does not match the ID of the ArtifactResolve"
      end

      it "rejects a mismatched Issuer" do
        xml = build_artifact_response_xml(valid_inner_response_xml, issuer: "https://evil.example.com/idp")
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, :settings => settings)

        refute artifact_response.is_valid?
        assert_includes artifact_response.errors.join(", "), "Doesn't match the issuer"
      end

      it "rejects a non Success status" do
        xml = build_artifact_response_xml(valid_inner_response_xml, status: "urn:oasis:names:tc:SAML:2.0:status:Responder")
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, :settings => settings)

        refute artifact_response.is_valid?
        assert_includes artifact_response.errors.join(", "), "status code of the ArtifactResponse was not Success"
      end

      it "rejects an invalid signature" do
        other_cert, other_key = CertificateHelper.generate_pair
        xml = build_artifact_response_xml(valid_inner_response_xml, signing_key: other_key, signing_cert: other_cert)
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, :settings => settings)

        refute artifact_response.is_valid?
        assert_includes artifact_response.errors.join(", "), "Invalid Signature on SAML ArtifactResponse"
      end

      it "rejects a tampered signed artifact response" do
        xml = build_artifact_response_xml(valid_inner_response_xml)
        tampered = xml.sub("https://app.onelogin.com/saml2", "https://app.onelogin.com/saml2/tampered")
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(tampered, :settings => settings)

        refute artifact_response.is_valid?
      end

      it "rejects an artifact response without inner response" do
        xml = build_artifact_response_xml(nil)
        artifact_response = OneLogin::RubySaml::ArtifactResponse.new(xml, :settings => settings)

        refute artifact_response.is_valid?
        assert_includes artifact_response.errors.join(", "), "must contain 1 inner Response"
      end

      it "raises when initialized with nil" do
        assert_raises(ArgumentError) { OneLogin::RubySaml::ArtifactResponse.new(nil) }
      end

      it "raises a ValidationError when the body is blank" do
        assert_raises(OneLogin::RubySaml::ValidationError) { OneLogin::RubySaml::ArtifactResponse.new("") }
      end

      it "raises a ValidationError when the body is not XML" do
        assert_raises(OneLogin::RubySaml::ValidationError) { OneLogin::RubySaml::ArtifactResponse.new("this is not xml") }
      end

      it "raises a ValidationError when the SOAP envelope carries no ArtifactResponse" do
        envelope = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body/></soap:Envelope>"
        assert_raises(OneLogin::RubySaml::ValidationError) { OneLogin::RubySaml::ArtifactResponse.new(envelope) }
      end
    end

    describe "IdpMetadataParser ArtifactResolutionService parsing" do
      let(:metadata_with_artifact_services) do
        <<-XML
  <md:EntityDescriptor entityID="https://idp.example.com/metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/ars/0" index="0"/>
      <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/ars/1" index="1" isDefault="true"/>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
        XML
      end

      it "parses the artifact resolution services into settings" do
        settings = OneLogin::RubySaml::IdpMetadataParser.new.parse(metadata_with_artifact_services)

        services = settings.idp_artifact_resolution_services
        assert_equal 2, services.size
        assert_equal 0, services[0][:index]
        assert_equal "https://idp.example.com/ars/0", services[0][:location]
        assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", services[0][:binding]
        assert_equal 1, services[1][:index]
      end

      it "selects the default artifact resolution service url" do
        settings = OneLogin::RubySaml::IdpMetadataParser.new.parse(metadata_with_artifact_services)

        assert_equal "https://idp.example.com/ars/1", settings.idp_artifact_resolution_service_url
      end

      it "falls back to the first service when none is flagged as default" do
        settings = OneLogin::RubySaml::IdpMetadataParser.new.parse(metadata_with_artifact_services.sub(' isDefault="true"', ""))

        assert_equal "https://idp.example.com/ars/0", settings.idp_artifact_resolution_service_url
      end

      it "returns nil when no artifact resolution service is published" do
        settings = OneLogin::RubySaml::IdpMetadataParser.new.parse(idp_metadata_descriptor)

        assert_nil settings.idp_artifact_resolution_service_url
        assert_empty settings.idp_artifact_resolution_services
      end
    end
  end
end
