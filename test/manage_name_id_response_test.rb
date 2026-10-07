require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ManageNameIdResponseTest < Minitest::Test

  module ResponseHelpers
    def read_manage_name_id_fixture(name)
      File.read(File.join(File.dirname(__FILE__), "manage_name_id", name))
    end

    def settings
      @settings ||= begin
        settings = OneLogin::RubySaml::Settings.new
        settings.sp_entity_id = "https://sp.example.com/saml/metadata"
        settings.idp_entity_id = "https://idp.example.com/"
        settings.idp_manage_name_id_service_url = "https://idp.example.com/manage-name-id"
        settings.idp_cert = ruby_saml_cert_text
        settings
      end
    end

    def success_response_xml
      read_manage_name_id_fixture("manage_name_id_response_success.xml")
    end

    def build_response_xml(options = {})
    uuid = options[:id] || OneLogin::RubySaml::Utils.uuid
    doc = XMLSecurity::Document.new
    doc.uuid = uuid
    root = doc.add_element "samlp:ManageNameIDResponse", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol", "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
    root.attributes["ID"] = uuid
    root.attributes["Version"] = "2.0"
    root.attributes["IssueInstant"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    root.attributes["InResponseTo"] = options[:in_response_to] if options[:in_response_to]
    issuer = root.add_element "saml:Issuer"
    issuer.text = options[:issuer] || "https://idp.example.com/"
    status = root.add_element "samlp:Status"
    status_code = status.add_element "samlp:StatusCode"
    status_code.attributes["Value"] = options[:status_code] || "urn:oasis:names:tc:SAML:2.0:status:Success"
    doc.sign_document(ruby_saml_key, ruby_saml_cert, XMLSecurity::Document::RSA_SHA256, XMLSecurity::Document::SHA256) if options[:sign]
      xml = ""
      doc.write(xml)
      xml
    end
  end

  describe "parsing" do
    include ResponseHelpers

    it "parses a success response" do
      response = OneLogin::RubySaml::ManageNameIdResponse.new(success_response_xml, :settings => settings)

      assert response.success?
      assert_equal "urn:oasis:names:tc:SAML:2.0:status:Success", response.status_code
      assert_equal "_mnid-response-001", response.response_id
      assert_equal "_mnid-request-rename-001", response.in_response_to
      assert_equal "https://idp.example.com/", response.issuer
      assert response.validate
    end

    it "parses a base64 encoded response" do
      encoded = Base64.encode64(success_response_xml)
      response = OneLogin::RubySaml::ManageNameIdResponse.new(encoded, :settings => settings)

      assert response.success?
      assert response.validate
    end

    it "parses a response wrapped in a SOAP envelope" do
      envelope = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>#{success_response_xml}</soap:Body></soap:Envelope>"
      response = OneLogin::RubySaml::ManageNameIdResponse.new(envelope, :settings => settings)

      assert response.success?
      assert response.validate
    end

    it "parses the terminate success sample" do
      xml = read_manage_name_id_fixture("manage_name_id_response_terminate_success.xml")
      response = OneLogin::RubySaml::ManageNameIdResponse.new(xml, :settings => settings)

      assert response.success?
      assert_equal "NameID terminated", response.status_message
      assert_equal "_mnid-request-terminate-001", response.in_response_to
      assert response.validate
    end

    it "parses the duplicated delivery sample" do
      xml = read_manage_name_id_fixture("manage_name_id_response_duplicate.xml")
      response = OneLogin::RubySaml::ManageNameIdResponse.new(xml, :settings => settings)

      assert response.success?
      assert_equal "_mnid-request-rename-001", response.in_response_to
      assert response.validate
    end
  end

  describe "error status domain" do
    include ResponseHelpers

    it "exposes the status code and message of a denied response" do
      xml = read_manage_name_id_fixture("manage_name_id_response_requester_error.xml")
      response = OneLogin::RubySaml::ManageNameIdResponse.new(xml, :settings => settings)

      refute response.success?
      assert_equal "urn:oasis:names:tc:SAML:2.0:status:Requester", response.status_code
      assert_equal "The NameID is not known by the IdP", response.status_message

      refute response.validate
      assert_includes response.errors.first, "Requester"
    end
  end

  describe "impersonation guard" do
    include ResponseHelpers

    it "rejects a login Response document" do
      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::ManageNameIdResponse.new(response_document_unsigned, :settings => settings)
      end
    end

    it "rejects a LogoutResponse document" do
      logout_response = OneLogin::RubySaml::SloLogoutresponse.new
      doc = logout_response.create_xml_document(settings, "_mnid-request-rename-001")
      xml = ""
      doc.write(xml)

      assert_raises(OneLogin::RubySaml::ValidationError) do
        OneLogin::RubySaml::ManageNameIdResponse.new(xml, :settings => settings)
      end
    end

    it "rejects objects of the login and logout APIs" do
      logout_response = OneLogin::RubySaml::Logoutresponse.new(response_document_unsigned, settings)
      assert_raises(ArgumentError) do
        OneLogin::RubySaml::ManageNameIdResponse.new(logout_response, :settings => settings)
      end

      login_response = OneLogin::RubySaml::Response.new(response_document_unsigned)
      assert_raises(ArgumentError) do
        OneLogin::RubySaml::ManageNameIdResponse.new(login_response, :settings => settings)
      end
    end

    it "rejects a nil response" do
      assert_raises(ArgumentError) do
        OneLogin::RubySaml::ManageNameIdResponse.new(nil, :settings => settings)
      end
    end
  end

  describe "validation" do
    include ResponseHelpers

    it "validates the correlation ID" do
      response = OneLogin::RubySaml::ManageNameIdResponse.new(success_response_xml, :settings => settings, :matches_request_id => "_mnid-request-rename-001")
      assert response.validate

      mismatched = OneLogin::RubySaml::ManageNameIdResponse.new(success_response_xml, :settings => settings, :matches_request_id => "_other-request")
      refute mismatched.validate
      assert_includes mismatched.errors.first, "does not match the ID of the ManageNameID Request"
    end

    it "validates the peer issuer" do
      settings.idp_entity_id = "https://evil.example.com/"
      response = OneLogin::RubySaml::ManageNameIdResponse.new(success_response_xml, :settings => settings)

      refute response.validate
      assert_includes response.errors.first, "Doesn't match the issuer"
    end

    it "validates an embedded signature" do
      xml = build_response_xml(:in_response_to => "_mnid-request-rename-001", :sign => true)
      response = OneLogin::RubySaml::ManageNameIdResponse.new(xml, :settings => settings, :matches_request_id => "_mnid-request-rename-001")

      assert response.validate
    end

    it "rejects a tampered signature" do
      xml = build_response_xml(:in_response_to => "_mnid-request-rename-001", :sign => true)
      tampered = xml.sub("https://idp.example.com/", "https://evil.example.com/")
      settings.idp_entity_id = "https://evil.example.com/"
      response = OneLogin::RubySaml::ManageNameIdResponse.new(tampered, :settings => settings)

      refute response.validate
      assert_includes response.errors.join(", "), "Invalid Signature on ManageNameID Response"
    end

    it "requires a signature when want_manage_name_id_responses_signed is enabled" do
      settings.security[:want_manage_name_id_responses_signed] = true
      response = OneLogin::RubySaml::ManageNameIdResponse.new(success_response_xml, :settings => settings)

      refute response.validate
      assert_includes response.errors.join(", "), "Signature not found on ManageNameID Response"
    end
  end
end
