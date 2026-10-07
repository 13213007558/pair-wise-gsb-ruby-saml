require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ManageNameIdRequestTest < Minitest::Test

  module RequestHelpers
    def read_manage_name_id_fixture(name)
      File.read(File.join(File.dirname(__FILE__), "manage_name_id", name))
    end

    def settings
      @settings ||= begin
        settings = OneLogin::RubySaml::Settings.new
        settings.sp_entity_id = "https://sp.example.com/saml/metadata"
        settings.idp_entity_id = "https://idp.example.com/"
        settings.idp_manage_name_id_service_url = "https://idp.example.com/manage-name-id"
        settings
      end
    end

    def old_identifier
      OneLogin::RubySaml::NameIdentifier.new(
        "old.user@example.com",
        :format => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        :name_qualifier => "https://idp.example.com/",
        :sp_name_qualifier => "https://sp.example.com/saml/metadata"
      )
    end
  end

  describe "NameIdentifier" do
    it "requires a value" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::NameIdentifier.new(nil) }
    end

    it "treats Format, NameQualifier and SPNameQualifier as part of the identity" do
      base = OneLogin::RubySaml::NameIdentifier.new("user", :format => "f", :name_qualifier => "nq", :sp_name_qualifier => "spq")
      assert_equal base, OneLogin::RubySaml::NameIdentifier.new("user", :format => "f", :name_qualifier => "nq", :sp_name_qualifier => "spq")
      refute_equal base, OneLogin::RubySaml::NameIdentifier.new("user", :format => "other", :name_qualifier => "nq", :sp_name_qualifier => "spq")
      refute_equal base, OneLogin::RubySaml::NameIdentifier.new("user", :format => "f", :name_qualifier => "other", :sp_name_qualifier => "spq")
      refute_equal base, OneLogin::RubySaml::NameIdentifier.new("user", :format => "f", :name_qualifier => "nq", :sp_name_qualifier => "other")
      refute_equal base, OneLogin::RubySaml::NameIdentifier.new("other", :format => "f", :name_qualifier => "nq", :sp_name_qualifier => "spq")
    end
  end

  describe "ManageNameIdRequest rename" do
    include RequestHelpers

    it "builds a schema valid request with the old identity attributes and the NewID" do
      request = OneLogin::RubySaml::ManageNameIdRequest.new
      doc = request.create_xml_document(settings, :name_identifier => old_identifier, :new_id => "new.user@example.com")

      xml = ""
      doc.write(xml)
      validate_xml!(xml, OneLogin::RubySaml::SamlMessage.schema)

      root = doc.elements["/samlp:ManageNameIDRequest"]
      assert_equal request.request_id, root.attributes["ID"]
      assert_equal "2.0", root.attributes["Version"]
      assert_equal "https://idp.example.com/manage-name-id", root.attributes["Destination"]
      assert_equal "https://sp.example.com/saml/metadata", doc.elements["//saml:Issuer"].text

      name_id = doc.elements["//saml:NameID"]
      assert_equal "old.user@example.com", name_id.text
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", name_id.attributes["Format"]
      assert_equal "https://idp.example.com/", name_id.attributes["NameQualifier"]
      assert_equal "https://sp.example.com/saml/metadata", name_id.attributes["SPNameQualifier"]

      assert_equal "new.user@example.com", doc.elements["//samlp:NewID"].text
    end

    it "matches the rename message sample" do
      sample = read_manage_name_id_fixture("manage_name_id_request_rename.xml")
      validate_xml!(sample, OneLogin::RubySaml::SamlMessage.schema)
      assert_includes sample, "<samlp:NewID>new.user@example.com</samlp:NewID>"
    end
  end

  describe "ManageNameIdRequest terminate" do
    include RequestHelpers

    it "builds a schema valid request with the Terminate element" do
      request = OneLogin::RubySaml::ManageNameIdRequest.new
      doc = request.create_xml_document(settings, :name_identifier => old_identifier, :terminate => true)

      xml = ""
      doc.write(xml)
      validate_xml!(xml, OneLogin::RubySaml::SamlMessage.schema)

      assert doc.elements["//samlp:Terminate"]
      assert_nil doc.elements["//samlp:NewID"]
    end

    it "matches the terminate message sample" do
      sample = read_manage_name_id_fixture("manage_name_id_request_terminate.xml")
      validate_xml!(sample, OneLogin::RubySaml::SamlMessage.schema)
      assert_includes sample, "<samlp:Terminate/>"
    end
  end

  describe "ManageNameIdRequest new_encrypted_id" do
    include RequestHelpers

    it "wraps the provided EncryptedData fragment in a NewEncryptedID element" do
      encrypted_fragment = '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:CipherData><xenc:CipherValue>ZW5jcnlwdGVk</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>'
      request = OneLogin::RubySaml::ManageNameIdRequest.new
      doc = request.create_xml_document(settings, :name_identifier => old_identifier, :new_encrypted_id => encrypted_fragment)

      assert doc.elements["//samlp:NewEncryptedID/xenc:EncryptedData"]
      assert_nil doc.elements["//samlp:NewID"]

      xml = ""
      doc.write(xml)
      validate_xml!(xml, OneLogin::RubySaml::SamlMessage.schema)
    end

    it "rejects a fragment without a NewEncryptedID or EncryptedData element" do
      request = OneLogin::RubySaml::ManageNameIdRequest.new
      assert_raises(ArgumentError) do
        request.create_xml_document(settings, :name_identifier => old_identifier, :new_encrypted_id => "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">x</saml:NameID>")
      end
    end
  end

  describe "mutually exclusive actions" do
    include RequestHelpers

    it "requires exactly one of new_id, new_encrypted_id or terminate" do
      request = OneLogin::RubySaml::ManageNameIdRequest.new

      assert_raises(ArgumentError) do
        request.create_xml_document(settings, :name_identifier => old_identifier)
      end

      assert_raises(ArgumentError) do
        request.create_xml_document(settings, :name_identifier => old_identifier, :new_id => "a", :terminate => true)
      end

      assert_raises(ArgumentError) do
        request.create_xml_document(settings, :name_identifier => old_identifier, :new_id => "a", :new_encrypted_id => "<saml:EncryptedID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>")
      end
    end

    it "requires the old identifier" do
      request = OneLogin::RubySaml::ManageNameIdRequest.new
      assert_raises(ArgumentError) do
        request.create_xml_document(settings, :new_id => "new.user@example.com")
      end
    end
  end

  describe "SOAP binding" do
    include RequestHelpers

    it "wraps the request in a SOAP envelope" do
      request = OneLogin::RubySaml::ManageNameIdRequest.new
      envelope = request.create(settings, :name_identifier => old_identifier, :new_id => "new.user@example.com")

      assert_includes envelope, "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
      assert_includes envelope, "<soap:Body>"
      assert_includes envelope, "<samlp:ManageNameIDRequest"

      unwrapped = OneLogin::RubySaml::ManageNameIdResponse.unwrap_soap_envelope(envelope)
      assert_includes unwrapped, "<samlp:ManageNameIDRequest"
      validate_xml!(unwrapped, OneLogin::RubySaml::SamlMessage.schema)
    end
  end

  describe "signing" do
    include RequestHelpers

    it "signs the request when manage_name_id_requests_signed is enabled" do
      settings.certificate = ruby_saml_cert_text
      settings.private_key = ruby_saml_key_text
      settings.security[:manage_name_id_requests_signed] = true

      request = OneLogin::RubySaml::ManageNameIdRequest.new
      doc = request.create_manage_name_id_request_xml_doc(settings, :name_identifier => old_identifier, :new_id => "new.user@example.com")

      assert doc.elements["//ds:Signature"], "expected the request to be signed"
    end

    it "does not sign the request by default" do
      settings.certificate = ruby_saml_cert_text
      settings.private_key = ruby_saml_key_text

      request = OneLogin::RubySaml::ManageNameIdRequest.new
      doc = request.create_manage_name_id_request_xml_doc(settings, :name_identifier => old_identifier, :new_id => "new.user@example.com")

      assert_nil doc.elements["//ds:Signature"]
    end
  end
end
