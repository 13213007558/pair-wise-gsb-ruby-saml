require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'onelogin/ruby-saml'

module ManageNameIDTestHelpers
  class MockSuccessResponse < Net::HTTPSuccess
    def initialize; end
    attr_accessor :body
  end

  def message_fixture(name)
    File.read(File.join(File.dirname(__FILE__), "manage_name_id_messages", name))
  end

  def manage_settings
    @settings ||= begin
      settings = OneLogin::RubySaml::Settings.new
      settings.sp_entity_id = "https://sp.example.com"
      settings.idp_entity_id = "https://idp.example.com/"
      settings.idp_manage_name_id_service_url = "https://idp.example.com/ManageNameID"
      settings.sp_manage_name_id_service_url = "https://sp.example.com/saml/manage-name-id"
      settings.certificate = ruby_saml_cert_text
      settings.private_key = ruby_saml_key_text
      settings.idp_cert = ruby_saml_cert_text
      settings.security[:manage_name_id_requests_signed] = true
      settings.security[:manage_name_id_responses_signed] = true
      settings
    end
  end

  def unsigned_request(action = :new_id)
    params = {
      :request_id => "_manage_test_1",
      :old_name_id => "old-id",
      :old_name_id_format => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
      :old_name_qualifier => "https://idp.example.com/",
      :old_sp_name_qualifier => "https://sp.example.com"
    }
    params[:new_id] = "new-id" if action == :new_id
    params[:terminate] = true if action == :terminate
    OneLogin::RubySaml::ManageNameIDRequest.new(params)
  end

  def signed_request_soap(action = :new_id)
    unsigned_request(action).create_soap(manage_settings)
  end

  def signed_incoming_request_soap(action = :new_id)
    incoming_settings = OneLogin::RubySaml::Settings.new
    incoming_settings.sp_entity_id = manage_settings.idp_entity_id
    incoming_settings.idp_manage_name_id_service_url = manage_settings.sp_manage_name_id_service_url
    incoming_settings.certificate = ruby_saml_cert_text
    incoming_settings.private_key = ruby_saml_key_text
    incoming_settings.security[:manage_name_id_requests_signed] = true
    unsigned_request(action).create_soap(incoming_settings)
  end

  def signed_response_soap(request_id = "_manage_test_1", status = OneLogin::RubySaml::SloManageNameIDResponse::SUCCESS, message = nil, secondary_status = nil)
    response_settings = OneLogin::RubySaml::Settings.new
    response_settings.sp_entity_id = "https://idp.example.com/"
    response_settings.certificate = ruby_saml_cert_text
    response_settings.private_key = ruby_saml_key_text
    response_settings.security[:manage_name_id_responses_signed] = true
    OneLogin::RubySaml::SloManageNameIDResponse.new.create_soap(response_settings, request_id, status, message, secondary_status)
  end
  alias_method :settings, :manage_settings

end

class ManageNameIDTest < Minitest::Test
  include ManageNameIDTestHelpers

  describe "ManageNameIDRequest" do
    include ManageNameIDTestHelpers
    it "creates a SOAP rename request with all old identity qualifiers and NewID" do
      soap = signed_request_soap
      assert_match(/<soapenv:Envelope/, soap)
      assert_match(/<samlp:ManageNameIDRequest/, soap)
      assert_match(/Format=['\"]urn:oasis:names:tc:SAML:2.0:nameid-format:persistent['\"]/, soap)
      assert_match(/NameQualifier=['\"]https:\/\/idp.example.com\/['\"]/, soap)
      assert_match(/SPNameQualifier=['\"]https:\/\/sp.example.com['\"]/, soap)
      assert_match(/<samlp:NewID>new-id<\/samlp:NewID>/, soap)
      assert_match(/<ds:Signature/, soap)
    end

    it "creates a terminate request" do
      assert_match(/<samlp:Terminate\/>/, signed_request_soap(:terminate))
    end

    it "rejects multiple choices" do
      assert_raises(ArgumentError) do
        unsigned_request.tap { |request| request.terminate = true }.create_soap(settings)
      end
    end

    it "round-trips NewEncryptedID using the IdP encryption certificate" do
      request = OneLogin::RubySaml::ManageNameIDRequest.new(
        :request_id => "_encrypted_new_id",
        :old_name_id => "old-id",
        :old_name_id_format => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        :old_sp_name_qualifier => settings.sp_entity_id,
        :new_id => "secret-new-id"
      )
      soap = request.create_soap(settings, :encrypt_new_id => true)
      parse_settings = OneLogin::RubySaml::Settings.new
      parse_settings.sp_entity_id = settings.sp_entity_id
      parse_settings.sp_manage_name_id_service_url = settings.idp_manage_name_id_service_url
      parse_settings.idp_entity_id = settings.sp_entity_id
      parse_settings.private_key = ruby_saml_key_text
      parse_settings.idp_cert = ruby_saml_cert_text
      incoming = OneLogin::RubySaml::SloManageNameIDRequest.new(soap, :settings => parse_settings)
      assert incoming.is_valid?(true), incoming.errors.inspect
      assert_equal "secret-new-id", incoming.new_id
    end

    it "round-trips an encrypted old identifier including qualifiers" do
      request = OneLogin::RubySaml::ManageNameIDRequest.new(
        :request_id => "_encrypted_old_id",
        :old_name_id => "secret-old-id",
        :old_name_id_format => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        :old_name_qualifier => "https://idp.example.com/",
        :old_sp_name_qualifier => settings.sp_entity_id,
        :terminate => true
      )
      soap = request.create_soap(settings, :encrypt_old_id => true)
      parse_settings = settings.dup
      parse_settings.idp_entity_id = settings.sp_entity_id
      parse_settings.sp_manage_name_id_service_url = settings.idp_manage_name_id_service_url
      incoming = OneLogin::RubySaml::SloManageNameIDRequest.new(soap, :settings => parse_settings)
      assert incoming.is_valid?(true), incoming.errors.inspect
      assert_equal "secret-old-id", incoming.old_name_id
      assert_equal "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", incoming.old_name_id_format
      assert_equal "https://idp.example.com/", incoming.old_name_qualifier
      assert_equal settings.sp_entity_id, incoming.old_sp_name_qualifier
    end
  end

  describe "SloManageNameIDRequest" do
    include ManageNameIDTestHelpers
    it "parses rename, terminate and identity qualifier fields" do
      settings.security[:want_manage_name_id_requests_signed] = false
      rename = OneLogin::RubySaml::SloManageNameIDRequest.new(message_fixture("rename_request.xml"), :settings => settings)
      assert rename.is_valid?
      assert_equal :new_id, rename.action
      assert_equal "old-identifier-123", rename.old_name_id
      assert_equal "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", rename.old_name_id_format
      assert_equal "https://idp.example.com/", rename.old_name_qualifier
      assert_equal "https://sp.example.com", rename.old_sp_name_qualifier
      assert_equal "new-identifier-456", rename.new_id

      terminate = OneLogin::RubySaml::SloManageNameIDRequest.new(message_fixture("terminate_request.xml"), :settings => settings)
      assert terminate.is_valid?
      assert terminate.terminate?
      assert_equal :terminate, terminate.action
    end

    it "validates a signed SOAP request and does not accept a Response object" do
      request = OneLogin::RubySaml::SloManageNameIDRequest.new(signed_incoming_request_soap, :settings => settings)
      assert request.is_valid?
      assert request.is_a?(OneLogin::RubySaml::SloManageNameIDRequest)
      refute request.is_a?(OneLogin::RubySaml::SloLogoutrequest)
      refute request.is_a?(OneLogin::RubySaml::Logoutrequest)
    end

    it "rejects a request whose target identity belongs to another SP qualifier" do
      settings.security[:want_manage_name_id_requests_signed] = false
      request = OneLogin::RubySaml::SloManageNameIDRequest.new(message_fixture("invalid_qualifier_request.xml"), :settings => settings)
      refute request.is_valid?(true)
      assert_includes request.errors, "Old NameID SPNameQualifier does not match the SP entity ID"
    end
  end

  describe "ManageNameIDResponse" do
    include ManageNameIDTestHelpers
    it "validates peer, InResponseTo and a success response" do
      response = OneLogin::RubySaml::ManageNameIDResponse.new(signed_response_soap, settings, :matches_request_id => "_manage_test_1")
      assert response.validate, response.errors.inspect
      assert response.success?
      assert_equal "https://idp.example.com/", response.issuer
      assert_equal "_manage_test_1", response.in_response_to
    end

    it "returns rejected status separately from validation failures" do
      response_soap = signed_response_soap("_manage_test_1", "urn:oasis:names:tc:SAML:2.0:status:Requester", "Denied", "urn:oasis:names:tc:SAML:2.0:status:RequestDenied")
      response = OneLogin::RubySaml::ManageNameIDResponse.new(response_soap, settings, :matches_request_id => "_manage_test_1")
      assert response.validate(true)
      refute response.success?
      assert_equal "urn:oasis:names:tc:SAML:2.0:status:Requester | urn:oasis:names:tc:SAML:2.0:status:RequestDenied", response.status_code
      response_soap = signed_response_soap("_manage_test_1", "urn:oasis:names:tc:SAML:2.0:status:Requester", "Denied", "urn:oasis:names:tc:SAML:2.0:status:RequestDenied")
      nested_response = OneLogin::RubySaml::ManageNameIDResponse.new(response_soap, settings, :matches_request_id => "_manage_test_1")
      assert nested_response.validate(true)
      assert_equal "urn:oasis:names:tc:SAML:2.0:status:Requester | urn:oasis:names:tc:SAML:2.0:status:RequestDenied", nested_response.status_code
    end

    it "rejects mismatched InResponseTo and cannot be represented by Logoutresponse" do
      response = OneLogin::RubySaml::ManageNameIDResponse.new(signed_response_soap("_other"), settings, :matches_request_id => "_manage_test_1")
      refute response.validate
      refute response.is_a?(OneLogin::RubySaml::Logoutresponse)
      refute response.is_a?(OneLogin::RubySaml::Response)
    end
  end

  describe "ManageNameIDService" do
    include ManageNameIDTestHelpers
      def service(storage = {}, options = {})
      service_settings = settings.dup
      service_settings.private_key = settings.private_key
      @service_settings = service_settings
      OneLogin::RubySaml::ManageNameIDService.new(service_settings, options.merge(:record_store => storage, :callback => lambda { |payload| @callback_payload = payload }))
    end

    def stub_http(body, success = true)
      response = MockSuccessResponse.new
      response.body = body
      http = Object.new
      http.define_singleton_method(:use_ssl=) { |value| }
      http.define_singleton_method(:verify_mode=) { |value| }
      http.define_singleton_method(:request) { |_request| response }
      Net::HTTP.expects(:new).returns(http)
    end

    it "submits a successful remote change before invoking the local callback" do
      stub_http(signed_response_soap("_service_1"))
      storage = {}
      result = service(storage).submit(:request_id => "_service_1", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id)
      assert result.success?
      assert_equal :completed, result.record[:status]
      assert_equal "new-id", @callback_payload[:new_identity][:name_id]
      assert_equal "old-id", @callback_payload[:old_identity][:name_id]
    end

    it "reports send failure without claiming rollback" do
      http = Object.new
      http.define_singleton_method(:request) { |_request| raise OneLogin::RubySaml::HttpError.new("connection refused") }
      Net::HTTP.expects(:new).returns(http)
      storage = {}
      result = service(storage).submit(:request_id => "_send_failed", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id)
      assert result.send_failed?
      refute result.success?
      assert_equal :send_failed, result.record[:status]
      assert_nil @callback_payload
    end

    it "retries a send failure using the caller record" do
      http = Object.new
      http.define_singleton_method(:use_ssl=) { |value| }
      http.define_singleton_method(:verify_mode=) { |value| }
      http.define_singleton_method(:request) { |_request| raise OneLogin::RubySaml::HttpError.new("connection refused") }
      Net::HTTP.expects(:new).returns(http).twice
      storage = {}
      params = { :request_id => "_send_retry", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id }
      first = service(storage).submit(params)
      assert first.send_failed?
      second = service(storage).submit(params)
      assert second.send_failed?
      assert_equal first.record[:id], second.record[:id]
    end

    it "reports a rejected remote status separately" do
      stub_http(signed_response_soap("_rejected_1", "urn:oasis:names:tc:SAML:2.0:status:Requester", "Denied", "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"))
      result = service.submit(:request_id => "_rejected_1", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id)
      assert result.rejected?
      assert_includes result.errors.first, "RequestDenied"
      assert_nil @callback_payload
    end

    it "reports local callback failure after remote success without changing remote result" do
      storage = {}
      failing_service = OneLogin::RubySaml::ManageNameIDService.new(settings, :record_store => storage, :callback => lambda { |_payload| raise("local database unavailable") })
      stub_http(signed_response_soap("_local_failed_1"))
      result = failing_service.submit(:request_id => "_local_failed_1", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id)
      assert result.local_submission_failed?
      assert result.response.success?
      assert_equal :local_submission_failed, result.record[:status]
      assert_includes result.errors, "local database unavailable"
    end

    it "retries only the local submission after remote success and does not send again" do
      calls = 0
      callback = lambda do |_payload|
        calls += 1
        raise "temporary local failure" if calls == 1
      end
      storage = {}
      service = OneLogin::RubySaml::ManageNameIDService.new(settings, :record_store => storage, :callback => callback)
      stub_http(signed_response_soap("_local_retry_1"))
      first = service.submit(:request_id => "_local_retry_1", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id)
      assert first.local_submission_failed?
      second = service.submit(:request_id => "_local_retry_1", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id)
      assert second.success?
      assert_equal :completed, second.record[:status]
      assert_equal 2, calls
    end

    it "reproduces duplicate outgoing requests from caller records" do
      stub_http(signed_response_soap("_duplicate_out_1"))
      storage = {}
      service = service(storage)
      params = { :request_id => "_duplicate_out_1", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id }
      assert service.submit(params).success?
      duplicate = service.submit(params)
      assert duplicate.duplicate?
      assert_equal :completed, duplicate.record[:status]
    end

    it "supports a caller-provided record store" do
      storage = Object.new
      records = {}
      storage.define_singleton_method(:get) { |id| records[id] }
      storage.define_singleton_method(:put) { |id, record| records[id] = record }
      stub_http(signed_response_soap("_custom_store_1"))
      service = service(storage)
      result = service.submit(:request_id => "_custom_store_1", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id)
      assert result.success?
      assert_equal :completed, records["_custom_store_1"][:status]
      assert service.submit(:request_id => "_custom_store_1", :old_name_id => "old-id", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id).duplicate?
    end

    it "does not call the local callback when the supplied target identity verifier rejects the identity" do
      verifier = lambda { |identity| identity[:name_id] == "known" }
      storage = {}
      called = false
      service = OneLogin::RubySaml::ManageNameIDService.new(settings, :record_store => storage, :callback => lambda { |_payload| called = true }, :identity_verifier => verifier)
      result = service.submit(:request_id => "_unknown_target", :old_name_id => "unknown", :new_id => "new-id", :old_sp_name_qualifier => settings.sp_entity_id)
      refute result.success?
      refute called
      assert_empty storage
    end

    it "consumes an inbound request once and returns a duplicate result on replay" do
      settings.security[:want_manage_name_id_requests_signed] = false
      storage = {}
      service = service(storage)
      result = service.receive(message_fixture("rename_request.xml"))
      assert result.success?
      duplicate = service.receive(message_fixture("duplicate_request.xml"))
      assert duplicate.duplicate?
      assert_includes duplicate.errors, "ManageNameID request _manage-rename-001 was already consumed"
    end

    it "requires all target identity qualifier fields to match on inbound requests" do
      settings.security[:want_manage_name_id_requests_signed] = false
      service = service({})
      expected = {
        :name_id => "old-identifier-123",
        :format => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        :name_qualifier => "https://idp.example.com/",
        :sp_name_qualifier => "https://evil.example.com"
      }
      result = service.receive(message_fixture("rename_request.xml"), :target_identity => expected)
      refute result.success?
      assert_nil result.record
    end

    it "does not consume an inbound request when the target identity verifier rejects it" do
      settings.security[:want_manage_name_id_requests_signed] = false
      storage = {}
      verifier = lambda { |identity| identity[:name_id] == "never" }
      service = service(storage, :identity_verifier => verifier)
      result = service.receive(message_fixture("rename_request.xml"))
      refute result.success?
      assert_empty storage
    end
  end
end
