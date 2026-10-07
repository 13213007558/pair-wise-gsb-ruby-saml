require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ManageNameIdServiceTest < Minitest::Test

  module ServiceHelpers
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

    def old_identifier
      OneLogin::RubySaml::NameIdentifier.new(
        "old.user@example.com",
        :format => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        :name_qualifier => "https://idp.example.com/",
        :sp_name_qualifier => "https://sp.example.com/saml/metadata"
      )
    end

    def rename_options
      { :name_identifier => old_identifier, :new_id => "new.user@example.com" }
    end

    # Builds a transport double that answers a ManageNameID Response whose
    # InResponseTo matches the ID of the received request.
    def success_transport(calls)
      lambda do |envelope, url|
        calls << [envelope, url]
        request_id = envelope[/ID=["']([^"']+)["']/, 1]
        read_manage_name_id_fixture("manage_name_id_response_success.xml").sub("_mnid-request-rename-001", request_id)
      end
    end

    def error_transport(calls)
      lambda do |envelope, url|
        calls << [envelope, url]
        request_id = envelope[/ID=["']([^"']+)["']/, 1]
        read_manage_name_id_fixture("manage_name_id_response_requester_error.xml").sub("_mnid-request-rename-001", request_id)
      end
    end
  end

  describe "successful rename" do
    include ServiceHelpers

    it "sends the SOAP envelope, validates the response and commits locally" do
      transport_calls = []
      committed = []
      store = OneLogin::RubySaml::ManageNameIdService::MemoryStore.new
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :store => store,
        :transport => success_transport(transport_calls),
        :commit => lambda { |change| committed << change; true }
      )

      result = service.execute(rename_options)

      assert result.success?
      assert result.remote_applied?
      assert_equal 1, transport_calls.size
      assert_includes transport_calls.first[0], "<soap:Envelope"
      assert_equal "https://idp.example.com/manage-name-id", transport_calls.first[1]

      assert_equal 1, committed.size
      assert_equal :rename, committed.first[:action]
      assert_equal old_identifier, committed.first[:name_identifier]
      assert_equal "new.user@example.com", committed.first[:new_id]
      assert_equal result.request_id, committed.first[:request_id]

      key = OneLogin::RubySaml::ManageNameIdService.operation_key(rename_options)
      assert_equal :completed, store.read(key)[:state]
    end
  end

  describe "successful terminate" do
    include ServiceHelpers

    it "commits a terminate change" do
      committed = []
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :transport => success_transport([]),
        :commit => lambda { |change| committed << change; true }
      )

      result = service.execute(:name_identifier => old_identifier, :terminate => true)

      assert result.success?
      assert_equal :terminate, committed.first[:action]
    end
  end

  describe "duplicated consumption" do
    include ServiceHelpers

    it "replays the recorded outcome without resending nor recommitting" do
      transport_calls = []
      committed = []
      store = OneLogin::RubySaml::ManageNameIdService::MemoryStore.new
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :store => store,
        :transport => success_transport(transport_calls),
        :commit => lambda { |change| committed << change; true }
      )

      first = service.execute(rename_options)
      second = service.execute(rename_options)

      assert first.success?
      assert second.duplicate?
      assert_equal :completed, second.recorded_state
      assert second.remote_applied?
      assert_equal first.request_id, second.request_id
      assert_equal 1, transport_calls.size, "the request must not be sent twice"
      assert_equal 1, committed.size, "the local commit must not run twice"
    end

    it "reproduces the recorded outcome from a caller provided store" do
      key = OneLogin::RubySaml::ManageNameIdService.operation_key(rename_options)
      store = OneLogin::RubySaml::ManageNameIdService::MemoryStore.new
      store.write(key, {
        :operation_key => key,
        :request_id => "_mnid-request-rename-001",
        :name_identifier => old_identifier.to_key,
        :state => :completed
      })

      transport_calls = []
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :store => store,
        :transport => success_transport(transport_calls),
        :commit => lambda { |change| flunk "commit must not run for a recorded operation" }
      )

      result = service.execute(rename_options)

      assert result.duplicate?
      assert_equal :completed, result.recorded_state
      assert_equal "_mnid-request-rename-001", result.request_id
      assert_equal 0, transport_calls.size
    end
  end

  describe "transport failure" do
    include ServiceHelpers

    it "returns a transport_error result with unknown remote state" do
      failing_transport = lambda { |envelope, url| raise IOError.new("connection refused") }
      committed = []
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :transport => failing_transport,
        :commit => lambda { |change| committed << change; true }
      )

      result = service.execute(rename_options)

      assert_equal :transport_error, result.status
      refute result.remote_applied?
      assert_includes result.errors.first, "remote state is unknown"
      assert_equal 0, committed.size
    end
  end

  describe "denied status" do
    include ServiceHelpers

    it "returns a denied result and does not commit locally" do
      committed = []
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :transport => error_transport([]),
        :commit => lambda { |change| committed << change; true }
      )

      result = service.execute(rename_options)

      assert_equal :denied, result.status
      assert_equal "urn:oasis:names:tc:SAML:2.0:status:Requester", result.status_code
      refute result.remote_applied?
      assert_includes result.errors.first, "not applied"
      assert_equal 0, committed.size
    end

    it "returns invalid_response when a denial comes from an unverified peer" do
      settings.idp_entity_id = "https://evil.example.com/"
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :transport => error_transport([]),
        :commit => lambda { |change| flunk "commit must not run" }
      )

      result = service.execute(rename_options)

      assert_equal :invalid_response, result.status
      assert_includes result.errors.join(", "), "Doesn't match the issuer"
    end
  end

  describe "local commit failure" do
    include ServiceHelpers

    it "returns a commit_failed result and never claims a remote rollback" do
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :transport => success_transport([]),
        :commit => lambda { |change| raise "database is locked" }
      )

      result = service.execute(rename_options)

      assert_equal :commit_failed, result.status
      assert result.remote_applied?
      assert_includes result.errors.first, "database is locked"
      assert_includes result.errors.first, "NOT rolled back"
    end

    it "treats a false return from the commit callback as a failure" do
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :transport => success_transport([]),
        :commit => lambda { |change| false }
      )

      result = service.execute(rename_options)

      assert_equal :commit_failed, result.status
      assert result.remote_applied?
    end
  end

  describe "invalid responses" do
    include ServiceHelpers

    it "returns invalid_response when the IdP answers another message type" do
      logout_style_transport = lambda do |envelope, url|
        request_id = envelope[/ID=["']([^"']+)["']/, 1]
        logout_response = OneLogin::RubySaml::SloLogoutresponse.new
        doc = logout_response.create_xml_document(settings, request_id)
        xml = ""
        doc.write(xml)
        xml
      end
      committed = []
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :transport => logout_style_transport,
        :commit => lambda { |change| committed << change; true }
      )

      result = service.execute(rename_options)

      assert_equal :invalid_response, result.status
      refute result.remote_applied?
      assert_equal 0, committed.size
    end

    it "returns invalid_response when the correlation ID does not match" do
      mismatched_transport = lambda do |envelope, url|
        read_manage_name_id_fixture("manage_name_id_response_success.xml")
      end
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :transport => mismatched_transport,
        :commit => lambda { |change| flunk "commit must not run" }
      )

      result = service.execute(rename_options)

      assert_equal :invalid_response, result.status
      assert_includes result.errors.join(", "), "does not match the ID of the ManageNameID Request"
    end

    it "returns invalid_response when the recorded target identity does not match" do
      tampering_store = Class.new(OneLogin::RubySaml::ManageNameIdService::MemoryStore) do
        def read(key)
          record = super
          if record && record[:state] == :pending
            record = record.dup
            record[:name_identifier] = ["attacker@example.com", nil, nil, nil]
          end
          record
        end
      end.new

      committed = []
      service = OneLogin::RubySaml::ManageNameIdService.new(
        settings,
        :store => tampering_store,
        :transport => success_transport([]),
        :commit => lambda { |change| committed << change; true }
      )

      result = service.execute(rename_options)

      assert_equal :invalid_response, result.status
      assert_includes result.errors.first, "target identity"
      assert_equal 0, committed.size
    end
  end

  describe "settings" do
    include ServiceHelpers

    it "requires the IdP ManageNameID service URL" do
      settings.idp_manage_name_id_service_url = nil
      service = OneLogin::RubySaml::ManageNameIdService.new(settings, :transport => success_transport([]))

      assert_raises(OneLogin::RubySaml::SettingError) do
        service.execute(rename_options)
      end
    end
  end
end
