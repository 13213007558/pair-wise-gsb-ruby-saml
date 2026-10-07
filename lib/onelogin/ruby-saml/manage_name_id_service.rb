require "net/http"
require "digest"

require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/http_error"
require "onelogin/ruby-saml/setting_error"
require "onelogin/ruby-saml/manage_name_id_request"
require "onelogin/ruby-saml/manage_name_id_response"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Result of a ManageNameID operation executed by ManageNameIdService.
    #
    # The status distinguishes the different outcomes so a caller never
    # confuses them:
    #   :success          The IdP applied the change and the local commit callback succeeded.
    #   :duplicate        The operation was already recorded on the store, the recorded
    #                     outcome is replayed (see recorded_state). Nothing was resent
    #                     nor committed again.
    #   :transport_error  The request could not be sent. The remote state is unknown.
    #   :invalid_response The IdP answer failed validation (peer, correlation ID or
    #                     signature). The remote state is unknown.
    #   :denied           The IdP answered with a non Success status code.
    #                     The remote change was NOT applied.
    #   :commit_failed    The IdP applied the change but the local commit callback
    #                     failed. The remote change was NOT rolled back.
    #
    class ManageNameIdResult
      attr_reader :status
      attr_reader :request_id
      attr_reader :status_code
      attr_reader :status_message
      attr_reader :errors
      attr_reader :recorded_state

      def initialize(status, options = {})
        @status = status
        @request_id = options[:request_id]
        @status_code = options[:status_code]
        @status_message = options[:status_message]
        @errors = options[:errors] || []
        @recorded_state = options[:recorded_state]
      end

      def success?
        status == :success
      end

      def duplicate?
        status == :duplicate
      end

      # @return [Boolean] True when the IdP already applied the identifier change
      #
      def remote_applied?
        return true if status == :success || status == :commit_failed
        duplicate? && [:completed, :commit_failed].include?(recorded_state)
      end

      def self.success(request_id)
        new(:success, :request_id => request_id)
      end

      def self.duplicate(record)
        new(:duplicate, :request_id => record[:request_id], :recorded_state => record[:state])
      end

      def self.transport_error(request_id, error)
        new(:transport_error, :request_id => request_id, :errors => ["ManageNameID Request could not be sent, the remote state is unknown: #{error}"])
      end

      def self.invalid_response(request_id, errors)
        new(:invalid_response, :request_id => request_id, :errors => errors)
      end

      def self.denied(request_id, status_code, status_message)
        new(:denied, :request_id => request_id, :status_code => status_code, :status_message => status_message,
            :errors => ["The IdP denied the ManageNameID Request with status #{status_code}#{" (#{status_message})" if status_message}. The remote change was not applied"])
      end

      def self.commit_failed(request_id, error)
        new(:commit_failed, :request_id => request_id,
            :errors => ["The IdP applied the ManageNameID change but the local commit failed: #{error}. The remote change was NOT rolled back"])
      end
    end

    # SAML2 ManageNameID Service (SP initiated, SOAP binding).
    #
    # Orchestrates a ManageNameIDRequest: builds the SOAP message, sends it to
    # the IdP, validates the ManageNameIDResponse (peer, correlation ID and
    # signature) and only then invokes the local commit callback provided by
    # the caller.
    #
    # Duplicated operations are detected through a record store provided by
    # the caller, so the handling of a repeated request is stably reproducible:
    # the recorded outcome is replayed and nothing is resent nor committed twice.
    #
    class ManageNameIdService
      SOAP_ACTION = "http://www.oasis-open.org/committees/security".freeze

      TERMINAL_STATES = [:transport_error, :invalid_response, :denied, :completed, :commit_failed].freeze

      # Simple in-memory record store. The caller can provide any object
      # responding to read(key) and write(key, record) to make the duplicate
      # handling persistent and reproducible across processes.
      #
      class MemoryStore
        def initialize
          @records = {}
        end

        def read(key)
          @records[key]
        end

        def write(key, record)
          @records[key] = record
        end
      end

      attr_reader :settings
      attr_reader :store
      attr_reader :transport
      attr_reader :commit

      # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
      # @param options [Hash]
      #   :store [#read, #write] Record store used to detect and replay duplicated
      #     operations. Defaults to an in-memory store.
      #   :transport [#call] Callable that receives the SOAP envelope and the IdP
      #     ManageNameID service URL and returns the response body. Defaults to a
      #     Net::HTTP POST.
      #   :commit [#call] Local callback invoked with the change descriptor once the
      #     IdP response has been validated. It must return a truthy value to confirm
      #     the local commit; returning false or raising is a local commit failure.
      #
      def initialize(settings, options = {})
        @settings = settings
        @store = options[:store] || MemoryStore.new
        @transport = options[:transport] || method(:default_transport)
        @commit = options[:commit]
      end

      # Executes a ManageNameID operation.
      # @param options [Hash]
      #   :name_identifier [OneLogin::RubySaml::NameIdentifier] The current (old) identifier. Required.
      #   :new_id [String] The new identifier value (rename).
      #   :new_encrypted_id [String] An XML fragment with a saml:EncryptedID element.
      #   :terminate [Boolean] True to terminate the identifier.
      #   Exactly one of :new_id, :new_encrypted_id or :terminate must be given.
      #   :operation_key [String] Stable key that identifies the operation on the
      #     record store. Defaults to a digest of the identity and the action, so
      #     repeating the same operation is detected as a duplicate.
      # @return [ManageNameIdResult] The outcome of the operation
      #
      def execute(options = {})
        name_identifier = options[:name_identifier]
        raise ArgumentError.new("A :name_identifier option with the current identifier is required") if name_identifier.nil?

        operation_key = options[:operation_key] || self.class.operation_key(options)

        existing = store.read(operation_key)
        if existing
          Logging.info "ManageNameID operation #{operation_key} already recorded as #{existing[:state]}, replaying the recorded outcome"
          return ManageNameIdResult.duplicate(existing)
        end

        service_url = endpoint

        request = ManageNameIdRequest.new
        envelope = request.create(settings, options)
        request_id = request.request_id

        record = {
          :operation_key => operation_key,
          :request_id => request_id,
          :name_identifier => name_identifier.to_key,
          :state => :pending
        }
        store.write(operation_key, record)

        raw_response = send_envelope(envelope, service_url, request_id, operation_key, record)
        return raw_response if raw_response.is_a?(ManageNameIdResult)

        response = validate_response(raw_response, request_id, operation_key, record)
        return response if response.is_a?(ManageNameIdResult)

        unless response.success?
          record[:state] = :denied
          record[:status_code] = response.status_code
          store.write(operation_key, record)
          return ManageNameIdResult.denied(request_id, response.status_code, response.status_message)
        end

        # The peer, the correlation ID and the signature were validated above.
        # Verify the target identity recorded for this operation before
        # invoking the local commit callback.
        stored_record = store.read(operation_key) || {}
        unless stored_record[:name_identifier] == name_identifier.to_key
          record[:state] = :invalid_response
          store.write(operation_key, record)
          return ManageNameIdResult.invalid_response(request_id, ["The target identity of the ManageNameID Response does not match the recorded identity"])
        end

        commit_change(request_id, operation_key, record, options)
      end

      # Builds the stable operation key used to detect duplicated operations.
      # @param options [Hash] The execute options
      # @return [String] A hex digest of the identity and the action
      #
      def self.operation_key(options)
        name_identifier = options[:name_identifier]
        identity = name_identifier.nil? ? nil : name_identifier.to_key
        action = [:new_id, :new_encrypted_id, :terminate].map { |key| [key, options[key]] }.reject { |pair| pair[1].nil? || pair[1] == false }
        Digest::SHA256.hexdigest([identity, action].inspect)
      end

      private

      def endpoint
        url = settings.idp_manage_name_id_service_url
        raise SettingError.new "Invalid settings, idp_manage_name_id_service_url is not set!" if url.nil? or url.empty?
        url
      end

      def send_envelope(envelope, service_url, request_id, operation_key, record)
        transport.call(envelope, service_url)
      rescue StandardError => error
        record[:state] = :transport_error
        record[:error] = error.message
        store.write(operation_key, record)
        ManageNameIdResult.transport_error(request_id, error.message)
      end

      def validate_response(raw_response, request_id, operation_key, record)
        response = ManageNameIdResponse.new(raw_response, :settings => settings, :matches_request_id => request_id)
        valid = response.success? ? response.validate : response.validate_message
        return response if valid

        record[:state] = :invalid_response
        record[:error] = response.errors.join(", ")
        store.write(operation_key, record)
        ManageNameIdResult.invalid_response(request_id, response.errors)
      rescue StandardError => error
        record[:state] = :invalid_response
        record[:error] = error.message
        store.write(operation_key, record)
        ManageNameIdResult.invalid_response(request_id, [error.message])
      end

      def commit_change(request_id, operation_key, record, options)
        change = {
          :action => options[:terminate] ? :terminate : (options[:new_encrypted_id] ? :new_encrypted_id : :rename),
          :name_identifier => options[:name_identifier],
          :new_id => options[:new_id],
          :new_encrypted_id => options[:new_encrypted_id],
          :request_id => request_id
        }

        begin
          committed = commit.nil? ? true : commit.call(change)
        rescue StandardError => error
          committed = false
          commit_error = error.message
        end

        if committed
          record[:state] = :completed
          store.write(operation_key, record)
          ManageNameIdResult.success(request_id)
        else
          record[:state] = :commit_failed
          record[:error] = commit_error || "commit callback returned false"
          store.write(operation_key, record)
          ManageNameIdResult.commit_failed(request_id, record[:error])
        end
      end

      # Default SOAP transport: POSTs the envelope to the IdP ManageNameID service.
      # @param envelope [String] The SOAP envelope
      # @param url [String] The IdP ManageNameID service URL
      # @return [String] The response body
      # @raise [OneLogin::RubySaml::HttpError] If the IdP does not answer a 2xx
      #
      def default_transport(envelope, url)
        uri = URI.parse(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"

        request = Net::HTTP::Post.new(uri.request_uri)
        request["Content-Type"] = "text/xml; charset=utf-8"
        request["SOAPAction"] = SOAP_ACTION
        request.body = envelope

        response = http.request(request)
        unless response.code.to_i >= 200 && response.code.to_i < 300
          raise HttpError.new("ManageNameID SOAP request failed with HTTP #{response.code}")
        end

        response.body.to_s
      end
    end
  end
end
