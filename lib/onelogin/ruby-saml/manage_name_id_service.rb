require "net/http"
require "net/https"
require "onelogin/ruby-saml/manage_name_id_request"
require "onelogin/ruby-saml/manage_name_id_response"
require "onelogin/ruby-saml/slo_manage_name_id_request"
require "onelogin/ruby-saml/slo_manage_name_id_response"
require "onelogin/ruby-saml/manage_name_id_record_store"
require "onelogin/ruby-saml/manage_name_id_result"
require "onelogin/ruby-saml/http_error"

module OneLogin
  module RubySaml
    class ManageNameIDService
      SOAP_ACTION = "http://www.oasis-open.org/committees/security"

      attr_reader :settings
      attr_reader :record_store
      attr_reader :callback

      def initialize(settings, options = {})
        @settings = settings
        @record_store = options[:record_store] || options[:records] || ManageNameIDRecordStore.new
        @record_store = ManageNameIDRecordStore.new(@record_store) unless @record_store.is_a?(ManageNameIDRecordStore)
        @callback = options[:callback] || options[:local_callback]
        @identity_verifier = options[:identity_verifier] || options[:target_identity_callback]
        @validate_cert = options.key?(:validate_cert) ? options[:validate_cert] : true
      end

      def submit(params = {})
        request = build_request(params)
        target_identity = {
          :name_id => request.old_name_id,
          :format => request.old_name_id_format,
          :name_qualifier => request.old_name_qualifier,
          :sp_name_qualifier => request.old_sp_name_qualifier
        }
        unless target_identity_verified?(target_identity, params[:identity_verifier] || params[:target_identity_callback], params[:target_identity])
          return ManageNameIDResult.new(:validation_error, :request => request, :errors => ["Target identity could not be verified"])
        end

        existing_record = record_store.find(request.request_id)
        if existing_record
          result = resume_existing_record(request, existing_record)
          return result if result
        end

        record = existing_record || new_record(params, request)
        record_store.save(request.request_id, record)

        return send_manage_name_id_request(request, record) unless record[:status] == :remote_succeeded
        response = ManageNameIDResponse.new(record[:response], settings, :matches_request_id => request.request_id)
        invoke_local_callback(request, record, response, record[:response])
      end

      def send_manage_name_id_request(request, record)
        begin
          soap_response = post_soap(request.create_soap(settings))
        rescue StandardError => exception
          record[:status] = :send_failed
          record[:error] = exception.message
          record_store.save(request.request_id, record)
          return ManageNameIDResult.new(:send_failed, :request => request, :record => record, :exception => exception, :errors => [exception.message])
        end

        response = ManageNameIDResponse.new(soap_response, settings, :matches_request_id => request.request_id)
        unless response.validate(true)
          record[:status] = :validation_error
          record[:response] = soap_response
          record[:errors] = response.errors
          record_store.save(request.request_id, record)
          return ManageNameIDResult.new(:validation_error, :request => request, :response => response, :record => record, :errors => response.errors)
        end

        unless response.success?
          record[:status] = :rejected
          record[:response] = soap_response
          record[:errors] = [Utils.status_error_msg("The status code of the ManageNameID Response was not Success", response.status_code, response.status_message)]
          record_store.save(request.request_id, record)
          return ManageNameIDResult.new(:rejected, :request => request, :response => response, :record => record, :errors => record[:errors])
        end

        record_store.mark_remote_success(request.request_id, soap_response)
        invoke_local_callback(request, record, response, soap_response)
      end

      def receive(soap_request, params = {})
        request = SloManageNameIDRequest.new(soap_request, :settings => settings)
        return invalid_request_result(request) unless request.validate(true)
        unless target_identity_verified?(request.old_identity, params[:identity_verifier] || params[:target_identity_callback], params[:target_identity])
          return invalid_identity_result(request)
        end

        record = record_store.find(request.request_id)
        return duplicate_result(record, request) if record

        record = {
          :id => request.request_id,
          :status => :received,
          :old_identity => request.old_identity,
          :new_identity => request.new_identity,
          :terminate => request.terminate?
        }
        record_store.save(request.request_id, record)

        begin
          invoke_callback(request)
        rescue StandardError => exception
          record[:status] = :local_submission_failed
          record[:error] = exception.message
          record_store.save(request.request_id, record)
          response = build_response(request, SloManageNameIDResponse::RESPONDER, exception.message)
          return ManageNameIDResult.new(:local_submission_failed, :request => request, :response => response, :record => record, :exception => exception, :errors => [exception.message])
        end

        record[:status] = :completed
        record_store.save(request.request_id, record)
        response = build_response(request)
        ManageNameIDResult.new(:success, :request => request, :response => response, :record => record)
      end

      private

      def build_request(params)
        request_params = {
          :request_id => params[:request_id],
          :old_name_id => params[:old_name_id] || settings.name_identifier_value,
          :old_name_id_format => params[:old_name_id_format] || settings.name_identifier_format,
          :old_name_qualifier => params[:old_name_qualifier] || settings.idp_name_qualifier,
          :old_sp_name_qualifier => params[:old_sp_name_qualifier] || settings.sp_name_qualifier || settings.sp_entity_id,
          :new_id => params[:new_id],
          :new_encrypted_id => params[:new_encrypted_id],
          :terminate => params[:terminate]
        }
        ManageNameIDRequest.new(request_params)
      end

      def new_record(params, request)
        {
          :id => request.request_id,
          :status => :pending,
          :old_identity => build_identity(params, "old"),
          :new_identity => request.terminate ? nil : build_new_identity(params, request),
          :terminate => request.terminate == true
        }
      end

      def resume_existing_record(request, record)
        case record[:status]
        when :completed, :duplicate
          ManageNameIDResult.new(:duplicate, :request => request, :record => record, :errors => record[:errors] || [])
        when :rejected
          ManageNameIDResult.new(:rejected, :request => request, :record => record, :errors => record[:errors] || [])
        when :validation_error
          ManageNameIDResult.new(:validation_error, :request => request, :record => record, :errors => record[:errors] || [])
        when :local_submission_failed
          response = ManageNameIDResponse.new(record[:response], settings, :matches_request_id => request.request_id)
          invoke_local_callback(request, record, response, record[:response])
        when :remote_succeeded
          response = ManageNameIDResponse.new(record[:response], settings, :matches_request_id => request.request_id)
          invoke_local_callback(request, record, response, record[:response])
        else
          nil
        end
      end

      def build_identity(params, prefix)
        {
          :name_id => params["#{prefix}_name_id".to_sym] || (prefix == "old" ? settings.name_identifier_value : nil),
          :format => params["#{prefix}_name_id_format".to_sym] || (prefix == "old" ? settings.name_identifier_format : nil),
          :name_qualifier => params["#{prefix}_name_qualifier".to_sym] || (prefix == "old" ? settings.idp_name_qualifier : nil),
          :sp_name_qualifier => params["#{prefix}_sp_name_qualifier".to_sym] || (prefix == "old" ? (settings.sp_name_qualifier || settings.sp_entity_id) : nil)
        }
      end

      def build_new_identity(params, request)
        if request.new_encrypted_id
          nil
        else
          identity = build_identity(params, "new")
          identity[:name_id] = request.new_id
          identity[:format] = request.old_name_id_format
          identity[:name_qualifier] = request.old_name_qualifier
          identity[:sp_name_qualifier] = request.old_sp_name_qualifier
          identity
        end
      end

      def post_soap(soap_request)
        url = settings.idp_manage_name_id_service_url
        raise ArgumentError.new("idp_manage_name_id_service_url is required") if url.nil? || url.empty?

        uri = URI.parse(url)
        raise ArgumentError.new("url must begin with http or https") unless uri.scheme =~ /\Ahttps?\z/
        http = Net::HTTP.new(uri.host, uri.port)
        if uri.scheme == "https"
          http.use_ssl = true
          http.verify_mode = @validate_cert ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        end

        post = Net::HTTP::Post.new(uri.request_uri)
        post.content_type = "text/xml"
        post["SOAPAction"] = SOAP_ACTION
        post.body = soap_request
        http_response = http.request(post)
        raise HttpError.new("ManageNameID request failed: #{http_response.code}: #{http_response.message}") unless http_response.is_a?(Net::HTTPSuccess)
        http_response.body
      end

      def invoke_local_callback(request, record, parsed_response, soap_response)
        begin
          invoke_callback(request)
        rescue StandardError => exception
          record_store.mark_local_failed(request.request_id, exception)
          updated_record = record_store.find(request.request_id) || record
          return ManageNameIDResult.new(:local_submission_failed, :request => request, :response => parsed_response, :record => updated_record, :exception => exception, :errors => [exception.message])
        end

        record_store.mark_completed(request.request_id, soap_response)
        ManageNameIDResult.new(:success, :request => request, :response => parsed_response, :record => record_store.find(request.request_id) || record)
      end

      def invoke_callback(request)
        raise ArgumentError.new("A local submission callback is required") if callback.nil?

        if request.is_a?(SloManageNameIDRequest)
          arguments = [{ :action => request.action, :old_identity => request.old_identity, :new_identity => request.new_identity, :request_id => request.request_id, :terminate => request.terminate? }]
        else
          record = record_store.find(request.request_id)
          arguments = [{ :action => request.terminate ? :terminate : (request.new_encrypted_id ? :new_encrypted_id : :new_id), :old_identity => record[:old_identity], :new_identity => record[:new_identity], :request_id => request.request_id, :terminate => request.terminate == true }]
        end

        if callback.arity == 0 && !callback.is_a?(Proc)
          callback.call
        else
          callback.call(arguments.first)
        end
      end

      def target_identity_verified?(identity, verifier = nil, expected_identity = nil)
        verifier ||= @identity_verifier
        return false if identity[:name_id].nil? || identity[:name_id].to_s.empty?
        return false unless identity[:sp_name_qualifier] == settings.sp_entity_id
        unless expected_identity.nil?
          return false unless identity_matches?(identity, expected_identity)
        end
        return true if verifier.nil?
        result = call_verifier(verifier, identity, expected_identity)
        !!result
      end

      def call_verifier(verifier, identity, expected_identity)
        if verifier.arity == 0
          verifier.call
        elsif verifier.arity == 1 || verifier.arity == -1
          verifier.call(identity)
        else
          verifier.call(identity, expected_identity)
        end
      end

      def identity_matches?(actual, expected)
        [:name_id, :format, :name_qualifier, :sp_name_qualifier].all? do |key|
          expected[key].nil? || actual[key] == expected[key]
        end
      end

      def build_response(request, status_code = SloManageNameIDResponse::SUCCESS, status_message = nil)
        SloManageNameIDResponse.new.create_soap(settings, request.request_id, status_code, status_message)
      end

      def invalid_request_result(request)
        ManageNameIDResult.new(:validation_error, :request => request, :errors => request.errors, :response => build_response(request, SloManageNameIDResponse::RESPONDER, request.errors.join("; ")))
      end

      def invalid_identity_result(request)
        ManageNameIDResult.new(:validation_error, :request => request, :errors => ["Target identity could not be verified"], :response => build_response(request, SloManageNameIDResponse::REQUESTER, "Target identity could not be verified"))
      end

      def duplicate_result(record, request = nil)
        response = request ? build_response(request) : nil
        ManageNameIDResult.new(:duplicate, :request => request, :record => record, :response => response, :errors => ["ManageNameID request #{record[:id]} was already consumed"])
      end
    end
  end
end
