module OneLogin
  module RubySaml
    class ManageNameIDResult
      STATUSES = [:validation_error, :duplicate, :rejected, :local_submission_failed, :send_failed, :success].freeze

      attr_reader :status
      attr_reader :request
      attr_reader :response
      attr_reader :record
      attr_reader :errors
      attr_reader :exception

      def initialize(status, attributes = {})
        @status = status
        @request = attributes[:request]
        @response = attributes[:response]
        @record = attributes[:record]
        @errors = attributes[:errors] || []
        @exception = attributes[:exception]
      end

      def success?
        status == :success
      end

      def duplicate?
        status == :duplicate
      end

      def rejected?
        status == :rejected
      end

      def send_failed?
        status == :send_failed
      end

      def local_submission_failed?
        status == :local_submission_failed
      end
    end
  end
end
