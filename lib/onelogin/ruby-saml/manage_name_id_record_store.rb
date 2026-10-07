module OneLogin
  module RubySaml
    class ManageNameIDRecordStore
      def initialize(storage = {})
        @storage = storage
      end

      def find(id)
        call_storage(:[], id) || call_storage(:get, id)
      end

      def save(id, record)
        if @storage.respond_to?(:[]=)
          @storage[id] = record
        elsif @storage.respond_to?(:put)
          @storage.put(id, record)
        end
        record
      end

      def mark_remote_success(id, response)
        record = find(id)
        return unless record
        record[:status] = :remote_succeeded
        record[:response] = response
        record.delete(:error)
        record.delete(:errors)
        save(id, record)
      end

      def mark_completed(id, response)
        record = find(id)
        return unless record
        record[:status] = :completed
        record[:response] = response
        record.delete(:error)
        record.delete(:errors)
        save(id, record)
      end

      def mark_local_failed(id, exception)
        record = find(id)
        return unless record
        record[:status] = :local_submission_failed
        record[:error] = exception.message
        save(id, record)
      end

      private

      def call_storage(method, *arguments)
        @storage.send(method, *arguments) if @storage.respond_to?(method)
      end
    end
  end
end
