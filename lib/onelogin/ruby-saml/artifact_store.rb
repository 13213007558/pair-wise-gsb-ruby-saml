# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Interface of the state store that backs the single-use semantics of
    # SAML artifacts. Implementations MUST make #acquire atomic so that
    # two concurrent resolutions of the same artifact cannot both win.
    #
    # Lifecycle of an artifact key:
    #   acquire -> commit   (resolution finished, artifact is spent)
    #   acquire -> release  (transient transport failure, artifact may be
    #                        retried later)
    #
    class ArtifactStore
      # Atomically claims the artifact identified by +key+ for the caller.
      # @param key [String] The artifact cache key.
      # @return [Boolean] true if the caller won the claim, false if the
      #   artifact is already being resolved or has been consumed.
      def acquire(key)
        raise NotImplementedError
      end

      # Gives back a previously acquired claim, allowing a later retry.
      # Only to be used after transient transport failures.
      # @param key [String] The artifact cache key.
      def release(key)
        raise NotImplementedError
      end

      # Permanently marks the artifact as consumed.
      # @param key [String] The artifact cache key.
      def commit(key)
        raise NotImplementedError
      end

      # @param key [String] The artifact cache key.
      # @return [Boolean] true if the artifact was already consumed.
      def consumed?(key)
        raise NotImplementedError
      end
    end

    # Simple in-memory artifact store. Suitable for single-process
    # deployments and tests; multi-process deployments should provide an
    # ArtifactStore implementation backed by shared storage.
    #
    class InMemoryArtifactStore < ArtifactStore
      def initialize
        @mutex = Mutex.new
        @in_flight = {}
        @consumed = {}
      end

      def acquire(key)
        @mutex.synchronize do
          return false if @consumed.key?(key) || @in_flight.key?(key)

          @in_flight[key] = true
          true
        end
      end

      def release(key)
        @mutex.synchronize do
          @in_flight.delete(key)
        end
        true
      end

      def commit(key)
        @mutex.synchronize do
          @in_flight.delete(key)
          @consumed[key] = true
        end
        true
      end

      def consumed?(key)
        @mutex.synchronize do
          @consumed.key?(key)
        end
      end
    end
  end
end
