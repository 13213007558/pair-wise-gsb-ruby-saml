# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Interface of the state store that enforces the one-time-use semantics
    # of SAML artifacts.
    #
    # A store must implement:
    #   consume(key) -> Boolean. Atomically marks the key as consumed.
    #                   Returns true when the key was not consumed before,
    #                   false when it was (replay / concurrent duplicate).
    #   release(key) -> Removes a previously consumed key. Only used when
    #                   the resolution failed before the artifact was
    #                   actually consumed by the IdP (transport errors),
    #                   so the caller is allowed to retry.
    #
    # In production environments inject a shared store (Redis, Memcached,
    # database...) through the :artifact_store option of the resolver.
    #
    module ArtifactStore
      # Thread safe in-memory store. Suitable for single process
      # deployments and for tests.
      #
      class Memory
        def initialize
          @consumed = {}
          @mutex = Mutex.new
        end

        # Atomically marks the key as consumed.
        # @param key [String] The artifact message handle key
        # @return [Boolean] True if the key was not consumed before
        #
        def consume(key)
          @mutex.synchronize do
            return false if @consumed.key?(key)

            @consumed[key] = Time.now.utc
            true
          end
        end

        # Removes a consumed key, allowing a later retry.
        # @param key [String] The artifact message handle key
        #
        def release(key)
          @mutex.synchronize { @consumed.delete(key) }
          nil
        end

        # @param key [String] The artifact message handle key
        # @return [Boolean] True if the key was already consumed
        #
        def consumed?(key)
          @mutex.synchronize { @consumed.key?(key) }
        end
      end
    end
  end
end
