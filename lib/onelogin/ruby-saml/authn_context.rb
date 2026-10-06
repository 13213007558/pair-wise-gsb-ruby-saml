require "onelogin/ruby-saml/setting_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Evaluates whether the AuthnContextClassRef of a SAML Response
    # satisfies the RequestedAuthnContext declared by the SP.
    #
    # The strength relationships between authentication context classes
    # are configured by the caller as a partial order: a Hash that maps
    # each class to the classes that are directly stronger than it.
    # Classes without a declared relationship are not comparable; no
    # strength is inferred from the class URI or from any list position.
    #
    module AuthnContext
      COMPARISONS = %w[exact minimum maximum better].freeze

      # Validates that the configured partial order does not contain cycles.
      # @param strengths [Hash] Hash mapping a class to the classes directly stronger than it
      # @raise [SettingError] if a cycle is detected
      #
      def self.validate_order!(strengths)
        return if strengths.nil?

        state = {}
        strengths.each_key do |node|
          detect_cycle(node, strengths, state, [])
        end
      end

      # Checks if the actual class satisfies the requested classes
      # according to the SAML comparison rules.
      # @param actual [String] AuthnContextClassRef of the SAML Response
      # @param requested [String, Array] Requested AuthnContextClassRef(s)
      # @param comparison [String] 'exact', 'minimum', 'maximum' or 'better'
      # @param strengths [Hash] Partial order of class strengths
      # @return [Boolean] True if the actual class satisfies the request
      #
      def self.satisfies?(actual, requested, comparison, strengths)
        requested = [requested] unless requested.is_a?(Array)

        case comparison
        when nil, "exact"
          requested.include?(actual)
        when "minimum"
          requested.any? { |ref| actual == ref || stronger?(actual, ref, strengths) }
        when "maximum"
          requested.any? { |ref| actual == ref || stronger?(ref, actual, strengths) }
        when "better"
          requested.any? { |ref| stronger?(actual, ref, strengths) }
        else
          false
        end
      end

      # Checks if the candidate class is strictly stronger than the
      # reference class, following the transitive closure of the
      # configured partial order.
      # @return [Boolean] True if candidate is strictly stronger than reference
      #
      def self.stronger?(candidate, reference, strengths)
        return false if strengths.nil?

        visited = {}
        stack = Array(strengths[reference]).dup
        until stack.empty?
          node = stack.pop
          next if visited[node]
          return true if node == candidate

          visited[node] = true
          stack.concat(Array(strengths[node]))
        end
        false
      end

      def self.detect_cycle(node, strengths, state, stack)
        return if state[node] == :done

        if state[node] == :visiting
          cycle = (stack.drop(stack.index(node)) + [node]).join(" -> ")
          raise SettingError.new("Cyclic authn_context_strengths configuration detected: " + cycle)
        end

        state[node] = :visiting
        Array(strengths[node]).each do |stronger|
          detect_cycle(stronger, strengths, state, stack + [node])
        end
        state[node] = :done
      end
      private_class_method :detect_cycle
    end
  end
end
