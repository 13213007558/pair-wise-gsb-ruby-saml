module OneLogin
  module RubySaml
    class AuthnContextRef
      attr_reader :type, :value

      def self.cast(reference, type)
        reference.is_a?(AuthnContextRef) ? reference : new(type, reference)
      end

      def initialize(type, value)
        @type = type
        @value = value
      end

      def key
        [type, value]
      end

      def ==(other)
        other.is_a?(AuthnContextRef) && key == other.key
      end
      alias_method :eql?, :==

      def hash
        key.hash
      end

      def to_s
        value
      end
    end

    class AuthnContextOrdering
      CLASS_REF = "class_ref".freeze
      DECL_REF = "decl_ref".freeze

      attr_reader :relations

      def initialize(relations = [])
        @relations = {}

        normalized_relations(relations).each do |weaker, stronger|
          @relations[weaker.key] ||= []
          @relations[weaker.key] << stronger unless @relations[weaker.key].include?(stronger)
        end

        reject_cycles!
      end

      def stronger?(strong_ref, weak_ref)
        path = path_to(strong_ref, weak_ref)
        path && path.length > 1 ? path : nil
      end

      def stronger_or_equal?(strong_ref, weak_ref)
        return [strong_ref] if same_ref?(strong_ref, weak_ref)

        stronger?(strong_ref, weak_ref)
      end

      def path_to(strong_ref, weak_ref)
        return unless same_type?(strong_ref, weak_ref)
        return [weak_ref] if same_ref?(strong_ref, weak_ref)

        queue = [[weak_ref, [weak_ref]]]
        visited = { weak_ref.key => true }

        until queue.empty?
          current, path = queue.shift
          direct_successors(current).each do |successor|
            next_path = path + [successor]
            return next_path if same_ref?(successor, strong_ref)

            next if visited.key?(successor.key)
            visited[successor.key] = true
            queue << [successor, next_path]
          end
        end

        nil
      end

      private

      def normalized_relations(relations)
        relation_pairs = relations.is_a?(Hash) ? relations.to_a : Array(relations)

        relation_pairs.map do |weaker, stronger|
          weaker = AuthnContextRef.cast(weaker, CLASS_REF) unless weaker.is_a?(AuthnContextRef)
          stronger = AuthnContextRef.cast(stronger, CLASS_REF) unless stronger.is_a?(AuthnContextRef)

          unless weaker.type == stronger.type
            raise ArgumentError.new("Authentication context relation types must match")
          end

          [weaker, stronger]
        end
      end

      def direct_successors(reference)
        (@relations[reference.key] || []).dup
      end

      def same_type?(first, second)
        first.type == second.type
      end

      def same_ref?(first, second)
        first.key == second.key
      end

      def reject_cycles!
        state = {}

        @relations.keys.each do |key|
          visit(key, state)
        end
      end

      def visit(key, state)
        return if state[key] == :visited
        raise ArgumentError.new("Authentication context ordering contains a cycle") if state[key] == :visiting

        state[key] = :visiting
        (@relations[key] || []).each { |reference| visit(reference.key, state) }
        state[key] = :visited
      end
    end

    class AuthnContextMatch
      attr_reader :request_id, :actual, :candidate, :comparison, :path,
                  :authn_statement_id, :authn_statement_index

      def initialize(request_id:, actual:, candidate:, comparison:, path:,
                     authn_statement_id: nil, authn_statement_index: nil)
        @request_id = request_id
        @actual = actual
        @candidate = candidate
        @comparison = comparison
        @path = path
        @authn_statement_id = authn_statement_id
        @authn_statement_index = authn_statement_index
      end
    end

    class ActualAuthnContext
      attr_reader :ref, :authn_statement_id, :authn_statement_index

      def initialize(ref:, authn_statement_id: nil, authn_statement_index: nil)
        @ref = ref
        @authn_statement_id = authn_statement_id
        @authn_statement_index = authn_statement_index
      end

      def type
        ref.type
      end

      def value
        ref.value
      end

      def key
        ref.key
      end
    end

    class RequestedAuthnContext
      COMPARISONS = %w(exact minimum maximum better).freeze

      attr_reader :request_id, :comparison, :class_refs, :decl_refs

      def initialize(request_id: nil, comparison: nil, class_refs: nil, decl_refs: nil,
                     authn_context_class_refs: nil, authn_context_decl_refs: nil)
        @request_id = request_id
        @comparison = (comparison || "exact").to_s
        @class_refs = normalize_refs(class_refs || authn_context_class_refs, AuthnContextOrdering::CLASS_REF)
        @decl_refs = normalize_refs(decl_refs || authn_context_decl_refs, AuthnContextOrdering::DECL_REF)
      end

      def candidates
        class_refs + decl_refs
      end

      def present?
        !candidates.empty?
      end

      def match(actual_contexts, ordering)
        validate_comparison!
        actual_contexts = Array(actual_contexts)
        return [] if actual_contexts.empty?

        actual_contexts.each_with_index.map do |actual, index|
          context_ref = context_ref(actual)
          candidate, path = matching_candidate(context_ref, ordering)
          next unless candidate

          AuthnContextMatch.new(
            request_id: request_id,
            actual: context_ref,
            candidate: candidate,
            comparison: comparison,
            path: path,
            authn_statement_id: actual.respond_to?(:authn_statement_id) ? actual.authn_statement_id : nil,
            authn_statement_index: actual.respond_to?(:authn_statement_index) ? actual.authn_statement_index : index
          )
        end.compact
      end

      def matches?(actual_contexts, ordering)
        matches = match(actual_contexts, ordering)
        !matches.empty? && matches.length == Array(actual_contexts).length
      end

      private

      def normalize_refs(references, type)
        Array(references).map do |reference|
          AuthnContextRef.cast(reference, type)
        end
      end

      def context_ref(actual)
        return actual.ref if actual.respond_to?(:ref)

        actual.is_a?(AuthnContextRef) ? actual : AuthnContextRef.new(AuthnContextOrdering::CLASS_REF, actual)
      end

      def validate_comparison!
        return if COMPARISONS.include?(comparison)

        raise ArgumentError.new("Unsupported RequestedAuthnContext comparison: #{comparison}")
      end

      def matching_candidate(actual, ordering)
        candidates.each do |candidate|
          next unless candidate.type == actual.type

          case comparison
          when "exact"
            return [candidate, [actual]] if candidate == actual
          when "minimum"
            path = ordering.path_to(actual, candidate)
            return [candidate, path] if path
          when "maximum"
            path = ordering.path_to(candidate, actual)
            return [candidate, path] if path
          when "better"
            next if candidate == actual

            path = ordering.path_to(actual, candidate)
            return [candidate, path] if path
          end
        end

        nil
      end
    end
  end
end
