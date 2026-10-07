require "onelogin/ruby-saml/validation_error"

module OneLogin
  module RubySaml
    class AuthnContextOrdering
      attr_reader :relations

      def initialize(relations = {})
        @relations = {}
        @successors = {}

        normalize(relations)
        validate_acyclic!
      end

      def path(from, to)
        from = reference_value(from)
        to = reference_value(to)
        return [from] if from == to

        visited = { from => true }
        queue = [[from, [from]]]

        until queue.empty?
          node, current_path = queue.shift

          successors(node).sort.each do |successor|
            next_path = current_path + [successor]
            return next_path if successor == to
            next if visited[successor]

            visited[successor] = true
            queue << [successor, next_path]
          end
        end

        nil
      end

      def stronger?(stronger, weaker)
        !path(weaker, stronger).nil?
      end

      def comparable?(first, second)
        first = reference_value(first)
        second = reference_value(second)
        first == second || !path(first, second).nil? || !path(second, first).nil?
      end

      private

      def normalize(relations)
        case relations
        when Hash
          relations.each_pair do |weaker, stronger_values|
            Array(stronger_values).each { |stronger| add_relation(weaker, stronger) }
          end
        when Enumerable
          relations.each do |relation|
            if relation.is_a?(Hash)
              add_relation(relation[:weaker] || relation['weaker'], relation[:stronger] || relation['stronger'])
            else
              add_relation(relation[0], relation[1])
            end
          end
        when nil
        else
          raise ArgumentError.new("Authn context ordering must be a Hash or Enumerable")
        end
      end

      def add_relation(weaker, stronger)
        weaker = reference_value(weaker)
        stronger = reference_value(stronger)

        (@relations[weaker] ||= [])
        (@relations[stronger] ||= [])
        @successors[weaker] ||= []
        @successors[stronger] ||= []

        unless @successors[weaker].include?(stronger)
          @successors[weaker] << stronger
          @relations[weaker] << stronger
        end
      end

      def validate_acyclic!
        indegrees = {}
        @successors.keys.each { |node| indegrees[node] = 0 }
        @successors.values.each { |values| values.each { |node| indegrees[node] += 1 } }

        queue = indegrees.select { |_, indegree| indegree == 0 }.keys.sort
        visited = 0

        until queue.empty?
          node = queue.shift
          visited += 1

          successors(node).each do |successor|
            indegrees[successor] -= 1
            queue.insert(insertion_index(queue, successor), successor) if indegrees[successor] == 0
          end
        end

        if visited != indegrees.size
          raise ArgumentError.new("Authn context ordering contains a cycle")
        end

        @relations.each_value(&:freeze)
        @relations.freeze
        @successors.each_value(&:freeze)
        @successors.freeze
      end

      def successors(node)
        @successors[node] || []
      end

      def insertion_index(queue, node)
        queue.each_with_index do |queued_node, index|
          return index if node < queued_node
        end
        queue.length
      end

      def reference_value(value)
        value = value.to_s.strip if value.respond_to?(:to_s)
        if value.nil? || value.empty?
          raise ArgumentError.new("Authn context references cannot be blank")
        end
        value
      end
    end

    class AuthnContextReference
      TYPES = [:class_ref, :decl_ref].freeze

      attr_reader :type, :value

      def initialize(type, value)
        type = type.to_sym
        unless TYPES.include?(type)
          raise ArgumentError.new("Authn context reference type must be :class_ref or :decl_ref")
        end

        value = value.to_s.strip if value.respond_to?(:to_s)
        if value.nil? || value.empty?
          raise ArgumentError.new("Authn context reference cannot be blank")
        end

        @type = type
        @value = value
      end

      def ==(other)
        other.is_a?(AuthnContextReference) && type == other.type && value == other.value
      end
      alias_method :eql?, :==

      def hash
        [type, value].hash
      end

      def to_h
        { :type => type, :value => value }
      end
    end

    class RequestedAuthnContext
      COMPARISONS = ["exact", "minimum", "maximum", "better"].freeze

      attr_reader :request_id, :comparison, :class_refs, :decl_refs, :candidates, :ordering

      def initialize(options = {})
        @request_id = options[:request_id]
        @comparison = (options[:comparison] || "exact").to_s
        unless COMPARISONS.include?(@comparison)
          raise ArgumentError.new("Authn context comparison must be one of #{COMPARISONS.join(', ')}")
        end

        @class_refs = normalize_references(options[:class_refs] || options[:class_ref], :class_ref)
        @decl_refs = normalize_references(options[:decl_refs] || options[:decl_ref], :decl_ref)
        @candidates = @class_refs + @decl_refs

        if @candidates.empty?
          raise ArgumentError.new("Requested authn context must contain at least one candidate")
        end

        ordering = options[:ordering]
        @ordering = ordering.is_a?(AuthnContextOrdering) ? ordering : AuthnContextOrdering.new(ordering)
      end

      def self.from_settings(settings, request_id = nil)
        new(
          :request_id => request_id,
          :comparison => settings.authn_context_comparison,
          :class_refs => settings.authn_context,
          :decl_refs => settings.authn_context_decl_ref,
          :ordering => settings.respond_to?(:authn_context_ordering) ? settings.authn_context_ordering : nil
        )
      end

      def match(actual)
        return nil unless actual.is_a?(AuthnContextReference)

        matching_candidates = candidates_of_type(actual.type)
        case comparison
        when "exact"
          candidate = matching_candidates.detect { |candidate_reference| candidate_reference.value == actual.value }
          build_match(candidate, actual, candidate.nil? ? nil : [candidate.value]) if candidate
        when "minimum"
          candidate = matching_candidates.detect { |candidate_reference| ordering.path(candidate_reference.value, actual.value) }
          build_match(candidate, actual, ordering.path(candidate.value, actual.value)) if candidate
        when "maximum"
          candidate = matching_candidates.detect { |candidate_reference| ordering.path(actual.value, candidate_reference.value) }
          build_match(candidate, actual, ordering.path(actual.value, candidate.value)) if candidate
        when "better"
          paths = matching_candidates.collect do |candidate_reference|
            path = ordering.path(candidate_reference.value, actual.value)
            if path.nil? || path.length < 2
              return nil
            end
            { :candidate => candidate_reference, :path => path }
          end
          build_better_match(matching_candidates, actual, paths) unless paths.empty?
        end
      end

      private

      def normalize_references(values, type)
        Array(values).collect do |value|
          next if value.nil?
          value = value.to_s.strip
          next if value.empty?
          AuthnContextReference.new(type, value)
        end.compact.uniq
      end

      def candidates_of_type(type)
        candidates.select { |candidate| candidate.type == type }
      end

      def build_match(candidate, actual, path)
        AuthnContextMatch.new(
          :request_id => request_id,
          :comparison => comparison,
          :candidate => candidate,
          :candidates => [candidate],
          :actual => actual,
          :paths => [{ :candidate => candidate, :path => path }]
        )
      end

      def build_better_match(candidates, actual, paths)
        AuthnContextMatch.new(
          :request_id => request_id,
          :comparison => comparison,
          :candidate => nil,
          :candidates => candidates,
          :actual => actual,
          :paths => paths
        )
      end
    end

    class AuthnContextMatch
      attr_reader :request_id, :comparison, :candidate, :candidates, :actual, :paths

      def initialize(options)
        @request_id = options[:request_id]
        @comparison = options[:comparison]
        @candidate = options[:candidate]
        @candidates = options[:candidates]
        @actual = options[:actual]
        @paths = options[:paths]
      end

      def path
        paths.first[:path] if paths && paths.size == 1
      end

      def to_h
        {
          :request_id => request_id,
          :comparison => comparison,
          :candidate => candidate.nil? ? nil : candidate.to_h,
          :candidates => candidates.collect(&:to_h),
          :actual => actual.to_h,
          :path => path,
          :paths => paths.collect { |item| { :candidate => item[:candidate].to_h, :path => item[:path] } }
        }
      end
    end
  end
end
