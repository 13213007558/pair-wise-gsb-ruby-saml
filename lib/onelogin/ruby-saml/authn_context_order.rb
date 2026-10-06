module OneLogin
  module RubySaml
    class AuthnContextOrder
      # Represents "stronger" as an ancestor of "weaker".
      #
      # Accepts a hash of stronger contexts pointing to one or more weaker
      # contexts, or an array of [stronger, weaker] pairs.
      def initialize(order)
        @stronger = {}
        add_edges(order)
        ensure_acyclic
        @reachable = nil
      end

      def stronger?(actual, requested)
        reachable?(actual, requested)
      end

      def weaker?(actual, requested)
        reachable?(requested, actual)
      end

      private

      def add_edges(order)
        return if order.nil?

        if order.is_a?(Hash)
          order.each do |stronger, weaker|
            add_relation(stronger, weaker)
          end
        elsif order.is_a?(Array)
          order.each do |edge|
            unless edge.is_a?(Array) && edge.length == 2
              raise ArgumentError.new("authn_context_order edges must be [stronger, weaker] pairs")
            end

            add_relation(edge[0], edge[1])
          end
        else
          raise ArgumentError.new("authn_context_order must be a Hash or an Array")
        end
      end

      def add_relation(stronger, weaker_contexts)
        stronger = stronger.to_s
        weaker_contexts = [weaker_contexts] unless weaker_contexts.is_a?(Array)
        weaker_contexts.each do |weaker|
          @stronger[stronger] ||= []
          weaker = weaker.to_s
          @stronger[stronger] << weaker unless @stronger[stronger].include?(weaker)
        end
      end

      def reachable?(start, target)
        build_reachable unless @reachable
        reachable_contexts = @reachable[start.to_s]
        !reachable_contexts.nil? && reachable_contexts.key?(target.to_s)
      end

      def build_reachable
        @reachable = {}
        contexts.each { |context| descendants(context) }
      end

      def descendants(context)
        return @reachable[context] if @reachable.key?(context)

        reachable = {}
        @stronger.fetch(context, []).each do |weaker|
          reachable[weaker] = true
          nested_contexts = descendants(weaker)
          next if nested_contexts.nil?
          nested_contexts.each do |nested_weaker, _|
            reachable[nested_weaker] = true
          end
        end

        @reachable[context] = reachable
      end

      def ensure_acyclic
        degrees = Hash.new(0)
        contexts.each { |context| degrees[context] = 0 }
        @stronger.each_value do |weaker_contexts|
          weaker_contexts.each { |weaker| degrees[weaker] += 1 }
        end

        roots = degrees.select { |_, degree| degree == 0 }.keys
        visited = 0

        while roots.any?
          context = roots.shift
          visited += 1
          @stronger.fetch(context, []).each do |weaker|
            degrees[weaker] -= 1
            roots << weaker if degrees[weaker] == 0
          end
        end

        unless visited == contexts.size
          raise ArgumentError.new("Cycle detected in authn_context_order")
        end
      end

      def contexts
        (@stronger.keys + @stronger.values.flatten).uniq
      end
    end
  end
end
