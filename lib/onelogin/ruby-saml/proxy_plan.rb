module OneLogin
  module RubySaml

    # Plans the next hop of an identity proxy.
    #
    # An identity proxy that holds an already validated assertion may need to
    # authenticate towards a downstream relying party, but it must not exceed
    # the limits the original IdP expressed through the assertion's
    # <ProxyRestriction> condition, nor the limits the incoming request
    # expressed through its <Scoping> element.
    #
    # This class only computes the constraint set the proxy is allowed to
    # propagate (or the reason the hop must be rejected). Issuing the actual
    # downstream assertion/request is left to the application.
    #
    # Semantics:
    # - A ProxyRestriction without a Count attribute allows unlimited
    #   proxying (only the audience, if listed, is constrained).
    # - Count="0" forbids any further proxying and rejects the hop.
    # - Count="n" (n > 0) allows this hop and leaves n - 1 hops downstream.
    # - The request's Scoping ProxyCount can only tighten (lower) the count.
    # - The request's requested audiences can only tighten (narrow) the
    #   audiences allowed by the ProxyRestriction.
    class ProxyPlan

      # The outcome of a plan evaluation.
      class Result
        # @return [Boolean] true when the next hop may proceed
        attr_reader :allowed

        # @return [Symbol, nil] machine readable rejection reason
        #   (:proxy_count_exhausted or :audience_not_allowed)
        attr_reader :rejection_reason

        # @return [String, nil] human readable rejection message
        attr_reader :rejection_message

        # @return [Hash] constraints the proxy may send downstream:
        #   { :proxy_count => Integer|nil, :audiences => Array<String> }
        #   A nil :proxy_count means unlimited remaining hops.
        #   An empty :audiences array means no audience constraint.
        attr_reader :constraints

        def initialize(allowed:, constraints: {}, rejection_reason: nil, rejection_message: nil)
          @allowed = allowed
          @constraints = constraints
          @rejection_reason = rejection_reason
          @rejection_message = rejection_message
        end

        def allowed?
          @allowed
        end
      end

      class << self

        # Evaluates whether the proxy may forward to the next hop and
        # computes the constraints it is allowed to propagate.
        #
        # @param proxy_restriction [Hash] limits from the validated assertion:
        #   { :count => Integer|nil, :audiences => Array<String> }
        #   A nil :count means the Count attribute was not written
        #   (unlimited proxying); 0 means proxying is forbidden.
        # @param scoping [Hash] limits from the incoming request:
        #   { :proxy_count => Integer|nil, :requested_audiences => Array<String> }
        # @return [ProxyPlan::Result]
        def evaluate(proxy_restriction: {}, scoping: {})
          restriction_count = proxy_restriction[:count]
          restriction_audiences = Array(proxy_restriction[:audiences])
          scoping_count = scoping[:proxy_count]
          requested_audiences = Array(scoping[:requested_audiences])

          # An absent Count and Count="0" are different: nil is unlimited,
          # 0 forbids this hop entirely.
          if restriction_count == 0 || scoping_count == 0
            return reject(:proxy_count_exhausted,
              "Proxying is not permitted: a Count of 0 forbids further hops")
          end

          # Downstream requests can only tighten the count, never raise it.
          effective_count = restriction_count
          if !scoping_count.nil? && (effective_count.nil? || scoping_count < effective_count)
            effective_count = scoping_count
          end

          # This hop consumes one indirection.
          remaining_count = effective_count.nil? ? nil : effective_count - 1

          # The next-hop audience must stay within the ProxyRestriction
          # audiences; the request may only narrow that set further.
          if !restriction_audiences.empty?
            disallowed = requested_audiences - restriction_audiences
            unless disallowed.empty?
              return reject(:audience_not_allowed,
                "Requested audience(s) #{disallowed.join(', ')} not allowed by the ProxyRestriction")
            end
          end
          acceptable_audiences = requested_audiences.empty? ? restriction_audiences.dup : requested_audiences.dup

          Result.new(
            :allowed => true,
            :constraints => {
              :proxy_count => remaining_count,
              :audiences => acceptable_audiences
            }
          )
        end

        # Extracts the ProxyRestriction limits from the Conditions element
        # of a validated response.
        #
        # @param conditions [REXML::Element, nil] the assertion Conditions
        # @return [Hash] { :count => Integer|nil, :audiences => Array<String> }
        #   Returns an empty Hash when no ProxyRestriction is present.
        def restriction_from_conditions(conditions)
          return {} if conditions.nil?

          element = nil
          conditions.elements.each do |child|
            if child.name == "ProxyRestriction"
              element = child
              break
            end
          end
          return {} if element.nil?

          count = element.attributes["Count"]
          audiences = []
          element.elements.each do |child|
            if child.name == "Audience"
              text = Utils.element_text(child)
              audiences << text unless text.empty?
            end
          end

          { :count => count.nil? ? nil : count.to_i, :audiences => audiences }
        end

        # Extracts the Scoping limits from an AuthnRequest document.
        #
        # @param document [REXML::Document] the decoded AuthnRequest
        # @return [Hash] { :proxy_count => Integer|nil,
        #   :requested_audiences => Array<String> }
        def scoping_from_request(document)
          scoping = REXML::XPath.first(document, "/p:AuthnRequest/p:Scoping", { "p" => SamlMessage::PROTOCOL })
          scoping ||= REXML::XPath.first(document, "//*[local-name()='Scoping']")
          return {} if scoping.nil?

          proxy_count = scoping.attributes["ProxyCount"]
          requested = []
          scoping.elements.each do |child|
            if child.name == "RequesterID"
              text = Utils.element_text(child)
              requested << text unless text.empty?
            end
          end

          { :proxy_count => proxy_count.nil? ? nil : proxy_count.to_i, :requested_audiences => requested }
        end

        private

        def reject(reason, message)
          Result.new(
            :allowed => false,
            :rejection_reason => reason,
            :rejection_message => message
          )
        end
      end
    end
  end
end
