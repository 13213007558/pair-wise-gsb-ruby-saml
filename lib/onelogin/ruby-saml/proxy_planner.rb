require "rexml/document"

require "onelogin/ruby-saml/utils"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Value object representing the <ProxyRestriction> condition of a
    # validated assertion (SAML 2.0 Core, section 2.5.1.5).
    #
    # A missing Count attribute and Count="0" are NOT the same thing:
    # an absent Count imposes no limit on further proxying, while
    # Count="0" forbids any further proxying of the assertion.
    # Likewise, a missing <Audience> list imposes no audience limit.
    #
    class ProxyRestriction
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"

      # @return [Integer|nil] The Count attribute, nil when not specified
      attr_reader :count

      # @return [Array<String>|nil] The permitted audiences, nil when not specified
      attr_reader :audiences

      def initialize(count: nil, count_specified: false, audiences: nil)
        @count = count
        @count_specified = count_specified
        @audiences = audiences
      end

      # @return [Boolean] True when the asserting party wrote an explicit Count
      def count_specified?
        @count_specified
      end

      # @return [Boolean] True when the asserting party listed permitted audiences
      def audiences_specified?
        !@audiences.nil?
      end

      # Builds a ProxyRestriction from a <ProxyRestriction> REXML element.
      # @param element [REXML::Element]
      # @return [OneLogin::RubySaml::ProxyRestriction]
      #
      def self.from_element(element)
        raw_count = element.attributes["Count"]
        audience_nodes = REXML::XPath.match(element, "./a:Audience", { "a" => ASSERTION })
        audiences = audience_nodes.map { |node| Utils.element_text(node) }.reject(&:empty?)

        new(
          :count => raw_count.nil? ? nil : raw_count.to_i,
          :count_specified => !raw_count.nil?,
          :audiences => audiences.empty? ? nil : audiences
        )
      end
    end

    # Value object representing the <Scoping> element of an incoming
    # AuthnRequest (SAML 2.0 Core, section 3.4.1.5).
    #
    # A missing ProxyCount attribute and ProxyCount="0" are NOT the same
    # thing: an absent ProxyCount imposes no limit, while ProxyCount="0"
    # forbids proxying the request to another Identity Provider.
    #
    class Scoping
      PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"

      # @return [Integer|nil] The ProxyCount attribute, nil when not specified
      attr_reader :proxy_count

      # @return [Array<String>|nil] The IDPList ProviderIDs, nil when no IDPList given
      attr_reader :idp_list

      # @return [Array<String>] The RequesterID values, empty when none given
      attr_reader :requester_ids

      def initialize(proxy_count: nil, proxy_count_specified: false, idp_list: nil, requester_ids: [])
        @proxy_count = proxy_count
        @proxy_count_specified = proxy_count_specified
        @idp_list = idp_list
        @requester_ids = requester_ids
      end

      # @return [Boolean] True when the requester wrote an explicit ProxyCount
      def proxy_count_specified?
        @proxy_count_specified
      end

      # Parses the <Scoping> element of an AuthnRequest XML document.
      # @param xml [String] The AuthnRequest XML
      # @return [OneLogin::RubySaml::Scoping|nil] nil when the request has no Scoping
      #
      def self.from_xml(xml)
        document = REXML::Document.new(xml)
        element = REXML::XPath.first(document, "/p:AuthnRequest/p:Scoping", { "p" => PROTOCOL })
        element.nil? ? nil : from_element(element)
      end

      # Builds a Scoping from a <Scoping> REXML element.
      # @param element [REXML::Element]
      # @return [OneLogin::RubySaml::Scoping]
      #
      def self.from_element(element)
        raw_count = element.attributes["ProxyCount"]

        idp_list = nil
        idp_list_element = REXML::XPath.first(element, "./p:IDPList", { "p" => PROTOCOL })
        unless idp_list_element.nil?
          idp_list = REXML::XPath.match(idp_list_element, "./p:IDPEntry", { "p" => PROTOCOL }).map do |entry|
            entry.attributes["ProviderID"]
          end.compact
        end

        requester_ids = REXML::XPath.match(element, "./p:RequesterID", { "p" => PROTOCOL }).map do |node|
          Utils.element_text(node)
        end.reject(&:empty?)

        new(
          :proxy_count => raw_count.nil? ? nil : raw_count.to_i,
          :proxy_count_specified => !raw_count.nil?,
          :idp_list => idp_list,
          :requester_ids => requester_ids
        )
      end
    end

    # The result of a proxy planning check: either a denial reason, or the
    # constraint set the proxy is allowed to propagate downstream.
    # Issuing the actual assertion/AuthnRequest is left to the application.
    #
    class ProxyPlan
      # @return [String|nil] Why proxying was denied, nil when allowed
      attr_reader :denial_reason

      # @return [Hash] The constraints that may be sent downstream:
      #   :proxy_count   [Integer|nil] remaining indirections, nil = unbounded
      #   :audiences     [Array<String>|nil] acceptable recipients, nil = unrestricted
      #   :idp_list      [Array<String>|nil] acceptable next IdPs, nil = unrestricted
      #   :requester_ids [Array<String>] accumulated RequesterID chain
      attr_reader :constraints

      def initialize(denial_reason: nil, constraints: {})
        @denial_reason = denial_reason
        @constraints = constraints
      end

      def self.denied(reason)
        new(:denial_reason => reason)
      end

      # @return [Boolean] True when the next hop may be attempted
      def allowed?
        @denial_reason.nil?
      end

      # Verifies that a proposed outgoing Scoping only TIGHTENS the planned
      # constraints; a downstream request may never loosen them.
      # @param scoping [OneLogin::RubySaml::Scoping] The Scoping the application
      #   wants to place on the outgoing AuthnRequest
      # @return [OneLogin::RubySaml::ProxyPlan] A plan with the merged
      #   (tightened) constraints, or a denial
      #
      def check_outgoing(scoping)
        return ProxyPlan.denied("Cannot derive an outgoing request from a denied plan") unless allowed?
        return self if scoping.nil?

        limit = constraints[:proxy_count]
        if scoping.proxy_count_specified? && !limit.nil? && scoping.proxy_count > limit
          return ProxyPlan.denied("Outgoing Scoping ProxyCount=#{scoping.proxy_count} loosens the planned limit of #{limit}")
        end

        allowed_idps = constraints[:idp_list]
        if !allowed_idps.nil? && !scoping.idp_list.nil?
          extra = scoping.idp_list - allowed_idps
          unless extra.empty?
            return ProxyPlan.denied("Outgoing Scoping IDPList #{extra.inspect} loosens the planned IDPList #{allowed_idps.inspect}")
          end
        end

        ProxyPlan.new(:constraints => {
          :proxy_count => scoping.proxy_count_specified? ? [limit, scoping.proxy_count].compact.min : limit,
          :audiences => constraints[:audiences],
          :idp_list => scoping.idp_list.nil? ? allowed_idps : scoping.idp_list,
          :requester_ids => constraints[:requester_ids]
        })
      end
    end

    # Plans the next hop of an identity proxy chain.
    #
    # Reads the <ProxyRestriction> condition of an already validated
    # assertion and the <Scoping> of the incoming AuthnRequest, then
    # computes how many indirections remain and which audiences / Identity
    # Providers the next hop may target. It never issues anything itself;
    # it only returns the constraint set the application may propagate.
    #
    class ProxyPlanner

      # @param response [OneLogin::RubySaml::Response|nil] A validated Response
      #   (its ProxyRestriction is read when :proxy_restriction is not given)
      # @param proxy_restriction [OneLogin::RubySaml::ProxyRestriction|nil]
      # @param scoping [OneLogin::RubySaml::Scoping|nil] The Scoping of the
      #   incoming AuthnRequest
      # @param requester [String|nil] entityID of the party that asked us
      #   (the recipient of the assertion we would issue next)
      # @param next_idp [String|nil] entityID of the candidate downstream IdP
      # @return [OneLogin::RubySaml::ProxyPlan]
      #
      def self.plan(response: nil, proxy_restriction: nil, scoping: nil, requester: nil, next_idp: nil)
        restriction = proxy_restriction
        restriction = response.proxy_restriction if restriction.nil? && !response.nil?

        remaining = nil

        if !restriction.nil? && restriction.count_specified?
          if restriction.count <= 0
            return ProxyPlan.denied("ProxyRestriction Count=#{restriction.count}: the asserting party does not permit any further proxying")
          end
          remaining = restriction.count - 1
        end

        if !scoping.nil? && scoping.proxy_count_specified?
          if scoping.proxy_count <= 0
            return ProxyPlan.denied("Scoping ProxyCount=#{scoping.proxy_count}: the requester does not permit proxying to another Identity Provider")
          end
          remaining = [remaining, scoping.proxy_count - 1].compact.min
        end

        audiences = restriction.nil? ? nil : restriction.audiences
        if !audiences.nil? && !requester.nil? && !audiences.include?(requester)
          return ProxyPlan.denied("Requester '#{requester}' is not listed in the ProxyRestriction audiences of the assertion")
        end

        idp_list = scoping.nil? ? nil : scoping.idp_list
        if !idp_list.nil? && !next_idp.nil? && !idp_list.include?(next_idp)
          return ProxyPlan.denied("Next Identity Provider '#{next_idp}' is not listed in the Scoping IDPList of the request")
        end

        requester_ids = scoping.nil? ? [] : scoping.requester_ids.dup
        requester_ids << requester unless requester.nil?

        ProxyPlan.new(:constraints => {
          :proxy_count => remaining,
          :audiences => audiences,
          :idp_list => idp_list,
          :requester_ids => requester_ids
        })
      end
    end
  end
end
