require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/response'
require 'onelogin/ruby-saml/proxy_planner'

class ProxyPlannerTest < Minitest::Test

  describe "ProxyPlanner" do
  def restriction(count: nil, audiences: nil)
    OneLogin::RubySaml::ProxyRestriction.new(
      :count => count,
      :count_specified => !count.nil?,
      :audiences => audiences
    )
  end

  def authn_request(scoping_xml)
    %Q{<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2026-10-06T00:00:00Z">#{scoping_xml}</samlp:AuthnRequest>}
  end

  describe "Response#proxy_restriction" do
    it "parses Count and Audience values from the assertion conditions" do
      response = OneLogin::RubySaml::Response.new(fixture(:response_with_proxy_restriction))
      proxy_restriction = response.proxy_restriction

      assert proxy_restriction.count_specified?
      assert_equal 2, proxy_restriction.count
      assert_equal ["https://proxy-c.example", "https://sp-e.example"], proxy_restriction.audiences
    end

    it "returns nil when the assertion has no ProxyRestriction" do
      response = OneLogin::RubySaml::Response.new(response_document_with_signed_assertion)
      assert_nil response.proxy_restriction
    end
  end

  describe "Scoping.from_xml" do
    it "parses ProxyCount, IDPList and RequesterID" do
      scoping = OneLogin::RubySaml::Scoping.from_xml(authn_request(%Q{
        <samlp:Scoping ProxyCount="2">
          <samlp:IDPList>
            <samlp:IDPEntry ProviderID="https://idp-b.example"/>
            <samlp:IDPEntry ProviderID="https://idp-c.example"/>
          </samlp:IDPList>
          <samlp:RequesterID>https://sp-d.example</samlp:RequesterID>
        </samlp:Scoping>}))

      assert scoping.proxy_count_specified?
      assert_equal 2, scoping.proxy_count
      assert_equal ["https://idp-b.example", "https://idp-c.example"], scoping.idp_list
      assert_equal ["https://sp-d.example"], scoping.requester_ids
    end

    it "returns nil when the request has no Scoping element" do
      assert_nil OneLogin::RubySaml::Scoping.from_xml(authn_request(""))
    end

    it "distinguishes a missing ProxyCount from ProxyCount=0" do
      without_count = OneLogin::RubySaml::Scoping.from_xml(authn_request("<samlp:Scoping/>"))
      refute without_count.proxy_count_specified?
      assert_nil without_count.proxy_count

      zero_count = OneLogin::RubySaml::Scoping.from_xml(authn_request(%Q{<samlp:Scoping ProxyCount="0"/>}))
      assert zero_count.proxy_count_specified?
      assert_equal 0, zero_count.proxy_count
    end
  end

  describe "ProxyPlanner count handling" do
    it "treats a missing Count as unbounded and consumes one hop" do
      plan = OneLogin::RubySaml::ProxyPlanner.plan(:proxy_restriction => restriction)
      assert plan.allowed?
      assert_nil plan.constraints[:proxy_count]
    end

    it "denies proxying when Count=0" do
      plan = OneLogin::RubySaml::ProxyPlanner.plan(:proxy_restriction => restriction(:count => 0))
      refute plan.allowed?
      assert_includes plan.denial_reason, "Count=0"
    end

    it "denies proxying when the request Scoping has ProxyCount=0" do
      scoping = OneLogin::RubySaml::Scoping.new(:proxy_count => 0, :proxy_count_specified => true)
      plan = OneLogin::RubySaml::ProxyPlanner.plan(:scoping => scoping)
      refute plan.allowed?
      assert_includes plan.denial_reason, "ProxyCount=0"
    end

    it "keeps the tighter of the ProxyRestriction and Scoping counts" do
      scoping = OneLogin::RubySaml::Scoping.new(:proxy_count => 5, :proxy_count_specified => true)
      plan = OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => restriction(:count => 3),
        :scoping => scoping
      )
      assert plan.allowed?
      assert_equal 2, plan.constraints[:proxy_count]

      scoping = OneLogin::RubySaml::Scoping.new(:proxy_count => 2, :proxy_count_specified => true)
      plan = OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => restriction(:count => 9),
        :scoping => scoping
      )
      assert plan.allowed?
      assert_equal 1, plan.constraints[:proxy_count]
    end
  end

  describe "ProxyPlanner audience and IDPList handling" do
    it "denies a requester outside the ProxyRestriction audiences" do
      plan = OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => restriction(:count => 3, :audiences => ["https://sp-e.example"]),
        :requester => "https://rogue.example"
      )
      refute plan.allowed?
      assert_includes plan.denial_reason, "https://rogue.example"
    end

    it "denies a next IdP outside the Scoping IDPList" do
      scoping = OneLogin::RubySaml::Scoping.new(:idp_list => ["https://idp-b.example"])
      plan = OneLogin::RubySaml::ProxyPlanner.plan(:scoping => scoping, :next_idp => "https://idp-x.example")
      refute plan.allowed?
      assert_includes plan.denial_reason, "https://idp-x.example"
    end

    it "accumulates the RequesterID chain in the constraints" do
      scoping = OneLogin::RubySaml::Scoping.new(:requester_ids => ["https://sp-d.example"])
      plan = OneLogin::RubySaml::ProxyPlanner.plan(:scoping => scoping, :requester => "https://proxy-c.example")
      assert plan.allowed?
      assert_equal ["https://sp-d.example", "https://proxy-c.example"], plan.constraints[:requester_ids]
    end
  end

  describe "ProxyPlan#check_outgoing" do
    let(:plan) {
      OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => restriction(:count => 3, :audiences => ["https://sp-e.example"]),
        :scoping => OneLogin::RubySaml::Scoping.new(:idp_list => ["https://idp-b.example", "https://idp-c.example"])
      )
    }

    it "accepts an outgoing Scoping that tightens the constraints" do
      outgoing = OneLogin::RubySaml::Scoping.new(
        :proxy_count => 1, :proxy_count_specified => true,
        :idp_list => ["https://idp-b.example"]
      )
      tightened = plan.check_outgoing(outgoing)
      assert tightened.allowed?
      assert_equal 1, tightened.constraints[:proxy_count]
      assert_equal ["https://idp-b.example"], tightened.constraints[:idp_list]
    end

    it "rejects an outgoing Scoping that loosens the proxy count" do
      outgoing = OneLogin::RubySaml::Scoping.new(:proxy_count => 5, :proxy_count_specified => true)
      tightened = plan.check_outgoing(outgoing)
      refute tightened.allowed?
      assert_includes tightened.denial_reason, "loosens"
    end

    it "rejects an outgoing Scoping that widens the IDPList" do
      outgoing = OneLogin::RubySaml::Scoping.new(:idp_list => ["https://idp-b.example", "https://idp-x.example"])
      tightened = plan.check_outgoing(outgoing)
      refute tightened.allowed?
      assert_includes tightened.denial_reason, "idp-x.example"
    end
  end

  describe "three-hop proxy chain (IdP-A -> Proxy-B -> Proxy-C -> Proxy-D -> SP-E)" do
    # Each proxy plans its next hop with ProxyPlanner, then (its own
    # responsibility) issues an assertion embedding the tightened count
    # from plan.constraints[:proxy_count].
    def next_restriction_from(plan, audiences = nil)
      remaining = plan.constraints[:proxy_count]
      restriction(:count => remaining, :audiences => audiences)
    end

    it "fails on the third hop when the Count budget is exhausted" do
      # IdP-A allows 2 indirections, no audience restriction.
      hop1 = OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => restriction(:count => 2),
        :requester => "https://proxy-c.example"
      )
      assert hop1.allowed?
      assert_equal 1, hop1.constraints[:proxy_count]

      hop2 = OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => next_restriction_from(hop1),
        :requester => "https://proxy-d.example"
      )
      assert hop2.allowed?
      assert_equal 0, hop2.constraints[:proxy_count]

      # Proxy-D receives an assertion with Count=0: the budget is spent.
      hop3 = OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => next_restriction_from(hop2),
        :requester => "https://sp-e.example"
      )
      refute hop3.allowed?
      assert_includes hop3.denial_reason, "Count=0"
    end

    it "fails on the second hop when the requester is outside the audiences" do
      # IdP-A allows 5 indirections but only towards proxy-c and sp-e.
      audiences = ["https://proxy-c.example", "https://sp-e.example"]

      hop1 = OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => restriction(:count => 5, :audiences => audiences),
        :requester => "https://proxy-c.example"
      )
      assert hop1.allowed?

      # Proxy-C wants to involve Proxy-D, which the asserting party never listed.
      hop2 = OneLogin::RubySaml::ProxyPlanner.plan(
        :proxy_restriction => next_restriction_from(hop1, audiences),
        :requester => "https://proxy-d.example"
      )
      refute hop2.allowed?
      assert_includes hop2.denial_reason, "https://proxy-d.example"
    end
  end
  end
end
