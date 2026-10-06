require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ProxyPlanTest < Minitest::Test

  describe "ProxyPlan" do

    describe "count handling" do
      it "treats an absent Count as unlimited proxying" do
        result = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => nil, :audiences => [] }
        )
        assert result.allowed?
        assert_nil result.constraints[:proxy_count]
      end

      it "rejects Count=0 while an absent Count is allowed" do
        result = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 0, :audiences => [] }
        )
        refute result.allowed?
        assert_equal :proxy_count_exhausted, result.rejection_reason
      end

      it "rejects a request Scoping ProxyCount of 0" do
        result = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 3, :audiences => [] },
          :scoping => { :proxy_count => 0 }
        )
        refute result.allowed?
        assert_equal :proxy_count_exhausted, result.rejection_reason
      end

      it "consumes one hop and propagates the remaining count" do
        result = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 2, :audiences => [] }
        )
        assert result.allowed?
        assert_equal 1, result.constraints[:proxy_count]
      end

      it "lets the request Scoping only tighten the count, never raise it" do
        tightened = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 5, :audiences => [] },
          :scoping => { :proxy_count => 2 }
        )
        assert_equal 1, tightened.constraints[:proxy_count]

        not_loosened = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 2, :audiences => [] },
          :scoping => { :proxy_count => 9 }
        )
        assert_equal 1, not_loosened.constraints[:proxy_count]
      end
    end

    describe "audience handling" do
      it "accepts a requested audience inside the ProxyRestriction set" do
        result = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 1, :audiences => %w[proxy-b sp-c] },
          :scoping => { :requested_audiences => %w[sp-c] }
        )
        assert result.allowed?
        assert_equal %w[sp-c], result.constraints[:audiences]
      end

      it "rejects a requested audience outside the ProxyRestriction set" do
        result = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 1, :audiences => %w[proxy-b] },
          :scoping => { :requested_audiences => %w[evil-sp] }
        )
        refute result.allowed?
        assert_equal :audience_not_allowed, result.rejection_reason
      end

      it "propagates the restriction audiences when the request narrows nothing" do
        result = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 1, :audiences => %w[proxy-b sp-c] }
        )
        assert result.allowed?
        assert_equal %w[proxy-b sp-c], result.constraints[:audiences]
      end

      it "allows any audience when the restriction lists none" do
        result = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 1, :audiences => [] },
          :scoping => { :requested_audiences => %w[anything] }
        )
        assert result.allowed?
        assert_equal %w[anything], result.constraints[:audiences]
      end
    end

    describe "extraction helpers" do
      it "reads ProxyRestriction from a Conditions element" do
        document = REXML::Document.new(<<~XML)
          <saml:Conditions xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:ProxyRestriction Count="2">
              <saml:Audience>proxy-b</saml:Audience>
              <saml:Audience>sp-c</saml:Audience>
            </saml:ProxyRestriction>
          </saml:Conditions>
        XML
        restriction = OneLogin::RubySaml::ProxyPlan.restriction_from_conditions(document.root)
        assert_equal 2, restriction[:count]
        assert_equal %w[proxy-b sp-c], restriction[:audiences]
      end

      it "returns an empty hash when no ProxyRestriction exists" do
        document = REXML::Document.new('<Conditions xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>')
        assert_equal({}, OneLogin::RubySaml::ProxyPlan.restriction_from_conditions(document.root))
        assert_equal({}, OneLogin::RubySaml::ProxyPlan.restriction_from_conditions(nil))
      end

      it "reads Scoping from an AuthnRequest document" do
        document = REXML::Document.new(<<~XML)
          <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
            <samlp:Scoping ProxyCount="1">
              <samlp:RequesterID>sp-c</samlp:RequesterID>
            </samlp:Scoping>
          </samlp:AuthnRequest>
        XML
        scoping = OneLogin::RubySaml::ProxyPlan.scoping_from_request(document)
        assert_equal 1, scoping[:proxy_count]
        assert_equal %w[sp-c], scoping[:requested_audiences]
      end
    end

    describe "three-hop chain (IdP -> proxy-a -> proxy-b -> sp-c)" do
      # Hop 1: proxy-a plans the hop to proxy-b.
      # Hop 2: proxy-b plans the hop to sp-c.
      # Hop 3: sp-c is terminal; any further hop must be rejected.

      it "fails the third hop on count after two allowed hops" do
        hop1 = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 2, :audiences => %w[proxy-b sp-c] },
          :scoping => { :requested_audiences => %w[proxy-b] }
        )
        assert hop1.allowed?
        assert_equal 1, hop1.constraints[:proxy_count]

        hop2 = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => hop1.constraints[:proxy_count],
                                  :audiences => hop1.constraints[:audiences] },
          :scoping => { :requested_audiences => %w[sp-c] }
        )
        refute hop2.allowed?, "hop 2 must fail: the restriction only names proxy-b"
        assert_equal :audience_not_allowed, hop2.rejection_reason
      end

      it "fails the final hop on count when the chain is fully consumed" do
        hop1 = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => 2, :audiences => %w[proxy-b sp-c] },
          :scoping => { :requested_audiences => %w[proxy-b sp-c] }
        )
        assert hop1.allowed?

        hop2 = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => hop1.constraints[:proxy_count],
                                  :audiences => hop1.constraints[:audiences] },
          :scoping => { :requested_audiences => %w[sp-c] }
        )
        assert hop2.allowed?
        assert_equal 0, hop2.constraints[:proxy_count]

        hop3 = OneLogin::RubySaml::ProxyPlan.evaluate(
          :proxy_restriction => { :count => hop2.constraints[:proxy_count],
                                  :audiences => hop2.constraints[:audiences] }
        )
        refute hop3.allowed?, "hop 3 must fail: the count is exhausted"
        assert_equal :proxy_count_exhausted, hop3.rejection_reason
      end
    end
  end
end
