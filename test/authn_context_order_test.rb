require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/authn_context_order'

class RubySamlTest < Minitest::Test
  describe OneLogin::RubySaml::AuthnContextOrder do
    let(:password) { "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" }
    let(:hardware_token) { "urn:oasis:names:tc:SAML:2.0:ac:classes:HardwareToken" }
    let(:smartcard) { "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard" }
    let(:order) do
      OneLogin::RubySaml::AuthnContextOrder.new(
        hardware_token => password,
        smartcard => password
      )
    end

    it "accepts pair arrays and follows the transitive order" do
      mfa = "urn:example:ac:classes:MFA"
      context_order = OneLogin::RubySaml::AuthnContextOrder.new([
        [mfa, smartcard],
        [smartcard, password]
      ])

      assert context_order.stronger?(mfa, password)
      assert context_order.weaker?(password, mfa)
    end

    it "knows when two contexts are stronger than a shared weaker context" do
      assert order.stronger?(hardware_token, password)
      assert order.stronger?(smartcard, password)
    end

    it "does not infer a relationship between unrelated contexts" do
      refute order.stronger?(hardware_token, smartcard)
      refute order.weaker?(hardware_token, smartcard)
    end

    it "does not treat equality as stronger" do
      refute order.stronger?(password, password)
      refute order.weaker?(password, password)
    end

    it "returns false for contexts without a configured relationship" do
      refute order.stronger?(password, "urn:example:ac:classes:Unknown")
      refute order.weaker?("urn:example:ac:classes:Unknown", password)
    end

    it "rejects a cycle when configured" do
      error = assert_raises ArgumentError do
        OneLogin::RubySaml::AuthnContextOrder.new([
          [password, smartcard],
          [smartcard, password]
        ])
      end
      assert_match(/Cycle detected/, error.message)
    end

    it "rejects self loops" do
      assert_raises ArgumentError do
        OneLogin::RubySaml::AuthnContextOrder.new([[password, password]])
      end
    end

    it "rejects an unsupported order shape" do
      assert_raises ArgumentError do
        OneLogin::RubySaml::AuthnContextOrder.new("stronger")
      end
    end
  end
end
