require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/authn_context'

class AuthnContextTest < Minitest::Test
  PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
  PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
  TLS_CLIENT = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
  SMARTCARD_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"

  # PasswordProtectedTransport and TLSClient are both stronger than Password,
  # but no strength relationship is declared between them.
  STRENGTHS = {
    PASSWORD => [PASSWORD_PROTECTED_TRANSPORT, TLS_CLIENT],
    PASSWORD_PROTECTED_TRANSPORT => [SMARTCARD_PKI]
  }.freeze

  describe "AuthnContext" do
    describe ".validate_order!" do
      it "accepts nil" do
        OneLogin::RubySaml::AuthnContext.validate_order!(nil)
      end

      it "accepts an acyclic partial order" do
        OneLogin::RubySaml::AuthnContext.validate_order!(STRENGTHS)
      end

      it "raises a SettingError on a self loop" do
        assert_raises OneLogin::RubySaml::SettingError do
          OneLogin::RubySaml::AuthnContext.validate_order!({ PASSWORD => [PASSWORD] })
        end
      end

      it "raises a SettingError on a direct cycle" do
        assert_raises OneLogin::RubySaml::SettingError do
          OneLogin::RubySaml::AuthnContext.validate_order!({ PASSWORD => [TLS_CLIENT], TLS_CLIENT => [PASSWORD] })
        end
      end

      it "raises a SettingError on an indirect cycle" do
        assert_raises OneLogin::RubySaml::SettingError do
          OneLogin::RubySaml::AuthnContext.validate_order!({
            PASSWORD => [PASSWORD_PROTECTED_TRANSPORT],
            PASSWORD_PROTECTED_TRANSPORT => [SMARTCARD_PKI],
            SMARTCARD_PKI => [PASSWORD]
          })
        end
      end
    end

    describe ".stronger?" do
      it "returns true for a directly stronger class" do
        assert OneLogin::RubySaml::AuthnContext.stronger?(PASSWORD_PROTECTED_TRANSPORT, PASSWORD, STRENGTHS)
      end

      it "returns true for a transitively stronger class" do
        assert OneLogin::RubySaml::AuthnContext.stronger?(SMARTCARD_PKI, PASSWORD, STRENGTHS)
      end

      it "returns false for a weaker class" do
        refute OneLogin::RubySaml::AuthnContext.stronger?(PASSWORD, PASSWORD_PROTECTED_TRANSPORT, STRENGTHS)
      end

      it "returns false for the same class" do
        refute OneLogin::RubySaml::AuthnContext.stronger?(PASSWORD, PASSWORD, STRENGTHS)
      end

      it "returns false for classes without a declared relationship" do
        refute OneLogin::RubySaml::AuthnContext.stronger?(PASSWORD_PROTECTED_TRANSPORT, TLS_CLIENT, STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.stronger?(TLS_CLIENT, PASSWORD_PROTECTED_TRANSPORT, STRENGTHS)
      end

      it "returns false when no partial order is configured" do
        refute OneLogin::RubySaml::AuthnContext.stronger?(PASSWORD_PROTECTED_TRANSPORT, PASSWORD, nil)
      end
    end

    describe ".satisfies?" do
      it "exact requires the class to be one of the requested ones" do
        assert OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, PASSWORD, "exact", STRENGTHS)
        assert OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, [TLS_CLIENT, PASSWORD], "exact", STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, PASSWORD, "exact", STRENGTHS)
      end

      it "minimum requires the class to be at least as strong as one of the requested ones" do
        assert OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, PASSWORD, "minimum", STRENGTHS)
        assert OneLogin::RubySaml::AuthnContext.satisfies?(SMARTCARD_PKI, PASSWORD, "minimum", STRENGTHS)
        assert OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, [TLS_CLIENT, PASSWORD], "minimum", STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, PASSWORD_PROTECTED_TRANSPORT, "minimum", STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, TLS_CLIENT, "minimum", STRENGTHS)
      end

      it "maximum requires the class to not exceed the strength of one of the requested ones" do
        assert OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, PASSWORD, "maximum", STRENGTHS)
        assert OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, PASSWORD_PROTECTED_TRANSPORT, "maximum", STRENGTHS)
        assert OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, [TLS_CLIENT, PASSWORD_PROTECTED_TRANSPORT], "maximum", STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, PASSWORD, "maximum", STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, TLS_CLIENT, "maximum", STRENGTHS)
      end

      it "better requires the class to be strictly stronger than one of the requested ones" do
        assert OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, PASSWORD, "better", STRENGTHS)
        assert OneLogin::RubySaml::AuthnContext.satisfies?(SMARTCARD_PKI, [TLS_CLIENT, PASSWORD], "better", STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, PASSWORD, "better", STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD, PASSWORD_PROTECTED_TRANSPORT, "better", STRENGTHS)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, TLS_CLIENT, "better", STRENGTHS)
      end

      it "does not infer strength from the class URI or the list position" do
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, PASSWORD, "minimum", nil)
        refute OneLogin::RubySaml::AuthnContext.satisfies?(PASSWORD_PROTECTED_TRANSPORT, PASSWORD, "better", {})
      end
    end
  end
end
