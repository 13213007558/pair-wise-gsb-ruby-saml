require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/response'

class RequestedAuthnContextTest < Minitest::Test
  PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
  PASSWORD_PROTECTED = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
  MFA = "https://example.example/authn-context/mfa"
  HARDWARE = "https://example.example/authn-context/hardware"
  TOP = "https://example.example/authn-context/top"
  DECLARATION = "https://example.example/authn-context/declaration"

  def diamond_ordering
    OneLogin::RubySaml::AuthnContextOrdering.new(
      MFA => TOP,
      HARDWARE => TOP
    )
  end

  def build_response(request_id = "request-1", type = :class_ref, value = PASSWORD, include_context = true)
    context_xml = ""
    if include_context
      element = type == :decl_ref ? "AuthnContextDeclRef" : "AuthnContextClassRef"
      context_xml = "<saml:AuthnStatement><saml:AuthnContext><saml:#{element}>#{value}</saml:#{element}></saml:AuthnContext></saml:AuthnStatement>"
    end

    in_response_to = request_id.nil? ? "" : %Q( InResponseTo="#{request_id}")
    xml = <<-XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="response-1" Version="2.0"#{in_response_to}>
  <saml:Assertion ID="assertion-1">#{context_xml}</saml:Assertion>
</samlp:Response>
XML

    OneLogin::RubySaml::Response.new(xml)
  end

  def signed_assertion(response)
    REXML::XPath.first(response.document, "/p:Response/a:Assertion", OneLogin::RubySaml::Response::SAML_NAMESPACES)
  end

  def test_exact_accepts_a_matching_candidate
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :class_refs => [PASSWORD, PASSWORD_PROTECTED]
    )
    match = constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, PASSWORD_PROTECTED))

    refute_nil match
    assert_equal PASSWORD_PROTECTED, match.candidate.value
    assert_equal [PASSWORD_PROTECTED], match.path
  end

  def test_unknown_and_incomparable_contexts_are_not_stronger
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :comparison => "minimum",
      :class_refs => [MFA],
      :ordering => diamond_ordering
    )

    assert_nil constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, HARDWARE))
    assert_nil constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, "https://example.example/authn-context/unknown"))
  end

  def test_minimum_follows_the_auditable_partial_order
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :comparison => "minimum",
      :class_refs => [MFA],
      :ordering => diamond_ordering
    )
    match = constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, TOP))

    refute_nil match
    assert_equal MFA, match.candidate.value
    assert_equal [MFA, TOP], match.path
  end

  def test_maximum_walks_down_to_a_weaker_candidate
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :comparison => "maximum",
      :class_refs => [MFA],
      :ordering => diamond_ordering
    )
    match = constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, MFA))

    refute_nil match
    assert_equal [MFA], match.path
  end

  def test_maximum_does_not_accept_a_stronger_context
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :comparison => "maximum",
      :class_refs => [MFA],
      :ordering => diamond_ordering
    )

    assert_nil constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, TOP))
  end

  def test_better_requires_a_strict_path_for_every_candidate_in_the_diamond
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :comparison => "better",
      :class_refs => [MFA, HARDWARE],
      :ordering => diamond_ordering
    )
    match = constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, TOP))

    refute_nil match
    assert_nil match.candidate
    assert_equal [[MFA, TOP], [HARDWARE, TOP]], match.paths.collect { |item| item[:path] }

    assert_nil constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, HARDWARE))
    assert_nil constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:class_ref, MFA))
  end

  def test_class_and_declaration_references_are_not_cross_matched
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :class_refs => [PASSWORD],
      :decl_refs => [DECLARATION]
    )

    assert_nil constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:decl_ref, PASSWORD))
    refute_nil constraint.match(OneLogin::RubySaml::AuthnContextReference.new(:decl_ref, DECLARATION))
  end

  def test_ordering_rejects_a_cycle
    assert_raises(ArgumentError) do
      OneLogin::RubySaml::AuthnContextOrdering.new(
        MFA => HARDWARE,
        HARDWARE => MFA
      )
    end
  end

  def test_response_uses_the_constraint_bound_to_its_request_id
    mfa_request = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "mfa-request",
      :comparison => "minimum",
      :class_refs => [MFA],
      :ordering => diamond_ordering
    )
    hardware_request = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "hardware-request",
      :comparison => "minimum",
      :class_refs => [HARDWARE],
      :ordering => diamond_ordering
    )

    response = build_response("hardware-request", :class_ref, TOP)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:requested_authn_contexts] = [mfa_request, hardware_request]

    assert response.send(:validate_requested_authn_context)
    assert_equal "hardware-request", response.authn_context_match.request_id
    assert_equal HARDWARE, response.authn_context_match.candidate.value
    assert_equal [HARDWARE, TOP], response.authn_context_match.path
  end

  def test_response_rejects_when_no_constraint_is_bound_to_the_request_id
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "other-request",
      :class_refs => [MFA]
    )
    response = build_response("request-1", :class_ref, MFA)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:requested_authn_contexts] = [constraint]

    refute response.send(:validate_requested_authn_context)
    assert_includes response.errors, "No requested authentication context found for the Response InResponseTo request-1"
  end

  def test_response_does_not_accept_a_satisfying_context_from_another_request
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "other-request",
      :comparison => "minimum",
      :class_refs => [MFA],
      :ordering => diamond_ordering
    )
    response = build_response("request-1", :class_ref, TOP)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:requested_authn_contexts] = [constraint]

    refute response.send(:validate_requested_authn_context)
    assert_nil response.authn_context_match
  end

  def test_response_rejects_multiple_constraints_for_the_same_request_id
    contexts = 2.times.collect do
      OneLogin::RubySaml::RequestedAuthnContext.new(
        :request_id => "request-1",
        :class_refs => [MFA]
      )
    end
    response = build_response("request-1", :class_ref, MFA)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:requested_authn_contexts] = contexts

    refute response.send(:validate_requested_authn_context)
    assert_includes response.errors, "Multiple requested authentication contexts were registered for the Response InResponseTo request-1"
  end

  def test_response_allows_an_explicit_unsolicited_context_to_be_validated
    unsolicited = OneLogin::RubySaml::RequestedAuthnContext.new(
      :comparison => "minimum",
      :class_refs => [MFA],
      :ordering => diamond_ordering
    )
    response = build_response(nil, :class_ref, TOP)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:allow_unsolicited_response] = true
    response.options[:requested_authn_contexts] = [unsolicited]

    assert response.send(:validate_requested_authn_context)
    assert_equal [MFA, TOP], response.authn_context_match.path
  end

  def test_response_rejects_an_unsolicited_response_by_default
    unsolicited = OneLogin::RubySaml::RequestedAuthnContext.new(
      :class_refs => [MFA]
    )
    response = build_response(nil, :class_ref, MFA)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:requested_authn_contexts] = [unsolicited]

    refute response.send(:validate_requested_authn_context)
    assert_includes response.errors, "A response without InResponseTo was rejected because unsolicited responses are not allowed"
  end

  def test_response_can_skip_validation_for_an_unsolicited_response
    response = build_response(nil, :class_ref, MFA)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:allow_unsolicited_response] = true
    response.options[:requested_authn_contexts] = [
      OneLogin::RubySaml::RequestedAuthnContext.new(:request_id => "request-1", :class_refs => [MFA])
    ]

    assert response.send(:validate_requested_authn_context)
    assert_nil response.authn_context_match
  end

  def test_response_reads_the_actual_decl_ref_from_the_authn_statement
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :decl_refs => [DECLARATION]
    )
    response = build_response("request-1", :decl_ref, DECLARATION)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:requested_authn_context] = constraint

    assert response.send(:validate_requested_authn_context)
    assert_equal :decl_ref, response.authn_context.type
    assert_equal DECLARATION, response.authn_context.value
    assert_equal :decl_ref, response.authn_context_match.actual.type
  end

  def test_response_rejects_a_missing_authn_context
    constraint = OneLogin::RubySaml::RequestedAuthnContext.new(
      :request_id => "request-1",
      :class_refs => [MFA]
    )
    response = build_response("request-1", :class_ref, MFA, false)
    response.stubs(:signed_assertion).returns(signed_assertion(response))
    response.options[:requested_authn_context] = constraint
    response.options[:skip_authnstatement] = true

    refute response.send(:validate_requested_authn_context)
    assert_includes response.errors, "The AuthnContext is missing or empty"
  end
end
