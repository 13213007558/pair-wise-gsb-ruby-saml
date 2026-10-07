require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/authn_context'

class AuthnContextTest < Minitest::Test
  BASE = "urn:example:base"
  LEFT = "urn:example:left"
  RIGHT = "urn:example:right"
  TOP = "urn:example:top"
  OTHER = "urn:example:other"

  def ref(value, type = OneLogin::RubySaml::AuthnContextOrdering::CLASS_REF)
    OneLogin::RubySaml::AuthnContextRef.new(type, value)
  end

  def diamond_ordering
    OneLogin::RubySaml::AuthnContextOrdering.new([
      [BASE, LEFT],
      [BASE, RIGHT],
      [LEFT, TOP],
      [RIGHT, TOP]
    ])
  end

  def request(comparison:, candidates: [BASE])
    OneLogin::RubySaml::RequestedAuthnContext.new(
      request_id: "request-1",
      comparison: comparison,
      class_refs: candidates
    )
  end

  def test_returns_the_auditable_comparison_path_through_the_diamond
    match = request(comparison: "minimum", candidates: [BASE]).match([TOP], diamond_ordering).first

    assert_equal BASE, match.candidate.value
    assert_equal TOP, match.actual.value
    assert_equal [BASE, LEFT, TOP], match.path.map(&:value)
  end

  def test_accepts_each_candidate_that_satisfies_minimum
    left_match = request(comparison: "minimum", candidates: [LEFT, RIGHT]).match([TOP], diamond_ordering).first

    assert_equal LEFT, left_match.candidate.value
    assert_equal [LEFT, TOP], left_match.path.map(&:value)

    right_match = request(comparison: "minimum", candidates: [RIGHT, LEFT]).match([TOP], diamond_ordering).first
    assert_equal RIGHT, right_match.candidate.value
    assert_equal [RIGHT, TOP], right_match.path.map(&:value)
  end

  def test_minimum_and_maximum_treat_equality_as_satisfied_without_a_registered_edge
    assert request(comparison: "minimum", candidates: [OTHER]).matches?([OTHER], OneLogin::RubySaml::AuthnContextOrdering.new)
    assert request(comparison: "maximum", candidates: [OTHER]).matches?([OTHER], OneLogin::RubySaml::AuthnContextOrdering.new)
  end

  def test_exact_does_not_treat_related_contexts_as_equivalent
    matches = request(comparison: "exact", candidates: [BASE]).match([TOP], diamond_ordering)

    assert_empty matches
  end

  def test_better_requires_a_strictly_stronger_context
    assert request(comparison: "better", candidates: [BASE]).matches?([TOP], diamond_ordering)
    refute request(comparison: "better", candidates: [TOP]).matches?([TOP], diamond_ordering)
  end

  def test_maximum_accepts_candidates_that_are_not_weaker_than_actual
    assert request(comparison: "maximum", candidates: [TOP]).matches?([LEFT], diamond_ordering)
    assert request(comparison: "maximum", candidates: [LEFT, RIGHT]).matches?([BASE], diamond_ordering)
  end

  def test_incomparable_contexts_are_not_assumed_stronger
    ordering = OneLogin::RubySaml::AuthnContextOrdering.new([
      [BASE, LEFT],
      [BASE, RIGHT]
    ])

    refute request(comparison: "minimum", candidates: [LEFT]).matches?([RIGHT], ordering)
    refute request(comparison: "maximum", candidates: [RIGHT]).matches?([LEFT], ordering)
    refute request(comparison: "better", candidates: [LEFT]).matches?([RIGHT], ordering)
  end

  def test_unknown_contexts_are_not_assumed_stronger
    refute request(comparison: "minimum", candidates: [BASE]).matches?([OTHER], diamond_ordering)
    refute request(comparison: "better", candidates: [BASE]).matches?([OTHER], diamond_ordering)
  end

  def test_unknown_context_can_still_match_exactly
    assert request(comparison: "exact", candidates: [OTHER]).matches?([OTHER], diamond_ordering)
  end

  def test_does_not_compare_class_refs_with_decl_refs
    declared = ref(BASE, OneLogin::RubySaml::AuthnContextOrdering::DECL_REF)
    requested = OneLogin::RubySaml::RequestedAuthnContext.new(
      request_id: "request-1",
      comparison: "minimum",
      class_refs: [BASE]
    )

    refute requested.matches?([declared], diamond_ordering)
  end

  def test_rejects_a_relation_cycle_when_configured
    error = assert_raises(ArgumentError) do
      OneLogin::RubySaml::AuthnContextOrdering.new([
        [BASE, LEFT],
        [LEFT, RIGHT],
        [RIGHT, BASE]
      ])
    end

    assert_match(/cycle/, error.message)
  end

  def test_rejects_a_self_relation_as_a_cycle
    error = assert_raises(ArgumentError) do
      OneLogin::RubySaml::AuthnContextOrdering.new([[BASE, BASE]])
    end

    assert_match(/cycle/, error.message)
  end

  def test_accepts_relations_registered_as_a_hash
    ordering = OneLogin::RubySaml::AuthnContextOrdering.new(BASE => TOP)

    assert_equal [BASE, TOP], ordering.path_to(ref(TOP), ref(BASE)).map(&:value)
  end
end
