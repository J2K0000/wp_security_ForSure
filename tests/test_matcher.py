from wp_security_forsure.scanner.vulndb import matcher

CF7_PAYLOAD = {
    "error": 0, "message": None,
    "data": {
        "name": "Contact Form 7", "plugin": "contact-form-7",
        "latest": "1778813700", "closed": 0,
        "vulnerability": [{
            "uuid": "abc",
            "name": "Contact Form 7 < 5.3.2",
            "description": None,
            "operator": {"min_version": None, "min_operator": None,
                         "max_version": "5.3.2", "max_operator": "lt",
                         "unfixed": "0", "closed": "0"},
            "source": [{"id": "CVE-2020-35489", "name": "CVE-2020-35489",
                        "link": "https://www.cve.org/CVERecord?id=CVE-2020-35489",
                        "description": "Unrestricted file upload", "date": "2020-12-17"}],
            "impact": {"cvss": {"version": "3.1", "vector": "CVSS:3.1/AV:N", "score": "7.2"}},
        }],
    },
}


def test_matches_max_lt():
    op = {"min_version": None, "min_operator": None,
          "max_version": "5.3.2", "max_operator": "lt", "unfixed": "0", "closed": "0"}
    assert matcher.matches("5.2.0", op) is True
    assert matcher.matches("5.3.2", op) is False   # lt = strict
    assert matcher.matches("5.4.0", op) is False


def test_matches_min_max_range():
    op = {"min_version": "2.0", "min_operator": "ge",
          "max_version": "2.5", "max_operator": "le", "unfixed": "0", "closed": "0"}
    assert matcher.matches("1.9", op) is False
    assert matcher.matches("2.0", op) is True      # ge inclusive
    assert matcher.matches("2.5", op) is True      # le inclusive
    assert matcher.matches("2.6", op) is False


def test_matches_unfixed_no_max():
    op = {"min_version": "3.0", "min_operator": "ge",
          "max_version": None, "max_operator": None, "unfixed": "1", "closed": "0"}
    assert matcher.matches("3.0", op) is True
    assert matcher.matches("9.9", op) is True
    assert matcher.matches("2.9", op) is False


def test_pre_release_bound_is_compared():
    op = {"min_version": None, "min_operator": None,
          "max_version": "1.2.3b", "max_operator": "lt", "unfixed": "0", "closed": "0"}
    assert matcher.matches("1.2.2", op) is True     # 1.2.2 < 1.2.3b0
    assert matcher.matches("1.2.3", op) is False    # version finale > pré-version
    assert matcher.matches("1.2.4", op) is False


def test_non_pep440_version_fallback():
    # « 2.0.0-wp-hotfix » n'est pas PEP 440 : repli sur la comparaison numérique.
    op = {"max_version": "2.0.0-wp-hotfix", "max_operator": "lt"}
    assert matcher.matches("1.9.9", op) is True
    assert matcher.matches("2.0.1", op) is False


def test_unknown_operator_is_not_matched_but_flagged():
    op = {"min_version": None, "min_operator": None,
          "max_version": "5.3.2", "max_operator": "eq"}
    assert matcher.match_status("5.3.2", op) == "unknown"
    assert matcher.matches("5.3.2", op) is False
    op_min = {"min_version": "1.0", "min_operator": "from", "max_version": None}
    assert matcher.match_status("2.0", op_min) == "unknown"


def test_known_bound_excluding_wins_over_unknown_operator():
    op = {"min_version": "4.0", "min_operator": "ge",
          "max_version": "5.0", "max_operator": "eq"}
    assert matcher.match_status("3.0", op) == "no_match"


def test_operator_case_and_empty_string_are_normalised():
    assert matcher.match_status("5.0", {"max_version": "5.2", "max_operator": "LT"}) == "match"
    assert matcher.match_status("5.0", {"max_version": "5.2", "max_operator": ""}) == "match"


def _payload(operator, **extra):
    entry = {"name": "Faille", "operator": operator, "source": [], "impact": {}}
    entry.update(extra)
    return {"data": {"vulnerability": [entry]}}


def test_unverifiable_for_lists_unknown_operator_entries():
    payload = _payload({"max_version": "5.3.2", "max_operator": "eq"})
    assert matcher.vulnerabilities_for(payload, "5.3.2") == []
    flagged = matcher.unverifiable_for(payload, "5.3.2")
    assert len(flagged) == 1
    assert flagged[0].title == "Faille"


def test_fixed_in_from_strict_upper_bound():
    v = matcher.vulnerabilities_for(_payload({"max_version": "5.3.2", "max_operator": "lt"}),
                                    "5.2")[0]
    assert v.fixed_in == "5.3.2"
    assert matcher.fixed_in_label(v) == "5.3.2"


def test_inclusive_upper_bound_is_not_the_fixed_version():
    v = matcher.vulnerabilities_for(_payload({"max_version": "5.3.2", "max_operator": "le"}),
                                    "5.3.2")[0]
    assert v.fixed_in is None
    assert v.last_affected == "5.3.2"
    assert matcher.fixed_in_label(v) == "corrigé après 5.3.2 (version exacte inconnue)"


def test_inclusive_upper_bound_uses_explicit_fixed_field():
    payload = _payload({"max_version": "5.3.2", "max_operator": "le"}, fixed_in="5.3.3")
    v = matcher.vulnerabilities_for(payload, "5.3.2")[0]
    assert v.fixed_in == "5.3.3"
    assert matcher.fixed_in_label(v) == "5.3.3"


def test_unfixed_entry_says_no_fix():
    payload = _payload({"min_version": "1.0", "min_operator": "ge", "unfixed": "1"})
    v = matcher.vulnerabilities_for(payload, "2.0")[0]
    assert v.fixed_in is None
    assert matcher.fixed_in_label(v) == "aucun correctif publié"


def test_compare_versions_is_public_and_correct():
    assert matcher.compare_versions("1.0", "2.0") == -1
    assert matcher.compare_versions("2.0", "2.0") == 0
    assert matcher.compare_versions("3.0", "2.0") == 1


def test_cmp_alias_kept_for_backwards_compat():
    # Ancien nom privé conservé en alias pour ne rien casser en dehors des
    # deux checks déjà migrés vers `compare_versions`.
    assert matcher._cmp is matcher.compare_versions


def test_vulnerabilities_for_hit_and_miss():
    hits = matcher.vulnerabilities_for(CF7_PAYLOAD, "5.2.0")
    assert len(hits) == 1
    v = hits[0]
    assert "CVE-2020-35489" in v.cve_ids
    assert v.cvss_score == 7.2
    assert v.title == "Contact Form 7 < 5.3.2"
    assert matcher.vulnerabilities_for(CF7_PAYLOAD, "5.4.0") == []
