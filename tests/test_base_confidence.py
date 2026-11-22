import pytest

from wp_security_forsure.scanner.checks.base import CheckResult, SEVERITIES, SEVERITY_ORDER


def _result():
    return CheckResult(check_name="x", title="X", description="d",
                       severity="INFO", passed=True)


def test_default_confidence_is_confirmed():
    r = _result()
    r.add_finding("msg", severity="HIGH")
    assert r.findings[0]["confidence"] == "confirmed"


def test_explicit_potential_is_stored():
    r = _result()
    r.add_finding("msg", severity="MEDIUM", confidence="potential")
    assert r.findings[0]["confidence"] == "potential"


def test_non_info_finding_fails_check():
    r = _result()
    r.add_finding("msg", severity="HIGH")
    assert r.passed is False


def test_info_finding_keeps_passed():
    r = _result()
    r.add_finding("msg", severity="INFO")
    assert r.passed is True


def test_invalid_severity_raises_value_error():
    r = _result()
    with pytest.raises(ValueError):
        r.add_finding("msg", severity="CRTICAL")


@pytest.mark.parametrize("sev", SEVERITIES)
def test_all_valid_severities_are_accepted(sev):
    r = _result()
    r.add_finding("msg", severity=sev)
    assert r.findings[-1]["severity"] == sev


def test_severity_order_matches_severities_ranking():
    assert SEVERITY_ORDER == {sev: i for i, sev in enumerate(SEVERITIES)}
    assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["HIGH"] < \
        SEVERITY_ORDER["MEDIUM"] < SEVERITY_ORDER["LOW"] < SEVERITY_ORDER["INFO"]


def test_max_severity_uses_shared_order():
    r = _result()
    r.add_finding("a", severity="LOW")
    r.add_finding("b", severity="CRITICAL")
    r.add_finding("c", severity="MEDIUM")
    assert r.max_severity == "CRITICAL"
