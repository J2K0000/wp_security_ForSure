"""Le finding peut porter access_class et impact (chantier A)."""
from wp_security_forsure.scanner.checks.base import CheckResult


def _result():
    return CheckResult(check_name="demo", title="Demo",
                       description="", severity="INFO", passed=True)


def test_add_finding_without_class_has_no_access_class_key():
    r = _result()
    r.add_finding("rien de spécial", severity="LOW")
    assert "access_class" not in r.findings[0]
    assert "impact" not in r.findings[0]


def test_add_finding_stores_explicit_access_class():
    r = _result()
    r.add_finding("wp-config exposé", severity="CRITICAL",
                  access_class="secrets")
    assert r.findings[0]["access_class"] == "secrets"


def test_add_finding_stores_impact_narrative():
    r = _result()
    imp = {"data": "d", "path": "p", "enables": "e"}
    r.add_finding("RCE pré-auth", severity="CRITICAL",
                  access_class="controle", impact=imp)
    assert r.findings[0]["impact"] == imp


def test_add_finding_uses_result_default_access_class():
    r = CheckResult(check_name="demo", title="Demo", description="",
                    severity="INFO", passed=True,
                    default_access_class="recon")
    r.add_finding("empreinte de version", severity="LOW")
    assert r.findings[0]["access_class"] == "recon"


def test_explicit_access_class_overrides_default():
    r = CheckResult(check_name="demo", title="Demo", description="",
                    severity="INFO", passed=True,
                    default_access_class="recon")
    r.add_finding("dump SQL téléchargeable", severity="HIGH",
                  access_class="secrets")
    assert r.findings[0]["access_class"] == "secrets"
