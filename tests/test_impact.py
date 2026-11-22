"""Couche impact, classification par accès attaquant + surface d'exposition."""
from wp_security_forsure.scanner.reporters.impact import (
    classify, narrative, exposure_surface, harvest_example, redact,
)
from wp_security_forsure.scanner.checks.base import CheckResult


def _result(check_name, findings):
    r = CheckResult(check_name=check_name, title=check_name, description="",
                    severity="INFO", passed=True)
    r.findings = findings
    return r


def test_classify_by_check_default():
    assert classify("rest_batch", "peu importe") == "controle"
    assert classify("database_exposure", "x") == "secrets"
    assert classify("fingerprint", "x") == "recon"


def test_message_refine_overrides_check_default():
    # file_exposure a pour défaut 'prive', mais un wp-config → 'secrets'.
    assert classify("file_exposure", "wp-config.php.bak exposé") == "secrets"
    # énumération d'utilisateurs → 'pii' quel que soit le check.
    assert classify("wp_features", "user enumeration via REST") == "pii"
    # readme → 'recon'.
    assert classify("file_exposure", "readme.html exposed") == "recon"


def test_narrative_three_parts_and_class():
    n = narrative("rest_api", "user enumeration /wp/v2/users")
    assert n["classe"] == "pii"
    assert n["data"] and n["path"] and n["enables"]
    assert n["emoji"] and n["label"]


def test_exposure_surface_confirmed_only_and_ordered():
    results = [
        _result("rest_api", [
            {"message": "user enumeration", "severity": "CRITICAL",
             "confidence": "confirmed"}]),
        _result("rest_batch", [
            {"message": "wp2shell EXPLOITABLE", "severity": "CRITICAL",
             "confidence": "confirmed"}]),
        _result("cache_security", [   # potential → exclu
            {"message": "web cache deception possible", "severity": "HIGH",
             "confidence": "potential"}]),
        _result("fingerprint", [      # INFO → exclu
            {"message": "empreinte", "severity": "INFO",
             "confidence": "confirmed"}]),
    ]
    surface = exposure_surface(results)
    # Ordre de gravité : contrôle avant données personnelles.
    assert [b["key"] for b in surface] == ["controle", "pii"]
    flat = [f["message"] for b in surface for _, f in b["findings"]]
    assert "web cache deception possible" not in flat  # potential exclu
    assert "empreinte" not in flat                     # INFO exclu


def test_exposure_surface_empty_without_confirmed():
    results = [_result("cache_security", [
        {"message": "x", "severity": "HIGH", "confidence": "potential"}])]
    assert exposure_surface(results) == []


def test_redact_masks_emails_and_secrets():
    r = redact("user j.dupont@exemple.test and DB_PASSWORD=Sup3rSecret!")
    assert "j•••@exemple.test" in r          # local part caviardé, domaine gardé
    assert "dupont" not in r
    assert "Sup3rSecret" not in r         # secret masqué


def test_harvest_example_extracts_real_data_and_redacts():
    ev = ("Users: admin_demo, marie, j.dupont@exemple.test\n"
          "Impact: user enumeration facilitates brute force\n"
          "Recommendation: disable REST users endpoint")
    ex = harvest_example(ev)
    assert ex is not None
    assert "admin_demo" in ex             # donnée réelle conservée
    assert "j•••@exemple.test" in ex          # email caviardé
    # les lignes de cadrage (Impact:/Recommendation:) sont écartées
    assert "Recommendation" not in ex


def test_harvest_example_none_on_empty():
    assert harvest_example("") is None
    assert harvest_example(None) is None
