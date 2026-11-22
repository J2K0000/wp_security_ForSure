"""Check email_auth, SPF / DKIM / DMARC (surface d'usurpation)."""
import pytest
from tests.conftest import make_check
from wp_security_forsure.scanner.checks import email_auth as ea_mod
from wp_security_forsure.scanner.checks.email_auth import EmailAuthCheck


def _run_with_dns(monkeypatch, records_by_name):
    def fake_resolve(name):
        return records_by_name.get(name, [])
    monkeypatch.setattr(ea_mod, "_resolve_txt", fake_resolve)
    chk = make_check(EmailAuthCheck, target="https://exemple.com")
    return chk.run()


def _msgs(result):
    return [f["message"].lower() for f in result.findings]


def test_spf_absent_is_flagged(monkeypatch):
    r = _run_with_dns(monkeypatch, {})
    assert any("spf" in m and "absent" in m for m in _msgs(r))
    spf = [f for f in r.findings if "spf" in f["message"].lower() and "absent" in f["message"].lower()][0]
    assert spf["severity"] == "MEDIUM"
    assert spf["access_class"] == "pii"


def test_spf_plus_all_is_high(monkeypatch):
    r = _run_with_dns(monkeypatch, {"exemple.com": ["v=spf1 +all"]})
    spf = [f for f in r.findings if "spf" in f["message"].lower()]
    assert spf and any(f["severity"] == "HIGH" for f in spf)


def test_spf_hardfail_no_finding(monkeypatch):
    r = _run_with_dns(monkeypatch, {"exemple.com": ["v=spf1 include:_spf.google.com -all"]})
    assert not any("spf" in m and ("absent" in m or "+all" in m) for m in _msgs(r))


def test_dmarc_absent_is_flagged(monkeypatch):
    r = _run_with_dns(monkeypatch, {"exemple.com": ["v=spf1 -all"]})
    assert any("dmarc" in m and "absent" in m for m in _msgs(r))


def test_dmarc_policy_none_is_flagged(monkeypatch):
    r = _run_with_dns(monkeypatch, {
        "exemple.com": ["v=spf1 -all"],
        "_dmarc.exemple.com": ["v=DMARC1; p=none; rua=mailto:x@exemple.com"]})
    dmarc = [f for f in r.findings if "dmarc" in f["message"].lower()]
    assert dmarc and any("p=none" in f["message"].lower() or "aucune application" in f["message"].lower()
                         for f in dmarc)


def test_dmarc_reject_no_finding(monkeypatch):
    r = _run_with_dns(monkeypatch, {
        "exemple.com": ["v=spf1 -all"],
        "_dmarc.exemple.com": ["v=DMARC1; p=reject"]})
    assert not any("dmarc" in m and ("absent" in m or "p=none" in m) for m in _msgs(r))


def test_dns_indetermine_no_false_absent(monkeypatch):
    def fake_resolve(name):
        return None
    monkeypatch.setattr(ea_mod, "_resolve_txt", fake_resolve)
    r = make_check(EmailAuthCheck, target="https://exemple.com").run()
    assert not any("absent" in m for m in _msgs(r))


def test_dkim_not_detected_fields(monkeypatch):
    # SPF/DMARC OK pour isoler le constat DKIM ; aucun sélecteur DKIM ne résout.
    r = _run_with_dns(monkeypatch, {
        "exemple.com": ["v=spf1 -all"],
        "_dmarc.exemple.com": ["v=DMARC1; p=reject"]})
    dkim = [f for f in r.findings if "dkim" in f["message"].lower()]
    assert dkim, "aucun constat DKIM"
    f = dkim[0]
    assert f["severity"] == "INFO"
    assert f["confidence"] == "potential"
    assert f["access_class"] == "recon"


def test_dmarc_indetermine_emits_info(monkeypatch):
    # SPF résout (present), mais _dmarc.* est indéterminé (None).
    def fake_resolve(name):
        if name == "exemple.com":
            return ["v=spf1 -all"]
        if name == "_dmarc.exemple.com":
            return None
        return []  # DKIM selectors: absents
    monkeypatch.setattr(ea_mod, "_resolve_txt", fake_resolve)
    r = make_check(EmailAuthCheck, target="https://exemple.com").run()
    msgs = [f["message"].lower() for f in r.findings]
    assert any("dmarc" in m and ("indisponible" in m or "ignoré" in m or "ignore" in m) for m in msgs)
    assert not any("dmarc" in m and "absent" in m for m in msgs)


def test_registered_in_registry():
    from wp_security_forsure.scanner.engine import CHECK_REGISTRY
    assert "email_auth" in CHECK_REGISTRY


def test_has_class_default():
    from wp_security_forsure.scanner.reporters.impact import _CLASS_BY_CHECK, _CLASS_ORDER
    assert _CLASS_BY_CHECK.get("email_auth") in _CLASS_ORDER
