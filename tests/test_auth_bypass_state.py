"""auth_bypass_state, détection comportementale des auth-bypass conditionnés.

Matrice couverte :
  A) Really Simple Security (CVE-2024-10924)
     - 9.1.0 + namespace 2FA REST exposé      → CRITICAL (2FA active = exploitable)
     - 9.1.0 sans namespace 2FA               → MEDIUM (exploitabilité réduite)
     - 9.2.0 (patché, hors plage)             → aucun finding vuln
  B) LiteSpeed Cache (CVE-2024-28000)
     - 6.3.0.1 (<= borne)                     → HIGH (weak-hash role-simulation)
     - 6.4.0 (patché)                         → aucun finding
"""
import re

import responses

from wp_security_forsure.scanner.checks.auth_bypass_state import AuthBypassStateCheck
from tests.conftest import make_check

WP_JSON_URL = re.compile(r"https://cible\.test/wp-json/.*")
# Index REST exposant le namespace 2FA de Really Simple Security.
_REST_INDEX_2FA = {
    "namespaces": ["oembed/1.0", "wp/v2", "reallysimplessl/v1"],
    "routes": {"/reallysimplessl/v1/two_fa/skip_onboarding": {}},
}
# Index REST « propre » : aucun namespace reallysimplessl (2FA désactivé).
_REST_INDEX_NO_2FA = {
    "namespaces": ["oembed/1.0", "wp/v2", "akismet/v1"],
    "routes": {"/wp/v2/posts": {}},
}


def _check_with_plugin(slug, version):
    chk = make_check(AuthBypassStateCheck)
    chk.context = {"inventory": {
        "core": {},
        "plugins": [{"slug": slug, "version": version, "source": "readme"}],
        "themes": [],
    }}
    return chk


# ── A) Really Simple Security ───────────────────────────────────────────
@responses.activate
def test_rss_vulnerable_with_2fa_surface_is_critical():
    responses.add(responses.GET, WP_JSON_URL, json=_REST_INDEX_2FA, status=200)
    chk = _check_with_plugin("really-simple-ssl", "9.1.0")
    chk.run()
    crit = [f for f in chk._result.findings if f["severity"] == "CRITICAL"]
    assert len(crit) == 1
    assert "CVE-2024-10924" in crit[0]["message"]
    assert "exploitable" in crit[0]["message"]
    assert chk._result.passed is False


@responses.activate
def test_rss_vulnerable_without_2fa_surface_is_medium():
    responses.add(responses.GET, WP_JSON_URL, json=_REST_INDEX_NO_2FA, status=200)
    chk = _check_with_plugin("really-simple-ssl", "9.1.0")
    chk.run()
    sev = {f["severity"] for f in chk._result.findings}
    assert sev == {"MEDIUM"}
    med = chk._result.findings[0]
    assert "exploitabilité réduite" in med["message"]
    assert med["confidence"] == "potential"


@responses.activate
def test_rss_patched_version_yields_no_finding():
    # 9.2.0 hors plage 9.0.0–9.1.1.1 : le check ne sonde même pas la surface.
    responses.add(responses.GET, WP_JSON_URL, json=_REST_INDEX_2FA, status=200)
    chk = _check_with_plugin("really-simple-ssl", "9.2.0")
    chk.run()
    assert chk._result.findings == []
    assert chk._result.passed is True


@responses.activate
def test_rss_unknown_version_does_not_conclude():
    """Version inconnue → pas de conclusion de plage (anti-faux-positif)."""
    chk = _check_with_plugin("really-simple-ssl", None)
    chk.run()
    assert chk._result.findings == []


# ── B) LiteSpeed Cache ──────────────────────────────────────────────────
@responses.activate
def test_litespeed_vulnerable_version_is_high():
    chk = _check_with_plugin("litespeed-cache", "6.3.0.1")
    chk.run()
    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    assert "CVE-2024-28000" in high[0]["message"]
    assert "litespeed_hash" in high[0]["message"]
    assert high[0]["confidence"] == "potential"
    assert chk._result.passed is False


@responses.activate
def test_litespeed_patched_version_yields_no_finding():
    chk = _check_with_plugin("litespeed-cache", "6.4.0")
    chk.run()
    assert chk._result.findings == []
    assert chk._result.passed is True


@responses.activate
def test_litespeed_boundary_below_is_reported():
    """Une version nettement antérieure reste dans la classe affectée."""
    chk = _check_with_plugin("litespeed-cache", "6.2.0")
    chk.run()
    assert any(f["severity"] == "HIGH" for f in chk._result.findings)


# ── Robustesse ──────────────────────────────────────────────────────────
@responses.activate
def test_rss_non_json_index_degrades_to_medium():
    """Index REST illisible (non-JSON) → surface non prouvée → MEDIUM, pas de crash."""
    responses.add(responses.GET, WP_JSON_URL, body="<html>not json</html>", status=200)
    chk = _check_with_plugin("really-simple-ssl", "9.0.0")
    chk.run()
    assert any(f["severity"] == "MEDIUM" for f in chk._result.findings)


def test_no_target_plugin_is_silent():
    """Aucun des deux plugins présent → aucun finding, aucune requête réseau."""
    chk = make_check(AuthBypassStateCheck)
    chk.context = {"inventory": {"core": {}, "plugins": [
        {"slug": "akismet", "version": "5.0", "source": "readme"}], "themes": []}}
    chk.run()
    assert chk._result.findings == []
