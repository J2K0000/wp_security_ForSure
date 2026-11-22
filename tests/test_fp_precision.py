"""Passe précision : faux positifs / sur-signalements corrigés (audit réel).

Constats issus d'un scan réel qui dégradaient la précision :
  A) « risky namespace » émis par sous-namespace (Elementor ×6) et en MEDIUM ;
  B) Block Directory « SSRF vector » MEDIUM alors que l'endpoint est en 401 ;
  C) JSONP au préfixe /**/ (assaini, natif) signalé en LOW.
"""
import re

import responses

from wp_security_forsure.scanner.checks.rest_api import RestApiCheck
from wp_security_forsure.scanner.checks.wp_features import WPFeaturesCheck
from tests.conftest import make_check


# ── A) « risky namespace » : dédup par plugin + INFO ────────────────────────
def test_risky_namespace_dedup_and_downgraded_to_info():
    chk = make_check(RestApiCheck)
    chk._wp_json_data = {
        "namespaces": ["elementor/v1", "elementor-pro/v1", "elementor/v1/documents",
                       "contact-form-7/v1"],
        "routes": {},
    }
    chk._check_custom_plugin_endpoints()
    fnd = chk._result.findings
    # La simple présence d'une surface REST n'est pas une vuln → jamais MEDIUM/HIGH.
    assert not any(f["severity"] in ("MEDIUM", "HIGH") for f in fnd)
    # Elementor dédupliqué : 1 seul finding malgré 3 sous-namespaces.
    elem = [f for f in fnd if "elementor" in f["message"].lower()]
    assert len(elem) == 1
    assert elem[0]["severity"] == "INFO"
    assert "3 namespace" in elem[0]["message"]


# ── B) Block Directory en 401 (auth requise) : INFO, pas MEDIUM « SSRF » ─────
@responses.activate
def test_block_directory_auth_gated_is_info_not_ssrf():
    responses.add(
        responses.GET,
        re.compile(r"https://cible\.test/wp-json/wp/v2/block-directory/search.*"),
        json={"code": "rest_forbidden"}, status=401,
    )
    chk = make_check(WPFeaturesCheck)
    chk._check_block_directory()
    bd = [f for f in chk._result.findings if "Block Directory" in f["message"]]
    assert len(bd) == 1
    assert bd[0]["severity"] == "INFO"           # pas MEDIUM
    assert "pas un SSRF" in bd[0]["message"]      # ne prétend plus au SSRF


# ── C) JSONP au préfixe /**/ (assaini) : INFO, pas LOW ──────────────────────
@responses.activate
def test_jsonp_sanitized_prefix_is_info_not_low():
    responses.add(
        responses.GET,
        re.compile(r"https://cible\.test/wp-json/wp/v2/posts.*"),
        body="/**/testCallback([])", status=200,
    )
    chk = make_check(RestApiCheck)
    chk._check_jsonp_callback()
    jsonp = [f for f in chk._result.findings if "/**/" in f["message"]]
    assert jsonp
    # Le préfixe /**/ EST la protection : aucun de ces constats ne doit être LOW.
    assert all(f["severity"] == "INFO" for f in jsonp)
    assert not any(f["severity"] == "LOW" for f in chk._result.findings)
