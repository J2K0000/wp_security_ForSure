"""Renfort CORS, bypass d'allowlist par origin dérivé du domaine cible.

Le CORS réflectif total (Origin echo) et le wildcard sont déjà couverts par
test_vulnerability_scan / l'audit réel. Ici on cible le gap : une allowlist
présente mais au match trop laxiste (préfixe/suffixe du domaine cible).
"""
import responses

from wp_security_forsure.scanner.checks.rest_api import RestApiCheck
from tests.conftest import make_check

CORS_URL = "https://cible.test/wp-json/wp/v2/posts"


def _bypass_findings(chk):
    return [f for f in chk._result.findings
            if "Bypass d'allowlist CORS" in f["message"]]


@responses.activate
def test_prefix_origin_bypass_is_flagged():
    """Origin https://<cible>.evil.com reflété = allowlist contournable → finding."""
    # Ordre des requêtes de _check_cors : base, evil.com, null, puis préfixe, suffixe.
    responses.add(responses.GET, CORS_URL, status=200)                     # base : pas d'ACAO
    responses.add(responses.GET, CORS_URL, status=200)                     # evil.com : non reflété
    responses.add(responses.GET, CORS_URL, status=200)                     # null : non reflété
    responses.add(responses.GET, CORS_URL, status=200,                     # préfixe : REFLÉTÉ
                  headers={"Access-Control-Allow-Origin": "https://cible.test.evil.com"})
    responses.add(responses.GET, CORS_URL, status=200)                     # suffixe : non reflété

    chk = make_check(RestApiCheck)
    chk._check_cors()
    hits = _bypass_findings(chk)
    assert len(hits) == 1
    assert hits[0]["severity"] == "HIGH"
    assert hits[0]["confidence"] == "potential"


@responses.activate
def test_prefix_bypass_with_credentials_is_critical():
    responses.add(responses.GET, CORS_URL, status=200)
    responses.add(responses.GET, CORS_URL, status=200)
    responses.add(responses.GET, CORS_URL, status=200)
    responses.add(responses.GET, CORS_URL, status=200,
                  headers={"Access-Control-Allow-Origin": "https://cible.test.evil.com",
                           "Access-Control-Allow-Credentials": "true"})
    responses.add(responses.GET, CORS_URL, status=200)

    chk = make_check(RestApiCheck)
    chk._check_cors()
    hits = _bypass_findings(chk)
    assert hits and hits[0]["severity"] == "CRITICAL"


@responses.activate
def test_clean_server_yields_no_bypass():
    """Aucune origine reflétée → aucun finding de bypass (5 requêtes émises)."""
    for _ in range(5):
        responses.add(responses.GET, CORS_URL, status=200)
    chk = make_check(RestApiCheck)
    chk._check_cors()
    assert _bypass_findings(chk) == []


@responses.activate
def test_full_reflection_does_not_double_report_as_bypass():
    """Réflexion totale (evil.com reflété) → le bloc bypass est court-circuité."""
    responses.add(responses.GET, CORS_URL, status=200)                     # base
    responses.add(responses.GET, CORS_URL, status=200,                     # evil.com REFLÉTÉ
                  headers={"Access-Control-Allow-Origin": "https://evil.com"})
    responses.add(responses.GET, CORS_URL, status=200)                     # null
    chk = make_check(RestApiCheck)
    chk._check_cors()
    # La réflexion totale est signalée par ailleurs ; pas de doublon "bypass".
    assert _bypass_findings(chk) == []
    assert any("Reflective CORS" in f["message"] for f in chk._result.findings)
