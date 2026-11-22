"""BAC (Broken Access Control), endpoints REST tiers exposant des données sans
auth (permission_callback manquant). Vecteur #1 du référentiel 2025-2026 (57 %).

Règle : un endpoint 200 renvoyant une liste non vide (ou un dict de données SANS
champ `code`) = fuite probable (HIGH, confidence "potential"). Un WP_Error
(`{"code": ...}`) ou un 401/403/404 = endpoint sain, aucun finding.
"""
import re
import responses

from wp_security_forsure.scanner.checks.rest_api import RestApiCheck
from tests.conftest import make_check


def _bac_findings(chk):
    """Findings émis par _check_bac_endpoints (message caractéristique)."""
    return [
        f for f in chk._result.findings
        if "sans authentification" in f["message"]
        and "permission_callback" in f["message"]
    ]


@responses.activate
def test_endpoint_exposes_list_is_high_potential():
    """(a) Un endpoint tiers renvoyant une liste JSON non vide en 200 → HIGH."""
    # La racine /wp-json/ ne renvoie pas de routes exploitables ici : on teste
    # la liste curée. Tout GET renvoie une liste de données sensibles.
    responses.add(
        responses.GET,
        re.compile(r"https://cible\.test/wp-json/.*"),
        json=[{"id": 1, "secret": "leak"}, {"id": 2, "secret": "leak2"}],
        status=200,
    )
    chk = make_check(RestApiCheck)
    chk._check_bac_endpoints()

    findings = _bac_findings(chk)
    assert len(findings) >= 1
    f = findings[0]
    assert f["severity"] == "HIGH"
    assert f["confidence"] == "potential"


@responses.activate
def test_wp_error_401_is_not_flagged():
    """(b) Un endpoint renvoyant {"code": "rest_forbidden"} en 401 → aucun finding."""
    responses.add(
        responses.GET,
        re.compile(r"https://cible\.test/wp-json/.*"),
        json={"code": "rest_forbidden", "message": "Sorry, you are not allowed."},
        status=401,
    )
    chk = make_check(RestApiCheck)
    chk._check_bac_endpoints()

    assert _bac_findings(chk) == []


@responses.activate
def test_404_is_not_flagged():
    """(c) Un endpoint 404 → aucun finding."""
    responses.add(
        responses.GET,
        re.compile(r"https://cible\.test/wp-json/.*"),
        json={"code": "rest_no_route"},
        status=404,
    )
    chk = make_check(RestApiCheck)
    chk._check_bac_endpoints()

    assert _bac_findings(chk) == []


@responses.activate
def test_wp_error_200_dict_with_code_is_not_flagged():
    """Un dict AVEC champ `code` même en 200 = WP_Error → aucun finding."""
    responses.add(
        responses.GET,
        re.compile(r"https://cible\.test/wp-json/.*"),
        json={"code": "rest_forbidden", "data": {"status": 401}},
        status=200,
    )
    chk = make_check(RestApiCheck)
    chk._check_bac_endpoints()

    assert _bac_findings(chk) == []


@responses.activate
def test_empty_list_is_not_flagged():
    """Une liste vide en 200 n'expose aucune donnée → aucun finding."""
    responses.add(
        responses.GET,
        re.compile(r"https://cible\.test/wp-json/.*"),
        json=[],
        status=200,
    )
    chk = make_check(RestApiCheck)
    chk._check_bac_endpoints()

    assert _bac_findings(chk) == []
