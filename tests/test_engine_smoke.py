"""Garde-fou moteur : chaque check du VRAI registre (`CHECK_REGISTRY`)
s'instancie et s'exécute sans lever, sur une cible minimalement mockée.

C'est le filet de sécurité qui aurait signalé l'angle mort cookies_sessions
/ waf_cdn (zéro test) avant l'audit : n'importe quel check nouvellement
ajouté au registre est automatiquement couvert par ce test, sans action
supplémentaire.

Portée : on vérifie l'absence d'exception et la forme du CheckResult, pas
le contenu métier de chaque check (déjà couvert par ses tests dédiés).

Tout le trafic HTTP est intercepté par un catch-all `responses` (GET/HEAD/
POST, n'importe quelle URL) : cela couvre aussi bien les requêtes vers la
cible que les appels vers des hôtes tiers fixes en dur dans certains checks
(ex. api.wordpress.org dans null_plugins, crt.sh dans takeover en mode
étendu). email_auth résout du DNS réel (dns.resolver) hors du seam HTTP :
sa fonction module-level `_resolve_txt` est monkeypatchée pour rester
100% offline.

ssl_tls et server_security sont exclus : ils shellent vers des binaires
externes (openssl s_client / curl) pour sonder le TLS/HTTP2 réel de l'hôte,
ce qui n'est ni interceptable par `responses` (pas du trafic `requests`) ni
déterministe/rapide sur un host fictif (`cible.test` ne résout pas, délai
DNS/connect variable selon l'environnement). Ils ont leurs propres suites de
tests dédiées.
"""
import re

import pytest
import responses

from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.engine import CHECK_REGISTRY
from tests.conftest import make_check

TARGET = "https://cible.test"

_SKIP = {
    "ssl_tls": "shell out vers openssl s_client (hors trafic requests, non déterministe)",
    "server_security": "shell out vers openssl/curl (hors trafic requests, non déterministe)",
}

_BENIGN_HTML = "<html><head><title>OK</title></head><body>Bienvenue</body></html>"


def _register_catchall_mocks():
    responses.add(responses.GET, re.compile(r".*"), body=_BENIGN_HTML, status=200)
    responses.add(responses.HEAD, re.compile(r".*"), status=200)
    responses.add(responses.POST, re.compile(r".*"), body="{}", status=200)


def _benign_context():
    # inventaire vide mais présent : satisfait les checks qui consultent
    # context["inventory"] (vulnerability_scan, high_risk_plugins, ...) sans
    # déclencher de composant à matcher (donc pas d'appel réseau vulndb).
    return {"inventory": {"core": {}, "plugins": [], "themes": []}}


@pytest.mark.parametrize("name", sorted(set(CHECK_REGISTRY) - set(_SKIP)))
@responses.activate
def test_check_runs_without_raising(name, monkeypatch):
    _register_catchall_mocks()

    if name == "email_auth":
        from wp_security_forsure.scanner.checks import email_auth as ea_mod
        monkeypatch.setattr(ea_mod, "_resolve_txt", lambda domain: [])

    check_cls = CHECK_REGISTRY[name]
    chk = make_check(check_cls, target=TARGET)
    chk.context = _benign_context()

    result = chk.run()

    assert isinstance(result, CheckResult)
    assert result.check_name == name
    assert isinstance(result.findings, list)


_DEFAULT_MODE = sorted(n for n in set(CHECK_REGISTRY) - set(_SKIP)
                       if CHECK_REGISTRY[n].access_tier < 2)


@pytest.mark.parametrize("name", _DEFAULT_MODE)
@responses.activate
def test_check_runs_without_level_2_request_in_default_mode(name, monkeypatch):
    """Mode par défaut (sans --authorized) : un check de niveau 0 ou 1, même
    poussé dans toutes ses branches par un catch-all 200, n'émet aucune
    requête de niveau 2 ni interdite (sinon AccessTierRequired / ForbiddenProbe,
    hors hiérarchie Exception, remonterait ici)."""
    _register_catchall_mocks()
    if name == "email_auth":
        from wp_security_forsure.scanner.checks import email_auth as ea_mod
        monkeypatch.setattr(ea_mod, "_resolve_txt", lambda domain: [])
    chk = make_check(CHECK_REGISTRY[name], target=TARGET,
                     config={"authorized": False})
    chk.context = _benign_context()
    assert isinstance(chk.run(), CheckResult)


def test_registry_discovery_is_not_broken():
    """Garde-fou du garde-fou : la découverte auto du registre doit rester
    substantielle (une régression de `_discover_checks` ne doit pas passer
    inaperçue en vidant silencieusement la boucle de test ci-dessus)."""
    assert len(CHECK_REGISTRY) >= 20
    assert "cookies_sessions" in CHECK_REGISTRY
    assert "waf_cdn" in CHECK_REGISTRY
    assert "high_risk_plugins" in CHECK_REGISTRY


def test_skip_list_entries_still_exist_in_registry():
    """Si un check exclu disparaissait du registre, on doit s'en apercevoir
    plutôt que de laisser l'exclusion masquer silencieusement son absence."""
    for name in _SKIP:
        assert name in CHECK_REGISTRY, name
