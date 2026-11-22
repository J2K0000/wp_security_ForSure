"""Détection des bibliothèques JS front vulnérables (façon retire.js).

Matrice couverte :
  (a) jquery 1.12.4 servi same-origin        → finding HIGH « vulnérable »
  (b) jquery 3.7.1 (récente)                  → PAS de finding vulnérable
  (c) lodash 4.17.10                          → HIGH (prototype pollution)
  (d) version non parsable / lib inconnue     → aucun finding
"""
import responses

from wp_security_forsure.scanner.checks.third_party_scripts import ThirdPartyScriptsCheck
from tests.conftest import make_check

HOME = "https://cible.test/"


def _home(html: str):
    responses.add(responses.GET, HOME, body=html, status=200)


def _vuln_findings(chk):
    return [f for f in chk._result.findings
            if "vulnérable" in f["message"].lower()]


@responses.activate
def test_jquery_old_is_high():
    """jQuery 1.12.4 servi depuis /wp-includes → HIGH, XSS < 3.5.0."""
    _home(
        "<html><head>"
        "<script src='/wp-includes/js/jquery/jquery.min.js?ver=1.12.4'></script>"
        "</head><body>x</body></html>"
    )
    chk = make_check(ThirdPartyScriptsCheck)
    chk._check_vulnerable_js_libraries()

    vuln = _vuln_findings(chk)
    assert len(vuln) == 1, chk._result.findings
    f = vuln[0]
    assert f["severity"] == "HIGH"
    assert f["confidence"] == "potential"
    assert "jquery 1.12.4" in f["message"]
    assert "3.5.0" in f["message"]
    assert "CVE-2020-11022" in f["message"]


@responses.activate
def test_jquery_recent_not_flagged():
    """jQuery 3.7.1 (à jour) → aucune lib signalée vulnérable."""
    _home(
        "<html><head>"
        "<script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>"
        "</head><body>x</body></html>"
    )
    chk = make_check(ThirdPartyScriptsCheck)
    chk._check_vulnerable_js_libraries()

    assert _vuln_findings(chk) == []
    # La lib reste inventoriée en INFO (détectée mais non vulnérable).
    assert any(f["severity"] == "INFO" and "jquery 3.7.1" in f["evidence"]
               for f in chk._result.findings)


@responses.activate
def test_lodash_old_is_high():
    """lodash 4.17.10 (< 4.17.21) → HIGH, prototype pollution."""
    _home(
        "<html><head>"
        "<script src='/wp-content/themes/x/js/lodash.min.js?ver=4.17.10'></script>"
        "</head><body>x</body></html>"
    )
    chk = make_check(ThirdPartyScriptsCheck)
    chk._check_vulnerable_js_libraries()

    vuln = _vuln_findings(chk)
    assert len(vuln) == 1, chk._result.findings
    assert vuln[0]["severity"] == "HIGH"
    assert "lodash 4.17.10" in vuln[0]["message"]
    assert "CVE-2021-23337" in vuln[0]["message"]


@responses.activate
def test_lodash_cdn_path_form():
    """Forme CDN /ajax/libs/lodash.js/4.17.10/ correctement extraite → HIGH."""
    _home(
        "<html><head>"
        "<script src='https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.10/lodash.min.js'></script>"
        "</head><body>x</body></html>"
    )
    chk = make_check(ThirdPartyScriptsCheck)
    chk._check_vulnerable_js_libraries()

    vuln = _vuln_findings(chk)
    assert len(vuln) == 1
    assert "lodash 4.17.10" in vuln[0]["message"]


@responses.activate
def test_unparsable_and_unknown_yield_nothing():
    """Version non parsable + lib inconnue → aucun finding (pas de faux positif)."""
    _home(
        "<html><head>"
        "<script src='/js/jquery.min.js?ver=latest'></script>"       # version non numérique
        "<script src='/js/superlib-2.0.min.js'></script>"            # lib inconnue
        "</head><body>x</body></html>"
    )
    chk = make_check(ThirdPartyScriptsCheck)
    chk._check_vulnerable_js_libraries()

    assert _vuln_findings(chk) == []
    # Rien n'a été reconnu → pas même l'inventaire INFO.
    assert chk._result.findings == []


@responses.activate
def test_jquery_migrate_not_confused_with_jquery():
    """jquery-migrate est reconnu comme sa propre lib, pas comme jquery."""
    _home(
        "<html><head>"
        "<script src='/wp-includes/js/jquery/jquery-migrate.min.js?ver=1.2.0'></script>"
        "</head><body>x</body></html>"
    )
    chk = make_check(ThirdPartyScriptsCheck)
    chk._check_vulnerable_js_libraries()

    vuln = _vuln_findings(chk)
    assert len(vuln) == 1
    assert "jquery-migrate 1.2.0" in vuln[0]["message"]
