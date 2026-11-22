"""Régression, discipline de confiance des fallbacks file_exposure.

Un chemin sensible accessible SANS indicateur de contenu réel matché n'est
qu'une heuristique : ça doit rester confidence=="potential" (le score client
et le code de sortie CLI ne comptent que confidence=="confirmed", un faux
CRITICAL confirmé, c'est crier au loup). Et un 403 (accès refusé, serveur
correctement durci) n'est PAS une exposition : ça ne doit produire aucun
finding CRITICAL/HIGH/MEDIUM.
"""
import re
import responses
from wp_security_forsure.scanner.checks.file_exposure import FileExposureCheck
from tests.conftest import make_check


def _mock_probe_404():
    responses.add(responses.HEAD, re.compile(r".*/wpsf-probe.*"), status=404)
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body="404 Not Found", status=404)


def _findings(chk):
    return [f for f in chk._result.findings if f["severity"] != "INFO"]


@responses.activate
def test_accessible_file_without_indicator_is_potential_not_confirmed():
    """200 + >100 octets mais AUCUN indicateur de contenu réel matché :
    ne doit pas gonfler un CRITICAL confirmé."""
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/wp-config.php.bak", status=200)
    responses.add(responses.GET, "https://cible.test/wp-config.php.bak",
                  body="<html>Unrelated placeholder content, nothing sensitive here</html>"
                       + ("x" * 100),
                  status=200)
    chk = make_check(FileExposureCheck)
    chk._check_single_path("wp-config.php.bak", "wp-config backup",
                            "CRITICAL", ["DB_NAME", "DB_PASSWORD", "define("],
                            is_directory=False)
    findings = _findings(chk)
    assert len(findings) == 1
    assert findings[0]["confidence"] == "potential"
    # Le point de discipline : jamais de CRITICAL confirmé sans preuve.
    assert not (findings[0]["severity"] == "CRITICAL"
                and findings[0]["confidence"] == "confirmed")


@responses.activate
def test_protected_directory_403_yields_no_exposure_finding():
    """Un répertoire sensible protégé (403) ne doit jamais produire de
    finding MEDIUM/HIGH/CRITICAL, 403 == accès refusé, pas exposition."""
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/wp-content/uploads/", status=403)
    responses.add(responses.GET, "https://cible.test/wp-content/uploads/",
                  body="<html><body>Forbidden</body></html>" + ("x" * 100),
                  status=403)
    chk = make_check(FileExposureCheck)
    chk._check_single_path("wp-content/uploads/", "wp-content/uploads/",
                            "HIGH",
                            ["Index of", "index of", "Directory listing",
                             "<title>Index of", "Parent Directory"],
                            is_directory=True)
    exposures = [f for f in chk._result.findings
                 if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    assert exposures == []


@responses.activate
def test_real_indicator_match_stays_confirmed():
    """Un vrai indicateur de contenu matché reste confidence=='confirmed'
    (on ne casse pas les vrais positifs)."""
    _mock_probe_404()
    body = ("<?php\ndefine('DB_NAME','wp');\ndefine('DB_PASSWORD','s3cr3t');\n"
            + ("X" * 200))
    responses.add(responses.HEAD, "https://cible.test/wp-config.php.bak", status=200)
    responses.add(responses.GET, "https://cible.test/wp-config.php.bak",
                  body=body, status=200)
    chk = make_check(FileExposureCheck)
    chk._check_single_path("wp-config.php.bak", "wp-config backup",
                            "CRITICAL", ["DB_NAME", "DB_PASSWORD", "define("],
                            is_directory=False)
    findings = _findings(chk)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["confidence"] == "confirmed"


# ── Fix B, install.php : "WordPress" seul n'est pas une preuve ───────────
# Le mot générique "WordPress" apparaît sur presque toutes les pages WP
# (footer, meta generator, readme...). Un CRITICAL confirmé sur
# wp-admin/install.php doit exiger un vrai signal de formulaire
# d'installation, pas seulement ce mot.

@responses.activate
def test_install_php_bare_wordpress_word_is_not_confirmed_critical():
    """Une page qui ne contient QUE le mot générique 'WordPress' (aucun
    signal de formulaire d'installation réel) ne doit jamais produire un
    CRITICAL confirmé."""
    _mock_probe_404()
    body = ("<html><head><title>Just a WordPress site</title></head>"
            "<body>Powered by WordPress. Nothing else here.</body></html>"
            + ("x" * 100))
    responses.add(responses.HEAD, "https://cible.test/wp-admin/install.php", status=200)
    responses.add(responses.GET, "https://cible.test/wp-admin/install.php",
                  body=body, status=200)
    chk = make_check(FileExposureCheck)
    chk._check_single_path(
        "wp-admin/install.php", "wp-admin/install.php", "CRITICAL",
        ["installation", "site title", "admin email", "submit", "Welcome", "WordPress"],
        is_directory=False,
    )
    findings = _findings(chk)
    assert not any(f["severity"] == "CRITICAL" and f["confidence"] == "confirmed"
                   for f in findings)


@responses.activate
def test_install_php_real_form_markers_is_confirmed_critical():
    """Une vraie page d'installation WP ouverte (formulaire five-minute
    install) reste un CRITICAL confirmé, pas de régression du vrai
    positif."""
    _mock_probe_404()
    body = (
        "<html><head><title>WordPress &rsaquo; Installation</title></head>"
        "<body><h1>Welcome</h1><form method='post'>"
        "<input name='weblog_title'><input name='admin_email'>"
        "<input type='submit' value='Install WordPress'></form></body></html>"
        + ("x" * 100)
    )
    responses.add(responses.HEAD, "https://cible.test/wp-admin/install.php", status=200)
    responses.add(responses.GET, "https://cible.test/wp-admin/install.php",
                  body=body, status=200)
    chk = make_check(FileExposureCheck)
    chk._check_single_path(
        "wp-admin/install.php", "wp-admin/install.php", "CRITICAL",
        ["installation", "site title", "admin email", "submit", "Welcome", "WordPress"],
        is_directory=False,
    )
    findings = _findings(chk)
    assert any(f["severity"] == "CRITICAL" and f["confidence"] == "confirmed"
               for f in findings)
