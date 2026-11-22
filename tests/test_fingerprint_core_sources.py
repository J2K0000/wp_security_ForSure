"""Détection de la version du cœur par sources résistantes au durcissement.

Un site qui a retiré la balise generator et readme.html (bonne pratique, et
que file_exposure recommande) sortait « core=? » et échappait au matching CVE
du cœur, angle mort majeur, ex. wp2shell sur un site par ailleurs bien tenu.
On récupère la version via le ?ver= de wp-includes puis via le flux RSS.
"""
import responses

from wp_security_forsure.scanner.checks.fingerprint import FingerprintCheck
from tests.conftest import make_check

# Accueil sans generator ni readme.html, mais avec un asset wp-includes versionné.
HOME_WPINC = """<html><head>
<link rel="stylesheet" href="https://cible.test/wp-includes/css/dist/block-library/style.min.css?ver=6.9.4" />
</head><body>ok</body></html>"""

HOME_BARE = "<html><head></head><body>rien d'exploitable</body></html>"

FEED = """<?xml version="1.0"?><rss><channel>
<generator>https://wordpress.org/?v=7.0.1</generator>
</channel></rss>"""


@responses.activate
def test_core_from_wpinclude_ver_param():
    responses.add(responses.GET, "https://cible.test/", body=HOME_WPINC,
                  status=200, content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core["version"] == "6.9.4"
    assert core["source"] == "wpinc_ver"


@responses.activate
def test_core_from_rss_feed_generator():
    # Accueil nu → pas de generator, pas de wp-includes versionné.
    responses.add(responses.GET, "https://cible.test/", body=HOME_BARE,
                  status=200, content_type="text/html")
    # La sonde soft-404 (chemin bidon) doit renvoyer autre chose que le feed.
    responses.add(responses.GET,
                  "https://cible.test/wpsf-probe-4f9a2c7e-does-not-exist",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/feed/", body=FEED,
                  status=200, content_type="application/rss+xml")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core["version"] == "7.0.1"
    assert core["source"] == "feed_generator"


@responses.activate
def test_generator_still_wins_when_present():
    """La balise generator reste la source prioritaire quand elle existe."""
    home = ('<html><head><meta name="generator" content="WordPress 6.9.4" />'
            '<link href="https://cible.test/wp-includes/x.css?ver=7.0.1" />'
            '</head><body>ok</body></html>')
    responses.add(responses.GET, "https://cible.test/", body=home, status=200,
                  content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core["version"] == "6.9.4"
    assert core["source"] == "generator"


# ---------------------------------------------------------------------------
# Source supplémentaire : page de connexion (wp-login.php).
#
# Un site à la home statique/cachée peut retirer tout signal de version côté
# accueil sans même le faire exprès (cache agressif). La page de login,
# elle, charge toujours les assets versionnés du core (wp-includes,
# wp-admin), difficile à faire disparaître sans casser l'admin.
# ---------------------------------------------------------------------------

LOGIN_WPINC = """<html><head>
<link rel="stylesheet" href="https://cible.test/wp-includes/css/login.min.css?ver=6.4.2" />
</head><body>login</body></html>"""


@responses.activate
def test_core_from_login_page_wpinc_ver_when_home_has_no_signal():
    """Home sans signal de version, mais wp-login.php expose un ?ver= : le
    core doit être détecté via cette source de secours, étiquetée
    login_wpinc_ver."""
    responses.add(responses.GET, "https://cible.test/", body=HOME_BARE,
                  status=200, content_type="text/html")
    responses.add(responses.GET,
                  "https://cible.test/wpsf-probe-4f9a2c7e-does-not-exist",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/feed/",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/wp-login.php",
                  body=LOGIN_WPINC, status=200, content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core is not None
    assert core["version"] == "6.4.2"
    assert core["source"] == "login_wpinc_ver"


@responses.activate
def test_login_page_soft404_falls_through_without_crash():
    """wp-login.php en soft-404 (renvoie la home) ne doit ni crasher, ni
    produire de faux positif, le core reste indétecté si aucune autre
    source ne donne de version."""
    responses.add(responses.GET, "https://cible.test/", body=HOME_BARE,
                  status=200, content_type="text/html")
    # Le témoin soft-404 ET wp-login.php renvoient tous deux la home : le
    # scanner doit reconnaître wp-login.php comme un faux-positif de cache.
    responses.add(responses.GET,
                  "https://cible.test/wpsf-probe-4f9a2c7e-does-not-exist",
                  body=HOME_BARE, status=200, content_type="text/html")
    responses.add(responses.GET, "https://cible.test/feed/",
                  body=HOME_BARE, status=200, content_type="text/html")
    responses.add(responses.GET, "https://cible.test/wp-login.php",
                  body=HOME_BARE, status=200, content_type="text/html")
    responses.add(responses.GET, "https://cible.test/readme.html",
                  body=HOME_BARE, status=200, content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    result = chk.run()  # ne doit pas lever
    core = chk.context["inventory"]["core"]
    assert core is None
    assert result is not None


@responses.activate
def test_login_page_unreachable_falls_through_without_crash():
    """wp-login.php injoignable (exception réseau) : pas de crash, on
    retombe sur le comportement existant (readme.html, etc.)."""
    responses.add(responses.GET, "https://cible.test/", body=HOME_BARE,
                  status=200, content_type="text/html")
    responses.add(responses.GET,
                  "https://cible.test/wpsf-probe-4f9a2c7e-does-not-exist",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/feed/",
                  body="not found", status=404)
    responses.add(
        responses.GET, "https://cible.test/wp-login.php",
        body=ConnectionError("connexion refusée"),
    )
    responses.add(responses.GET, "https://cible.test/readme.html",
                  body="Version 6.1.1 readme text", status=200,
                  content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core is not None
    assert core["version"] == "6.1.1"
    assert core["source"] == "readme_html"


# ---------------------------------------------------------------------------
# Constat « version exposée » (recon) : seules les sources facilement
# retirables/publicitaires (generator, readme_html) déclenchent le constat -
# pas les sources fondées sur un ?ver= d'asset, difficiles à supprimer.
# ---------------------------------------------------------------------------

def _recon_finding(chk):
    return [f for f in chk.result.findings
            if f.get("access_class") == "recon"
            and "exposée" in f["message"]]


@responses.activate
def test_version_exposed_finding_emitted_for_generator_source():
    home = ('<html><head><meta name="generator" content="WordPress 6.9.4" />'
            '</head><body>ok</body></html>')
    responses.add(responses.GET, "https://cible.test/", body=home, status=200,
                  content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core["source"] == "generator"
    findings = _recon_finding(chk)
    assert len(findings) == 1
    f = findings[0]
    assert "6.9.4" in f["message"]
    assert "generator" in f["message"]
    assert f["severity"] in ("LOW", "INFO")
    assert f["confidence"] == "confirmed"


@responses.activate
def test_version_exposed_finding_emitted_for_readme_html_source():
    responses.add(responses.GET, "https://cible.test/", body=HOME_BARE,
                  status=200, content_type="text/html")
    responses.add(responses.GET,
                  "https://cible.test/wpsf-probe-4f9a2c7e-does-not-exist",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/feed/",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/wp-login.php",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/readme.html",
                  body="Version 6.1.1 readme text", status=200,
                  content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core["source"] == "readme_html"
    findings = _recon_finding(chk)
    assert len(findings) == 1
    assert "6.1.1" in findings[0]["message"]
    assert "readme_html" in findings[0]["message"]


@responses.activate
def test_version_exposed_finding_not_emitted_for_wpinc_ver_source():
    """Une version obtenue via l'asset ?ver= (home) n'est pas « exposée » au
    sens recon : c'est un signal technique difficile à retirer, pas un choix
    d'affichage. Pas de constat."""
    responses.add(responses.GET, "https://cible.test/", body=HOME_WPINC,
                  status=200, content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core["source"] == "wpinc_ver"
    assert _recon_finding(chk) == []


@responses.activate
def test_version_exposed_finding_not_emitted_for_login_wpinc_ver_source():
    """Idem pour la nouvelle source login_wpinc_ver : c'est aussi un ?ver=
    d'asset, pas un signal publicitaire."""
    responses.add(responses.GET, "https://cible.test/", body=HOME_BARE,
                  status=200, content_type="text/html")
    responses.add(responses.GET,
                  "https://cible.test/wpsf-probe-4f9a2c7e-does-not-exist",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/feed/",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/wp-login.php",
                  body=LOGIN_WPINC, status=200, content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core["source"] == "login_wpinc_ver"
    assert _recon_finding(chk) == []


@responses.activate
def test_version_exposed_finding_not_emitted_when_no_core_detected():
    responses.add(responses.GET, "https://cible.test/", body=HOME_BARE,
                  status=200, content_type="text/html")
    responses.add(responses.GET,
                  "https://cible.test/wpsf-probe-4f9a2c7e-does-not-exist",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/feed/",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/wp-login.php",
                  body="not found", status=404)
    responses.add(responses.GET, "https://cible.test/readme.html",
                  body="not found", status=404)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    core = chk.context["inventory"]["core"]
    assert core is None
    assert _recon_finding(chk) == []
