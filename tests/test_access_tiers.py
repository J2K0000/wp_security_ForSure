"""Niveaux d'accès des requêtes vers la cible (scanner/access_tiers.py) et
leur application par le client HTTP de BaseCheck.

Niveau 0 : l'accueil et ce qu'il référence. Niveau 1 : la liste fermée des
points d'entrée publics standard de WordPress, et ce que référence une autre
page déjà récupérée. Niveau 2 : tout chemin deviné et non lié, réservé au mode
--authorized. Interdit à tout niveau : wp-cron.php, diagnostics Site Health et
fichier PHP deviné sous wp-content/, uploads/ ou mu-plugins/.
"""
import re

import pytest
import requests
import responses

from wp_security_forsure.scanner import access_tiers as at
from wp_security_forsure.scanner.checks.base import (
    AccessTierRequired,
    BaseCheck,
    ForbiddenProbe,
)
from tests.conftest import make_check

TARGET = "https://cible.test"


class _Probe(BaseCheck):
    name = "probe_tiers"
    title = "probe"
    description = "test only"

    def run(self):
        return self._result


def _tier(path, method="GET", refs=None, target=TARGET):
    url = path if path.startswith("http") else f"{target}/{path}"
    return at.classify(method, url, target, refs or {})


def _catch_all(body="<html></html>", content_type="text/html"):
    for method in ("GET", "HEAD", "OPTIONS"):
        responses.add(method, re.compile(r".*"), body=body, status=200,
                      content_type=content_type)


# ── Liste fermée du niveau 1 ────────────────────────────────────────────

LEVEL_1 = [
    ("wp-json/", "GET"), ("wp-json", "GET"), ("wp-json/wp/v2/users", "GET"),
    ("wp-json/wp/v2/posts?per_page=1", "GET"), ("wp-json/batch/v1", "OPTIONS"),
    ("?rest_route=/", "GET"), ("?rest_route=/wp/v2/posts&per_page=1", "GET"),
    ("feed/", "GET"), ("feed", "GET"), ("comments/feed/", "GET"),
    ("?feed=rss2", "GET"), ("xmlrpc.php", "GET"), ("xmlrpc.php?rsd", "GET"),
    ("wp-login.php", "GET"), ("wp-login.php?action=register", "GET"),
    ("wp-login.php?action=lostpassword", "GET"), ("robots.txt", "GET"),
    ("sitemap.xml", "GET"), ("wp-sitemap.xml", "GET"),
    ("sitemap_index.xml", "GET"), ("readme.html", "HEAD"),
    ("license.txt", "GET"), ("?author=1", "GET"), ("?author=12", "GET"),
    ("?s=bonjour", "GET"), ("?p=42", "GET"), ("wp-admin/", "GET"),
    ("wp-admin", "GET"), ("wp-admin/admin-ajax.php", "GET"),
    (".well-known/security.txt", "GET"), ("favicon.ico", "GET"),
    ("index.php", "HEAD"), ("wp-signup.php", "GET"),
    (at.SOFT404_PROBE_PATH, "GET"),
]


@pytest.mark.parametrize("path, method", LEVEL_1)
def test_closed_list_entries_are_level_1(path, method):
    assert _tier(path, method) == at.TIER_PUBLIC


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_home_is_level_0(method):
    assert _tier("", method) == at.TIER_HOME
    assert at.classify(method, TARGET, TARGET, {}) == at.TIER_HOME


def test_closed_list_follows_a_subdirectory_install():
    target = "https://cible.test/blog"
    assert _tier("wp-json/", target=target) == at.TIER_PUBLIC
    assert _tier("", target=target) == at.TIER_HOME
    assert _tier(".env", target=target) == at.TIER_UNLINKED


def test_other_hosts_are_not_classified():
    assert at.classify("GET", "https://cdn.tiers.test/x.js", TARGET, {}) is None
    assert at.classify("GET", "https://www.cible.test/robots.txt",
                       TARGET, {}) == at.TIER_PUBLIC


# ── Chemins devinés : niveau 2 ───────────────────────────────────────────

LEVEL_2 = [
    (".env", "HEAD"), (".git/HEAD", "HEAD"), ("wp-config.php.bak", "HEAD"),
    ("wp-config.php~", "HEAD"), ("wp-content/debug.log", "HEAD"),
    ("phpinfo.php", "HEAD"), ("backup.sql.gz", "HEAD"), (".htaccess", "GET"),
    ("wp-content/uploads/", "HEAD"), ("wp-content/plugins/", "GET"),
    ("wp-content/plugins/akismet/readme.txt", "GET"),
    ("wp-content/themes/astra/style.css", "GET"),
    ("wp-content/uploads/2020/01/a.php.bak", "HEAD"),
    ("wp-admin/install.php", "HEAD"), ("wp-admin/network/", "GET"),
    ("?author=abc", "GET"), ("?wc-api=", "GET"), ("?p=1&x=2", "GET"),
    ("wp-login.php?action=rp", "GET"), ("xmlrpc.php", "OPTIONS"),
    ("wp-admin/admin-ajax.php?action=heartbeat", "GET"),
    ("wp-admin/admin-ajax.php", "OPTIONS"), ("checkout/", "GET"),
    ("robots.txt.bak", "GET"),
]


@pytest.mark.parametrize("path, method", LEVEL_2)
def test_guessed_paths_are_level_2(path, method):
    assert _tier(path, method) == at.TIER_UNLINKED


def test_dot_segments_cannot_smuggle_a_guessed_path_into_the_list():
    assert _tier("wp-json/../.env") == at.TIER_UNLINKED
    assert _tier("feed/../wp-config.php.bak") == at.TIER_UNLINKED


# ── Ressources référencées ───────────────────────────────────────────────

def test_resource_referenced_by_home_is_level_0_by_another_page_level_1():
    refs = {}
    at.add_references(refs, ["https://cible.test/wp-content/themes/t/style.css?ver=6.4"],
                      TARGET, at.TIER_HOME)
    at.add_references(refs, ["/wp-includes/js/wp-embed.min.js"], TARGET,
                      at.TIER_PUBLIC, base_url="https://cible.test/feed/")
    assert _tier("wp-content/themes/t/style.css", refs=refs) == at.TIER_HOME
    assert _tier("wp-includes/js/wp-embed.min.js", refs=refs) == at.TIER_PUBLIC
    # Même dossier, fichier non référencé : deviné.
    assert _tier("wp-content/themes/t/readme.txt", refs=refs) == at.TIER_UNLINKED


def test_referenced_script_keeps_its_query_string():
    refs = {}
    at.add_references(refs, ["/wp-content/plugins/x/feed.php?id=3"], TARGET,
                      at.TIER_HOME, base_url=TARGET + "/")
    assert _tier("wp-content/plugins/x/feed.php?id=3", refs=refs) == at.TIER_HOME
    assert _tier("wp-content/plugins/x/feed.php?id=4", refs=refs) == at.TIER_UNLINKED


def test_extract_references_reads_html_css_json_and_xml():
    html = ('<link rel="stylesheet" href="/wp-content/themes/t/style.css?ver=1">'
            '<script src="https://cible.test/wp-includes/js/a.js"></script>'
            '<img srcset="/wp-content/uploads/a.jpg 1x, /wp-content/uploads/b.jpg 2x">'
            '<a href="contact/">Contact</a><a href="#top">haut</a>')
    found = set(at.extract_references(html, "text/html", TARGET + "/"))
    assert {"https://cible.test/wp-content/themes/t/style.css?ver=1",
            "https://cible.test/wp-includes/js/a.js",
            "https://cible.test/wp-content/uploads/a.jpg",
            "https://cible.test/wp-content/uploads/b.jpg",
            "https://cible.test/contact/"} <= found
    css = "body{background:url('../img/fond.png')}"
    assert ("https://cible.test/wp-content/themes/t/img/fond.png"
            in set(at.extract_references(
                css, "text/css", "https://cible.test/wp-content/themes/t/css/s.css")))
    js = '{"source_url":"https:\\/\\/cible.test\\/wp-content\\/uploads\\/c.png"}'
    assert ("https://cible.test/wp-content/uploads/c.png"
            in set(at.extract_references(js, "application/json", TARGET)))
    xml = "<urlset><url><loc>https://cible.test/wp-sitemap-posts-post-1.xml</loc></url></urlset>"
    assert ("https://cible.test/wp-sitemap-posts-post-1.xml"
            in set(at.extract_references(xml, "application/xml", TARGET)))
    assert list(at.extract_references("\x89PNG", "image/png", TARGET)) == []


# ── Interdit à tout niveau ───────────────────────────────────────────────

FORBIDDEN = [
    "wp-cron.php", "WP-CRON.PHP", "wp-cron.php?doing_wp_cron=1",
    "?doing_wp_cron=1", "wp-cron%2Ephp", "wp-json/../wp-cron.php",
    "wp-content/uploads/2024/01/shell.php", "wp-content/mu-plugins/loader.php",
    "wp-content/db.php", "wp-content/object-cache.php",
    "wp-content/advanced-cache.php", "wp-content/sunrise.php",
    "wp-content/plugins/akismet/akismet.php", "wp-content/./uploads/a.php",
    "wp-content/uploads/a.php/b.jpg", "wp-content/uploads/a.phtml",
    "wp-content/w3tc-config/master.php", "uploads/x.php",
    "wp-json/wp-site-health/v1/tests/loopback-requests",
    "?rest_route=/wp-site-health/v1/tests/background-updates",
    "wp-json/wp-site-health/v1/directory-sizes",
]


@pytest.mark.parametrize("path", FORBIDDEN)
def test_forbidden_requests_have_a_reason(path):
    assert at.forbidden_reason(f"{TARGET}/{path}", TARGET, {})


@pytest.mark.parametrize("path", [
    "", "wp-json/wp-site-health/v1", "wp-content/uploads/a.php.bak",
    "wp-content/plugins/x/readme.txt", "phpinfo.php", "wp-includes/version.php",
    ".user.ini", ".htaccess", "wp-login.php",
])
def test_non_php_and_non_task_paths_are_not_forbidden(path):
    assert at.forbidden_reason(f"{TARGET}/{path}", TARGET, {}) is None


def test_referenced_php_under_wp_content_is_not_forbidden():
    refs = {}
    at.add_references(refs, ["/wp-content/plugins/x/style.php?v=2"], TARGET,
                      at.TIER_HOME, base_url=TARGET + "/")
    url = f"{TARGET}/wp-content/plugins/x/style.php?v=2"
    assert at.forbidden_reason(url, TARGET, refs) is None
    # wp-cron.php reste interdit même s'il est lié.
    at.add_references(refs, ["/wp-cron.php"], TARGET, at.TIER_HOME,
                      base_url=TARGET + "/")
    assert at.forbidden_reason(f"{TARGET}/wp-cron.php", TARGET, refs)


# ── Client HTTP de BaseCheck ─────────────────────────────────────────────

def test_access_tier_required_is_not_a_request_exception():
    assert not issubclass(AccessTierRequired, requests.exceptions.RequestException)
    assert not issubclass(ForbiddenProbe, requests.exceptions.RequestException)
    # Ni même une Exception : un « except Exception » de check ne l'avale pas.
    assert not issubclass(AccessTierRequired, Exception)
    assert not issubclass(ForbiddenProbe, Exception)


@responses.activate
def test_level_2_request_is_refused_without_authorized():
    _catch_all()
    chk = make_check(_Probe, config={"authorized": False})
    with pytest.raises(AccessTierRequired):
        chk.http_head(".env")
    with pytest.raises(AccessTierRequired):
        chk.http_get("wp-content/plugins/akismet/readme.txt")
    assert len(responses.calls) == 0


@responses.activate
def test_broad_except_in_a_check_does_not_swallow_the_refusal():
    _catch_all()
    chk = make_check(_Probe, config={"authorized": False})
    with pytest.raises(AccessTierRequired):
        try:
            chk.http_get(".git/HEAD")
        except Exception:
            pytest.fail("AccessTierRequired a été avalée par « except Exception »")


@responses.activate
def test_level_2_request_is_sent_with_authorized():
    _catch_all()
    chk = make_check(_Probe, config={"authorized": True})
    assert chk.http_head(".env").status_code == 200
    assert len(responses.calls) == 1


@responses.activate
@pytest.mark.parametrize("authorized", [False, True])
def test_forbidden_request_is_refused_in_both_modes(authorized):
    _catch_all()
    chk = make_check(_Probe, config={"authorized": authorized})
    for path in ("wp-cron.php", "wp-content/uploads/2024/01/x.php",
                 "wp-content/object-cache.php"):
        with pytest.raises(ForbiddenProbe):
            chk.http_head(path)
    assert len(responses.calls) == 0


@responses.activate
def test_level_1_requests_are_sent_by_default():
    _catch_all()
    chk = make_check(_Probe, config={"authorized": False})
    for path in ("", "wp-json/", "robots.txt", "?author=1", "wp-login.php"):
        chk.http_get(path)
    chk.http_options("wp-json/batch/v1")
    assert len(responses.calls) == 6


@responses.activate
def test_resource_referenced_by_a_fetched_page_becomes_reachable():
    home = ('<link rel="stylesheet" href="https://cible.test/wp-content/themes/t/'
            'style.css?ver=6.4"><script src="/wp-content/plugins/p/app.js"></script>')
    responses.add(responses.GET, f"{TARGET}/", body=home, status=200,
                  content_type="text/html")
    responses.add(responses.GET, re.compile(r".*/wp-content/.*"), body="x",
                  status=200, content_type="text/css")
    chk = make_check(_Probe, config={"authorized": False})
    with pytest.raises(AccessTierRequired):
        chk.http_get("wp-content/themes/t/style.css")
    chk.http_get("")
    assert chk.http_get("wp-content/themes/t/style.css").status_code == 200
    assert chk.http_get("wp-content/plugins/p/app.js").status_code == 200
    assert chk.request_tier("wp-content/themes/t/style.css") == at.TIER_HOME
    with pytest.raises(AccessTierRequired):
        chk.http_get("wp-content/themes/t/readme.txt")


@responses.activate
def test_redirect_designated_by_the_server_is_followed():
    responses.add(responses.GET, f"{TARGET}/wp-admin/", status=302,
                  headers={"Location": f"{TARGET}/wp-login.php?redirect_to=x&reauth=1"})
    responses.add(responses.GET, re.compile(r".*/wp-login\.php.*"), body="ok",
                  status=200)
    chk = make_check(_Probe, config={"authorized": False})
    resp = chk.http_get("wp-admin/")
    assert resp.status_code == 200
    assert len(responses.calls) == 2


@responses.activate
@pytest.mark.parametrize("authorized", [False, True])
def test_redirect_to_a_forbidden_destination_is_not_followed(authorized):
    responses.add(responses.GET, f"{TARGET}/feed/", status=302,
                  headers={"Location": f"{TARGET}/wp-cron.php?doing_wp_cron=1"})
    responses.add(responses.GET, re.compile(r".*wp-cron.*"), body="cron", status=200)
    chk = make_check(_Probe, config={"authorized": authorized})
    resp = chk.http_get("feed/")
    assert resp.status_code == 302
    assert len(responses.calls) == 1


@responses.activate
def test_mixed_check_says_what_it_did_not_do_by_default():
    from wp_security_forsure.scanner.checks.fingerprint import FingerprintCheck
    _catch_all()
    chk = make_check(FingerprintCheck, config={"authorized": False})
    result = chk.run()
    assert not any("readme.txt" in c.request.url or "style.css" in c.request.url
                   for c in responses.calls)
    notes = [f for f in result.findings
             if f["message"].startswith("Non réalisé sans --authorized")]
    assert len(notes) == 1 and notes[0]["severity"] == "INFO"
    assert "readme.txt" in notes[0]["message"]


def test_may_request_tells_mixed_checks_what_they_can_send():
    off = make_check(_Probe, config={"authorized": False})
    on = make_check(_Probe, config={"authorized": True})
    assert off.may_request("readme.html") and on.may_request("readme.html")
    assert not off.may_request(".env") and on.may_request(".env")
    assert not off.may_request("wp-cron.php") and not on.may_request("wp-cron.php")
    assert not off.may_request("xmlrpc.php", method="OPTIONS")
    assert off.may_request("https://cdn.tiers.test/lib.js")
