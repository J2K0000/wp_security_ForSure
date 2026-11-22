"""Version du cœur : les bibliothèques tierces embarquées dans wp-includes
(jQuery, underscore...) ne donnent jamais la version de WordPress, et toutes
les sources de version du cœur sont croisées (divergence = « à vérifier »)."""
import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.fingerprint import (
    FingerprintCheck,
    core_asset_versions,
)
from wp_security_forsure.scanner.checks.vulnerability_scan import VulnerabilityScanCheck

BASE = "https://cible.test"

BUNDLED_LIBS = [
    "/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
    "/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1",
    "/wp-includes/js/jquery/ui/core.min.js?ver=1.13.2",
    "/wp-includes/js/tinymce/tinymce.min.js?ver=4.9.11",
    "/wp-includes/js/dist/vendor/react.min.js?ver=18.3.1",
    "/wp-includes/js/dist/vendor/lodash.min.js?ver=4.17.21",
    "/wp-includes/js/dist/i18n.min.js?ver=3.1.0",
    "/wp-includes/js/underscore.min.js?ver=1.13.4",
    "/wp-includes/js/backbone.min.js?ver=1.5.0",
    "/wp-includes/js/plupload/plupload.full.min.js?ver=2.1.9",
    "/wp-includes/js/mediaelement/mediaelement-and-player.min.js?ver=4.2.17",
    "/wp-includes/js/codemirror/codemirror.min.js?ver=5.29.1",
    "/wp-includes/js/imagesloaded.min.js?ver=5.0.0",
    "/wp-includes/js/masonry.min.js?ver=4.2.2",
    "/wp-includes/js/hoverIntent.min.js?ver=1.10.2",
    "/wp-includes/js/hoverintent-js.min.js?ver=2.2.1",
    "/wp-includes/js/clipboard.min.js?ver=2.0.11",
    "/wp-includes/js/thickbox/thickbox.js?ver=3.1",
    "/wp-includes/js/swfobject.js?ver=2.2",
    "/wp-includes/js/twemoji.min.js?ver=15.0.3",
]


def _page(*srcs, extra=""):
    tags = "".join(f'<script src="{BASE}{s}"></script>' for s in srcs)
    return f"<html><head>{extra}{tags}</head><body>ok</body></html>"


def _no_other_source():
    """Témoin soft-404, flux, connexion et readme.html sans version."""
    for path in ("wpsf-probe-4f9a2c7e-does-not-exist", "feed/",
                 "wp-login.php", "readme.html"):
        responses.add(responses.GET, f"{BASE}/{path}", body="not found", status=404)


def _run_home(home):
    responses.add(responses.GET, f"{BASE}/", body=home, status=200,
                  content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    return chk


def _inconsistency(chk):
    return [f for f in chk.result.findings if "incohérentes" in f["message"]]


def test_core_asset_versions_ignores_bundled_libraries():
    assert core_asset_versions(_page(*BUNDLED_LIBS)) == []


def test_core_asset_versions_keeps_core_resources():
    home = _page("/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
                 "/wp-includes/js/comment-reply.min.js?ver=6.4.3",
                 extra=f'<link href="{BASE}/wp-includes/css/dashicons.min.css?ver=6.4.3">')
    assert core_asset_versions(home) == ["6.4.3", "6.4.3"]


def test_core_asset_versions_rejects_non_core_version_format():
    home = _page("/wp-includes/js/wp-embed.min.js?ver=6.4.3-alpha-57000",
                 "/wp-includes/js/dist/hooks.min.js?ver=4d63a3d491d11ffd8ac6")
    assert core_asset_versions(home) == []


@responses.activate
def test_jquery_alone_gives_no_core_version():
    _no_other_source()
    chk = _run_home(_page("/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"))
    assert chk.context["inventory"]["core"] is None


@responses.activate
def test_all_bundled_libraries_give_no_core_version():
    _no_other_source()
    chk = _run_home(_page(*BUNDLED_LIBS))
    assert chk.context["inventory"]["core"] is None


@responses.activate
def test_core_resource_wins_over_jquery_on_same_page():
    _no_other_source()
    chk = _run_home(_page("/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
                          "/wp-includes/js/comment-reply.min.js?ver=6.4.3"))
    core = chk.context["inventory"]["core"]
    assert core["version"] == "6.4.3"
    assert core["source"] == "wpinc_ver"


@responses.activate
def test_two_concordant_sources_are_confirmed():
    _no_other_source()
    chk = _run_home(_page(
        "/wp-includes/js/comment-reply.min.js?ver=6.4.3",
        extra='<meta name="generator" content="WordPress 6.4.3" />'))
    core = chk.context["inventory"]["core"]
    assert core["version"] == "6.4.3"
    assert core["confidence"] == "confirmed"
    assert core["sources"] == {"generator": "6.4.3", "wpinc_ver": "6.4.3"}
    assert _inconsistency(chk) == []


@responses.activate
def test_two_divergent_sources_are_potential_with_finding():
    responses.add(responses.GET, f"{BASE}/wpsf-probe-4f9a2c7e-does-not-exist",
                  body="not found", status=404)
    responses.add(responses.GET, f"{BASE}/feed/", status=200,
                  body="<rss><channel><generator>https://wordpress.org/?v=6.5.2"
                       "</generator></channel></rss>",
                  content_type="application/rss+xml")
    for path in ("wp-login.php", "readme.html"):
        responses.add(responses.GET, f"{BASE}/{path}", body="not found", status=404)
    chk = _run_home(_page(extra='<meta name="generator" content="WordPress 6.4.3" />'))
    core = chk.context["inventory"]["core"]
    assert core["confidence"] == "potential"
    assert core["sources"] == {"generator": "6.4.3", "feed_generator": "6.5.2"}
    findings = _inconsistency(chk)
    assert len(findings) == 1
    f = findings[0]
    assert "mise à jour peut-être incomplète ou version masquée" in f["message"]
    assert f["confidence"] == "potential"
    assert "6.4.3" in f["evidence"] and "6.5.2" in f["evidence"]
    assert "balise generator" in f["evidence"] and "flux RSS" in f["evidence"]


@responses.activate
def test_login_page_jquery_is_not_core_version():
    """wp-login.php charge jQuery : sa version ne doit pas passer pour le cœur."""
    for path in ("wpsf-probe-4f9a2c7e-does-not-exist", "feed/", "readme.html"):
        responses.add(responses.GET, f"{BASE}/{path}", body="not found", status=404)
    responses.add(responses.GET, f"{BASE}/wp-login.php", status=200,
                  body=_page("/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
                             "/wp-includes/js/underscore.min.js?ver=1.13.4"),
                  content_type="text/html")
    chk = _run_home(_page())
    assert chk.context["inventory"]["core"] is None


@responses.activate
def test_readme_branch_matches_full_version():
    """readme.html n'affiche parfois que la branche (6.4) : pas une divergence."""
    for path in ("wpsf-probe-4f9a2c7e-does-not-exist", "feed/", "wp-login.php"):
        responses.add(responses.GET, f"{BASE}/{path}", body="not found", status=404)
    responses.add(responses.GET, f"{BASE}/readme.html", body="<br /> Version 6.4",
                  status=200, content_type="text/html")
    chk = _run_home(_page(extra='<meta name="generator" content="WordPress 6.4.3" />'))
    core = chk.context["inventory"]["core"]
    assert core["confidence"] == "confirmed"
    assert _inconsistency(chk) == []


class _FakeCache:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_or_fetch(self, type_, slug, client, ttl_days=7, now=None):
        return self.mapping.get(slug), False


CORE_VULN = {"data": {"vulnerability": [{
    "name": "WordPress < 6.4.4", "operator": {
        "min_version": None, "min_operator": None,
        "max_version": "6.4.4", "max_operator": "lt", "unfixed": "0"},
    "source": [{"id": "CVE-2024-0001", "link": "https://x"}],
    "impact": {"cvss": {"score": "9.8", "vector": "v"}},
}]}}


def _vuln_findings(core):
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"core": core, "plugins": [], "themes": []}}
    chk._cache = _FakeCache({core["version"]: CORE_VULN})
    chk._client = lambda t, s: None
    chk.run()
    return [f for f in chk.result.findings if "CVE-2024-0001" in f["evidence"]]


def test_vulnerability_scan_keeps_confirmed_for_concordant_core():
    vulns = _vuln_findings({"version": "6.4.3", "source": "generator",
                            "confidence": "confirmed"})
    assert vulns and vulns[0]["confidence"] == "confirmed"


def test_vulnerability_scan_downgrades_divergent_core_to_potential():
    vulns = _vuln_findings({"version": "6.4.3", "source": "generator",
                            "confidence": "potential"})
    assert vulns and vulns[0]["confidence"] == "potential"
