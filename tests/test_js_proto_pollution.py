"""Libs JS, la prototype pollution (jQuery < 3.4.0, CVE-2019-11358) doit
apparaître dans l'évidence, même quand la plage XSS < 3.5.0 (plus large) est
celle affichée dans le message. Sinon la classe proto-pollution reste masquée.
"""
import responses

from wp_security_forsure.scanner.checks.third_party_scripts import ThirdPartyScriptsCheck
from tests.conftest import make_check

HOME = "https://cible.test/"


def _run_with_jquery(version):
    html = (f'<html><head><script src="/wp-includes/js/jquery/jquery.min.js'
            f'?ver={version}"></script></head><body>x</body></html>')
    responses.add(responses.GET, HOME, body=html, status=200)
    chk = make_check(ThirdPartyScriptsCheck)
    chk._check_vulnerable_js_libraries()
    return [f for f in chk._result.findings
            if "Bibliothèque JS vulnérable" in f["message"]]


@responses.activate
def test_jquery_below_340_surfaces_prototype_pollution():
    """jQuery 3.3.1 : message = plage large (< 3.5.0) mais évidence liste CVE-2019-11358."""
    hits = _run_with_jquery("3.3.1")
    assert len(hits) == 1
    f = hits[0]
    assert "< 3.5.0" in f["message"]                 # plage la plus large
    assert "CVE-2019-11358" in f["evidence"]         # proto-pollution surfacée
    assert "prototype pollution" in f["evidence"].lower()


@responses.activate
def test_jquery_between_340_and_350_has_no_proto_pollution():
    """jQuery 3.4.1 : seule la XSS < 3.5.0 s'applique, pas la proto-pollution."""
    hits = _run_with_jquery("3.4.1")
    assert len(hits) == 1
    assert "CVE-2019-11358" not in hits[0]["evidence"]


@responses.activate
def test_recent_jquery_not_flagged():
    hits = _run_with_jquery("3.7.1")
    assert hits == []
