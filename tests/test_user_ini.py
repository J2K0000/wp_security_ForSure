""".user.ini servi par le serveur : lu comme un fichier texte (niveau 2)."""
import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.file_exposure import FileExposureCheck

URL = "https://cible.test/.user.ini"


def run(body, status=200, ctype="text/plain", authorized=True):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.HEAD, URL, status=status)
        rsps.add(responses.GET, URL, body=body, status=status, content_type=ctype)
        rsps.add(responses.GET, "https://cible.test/wpsf-soft404-probe-0000.html",
                 body="introuvable", status=404)
        chk = make_check(FileExposureCheck, config={"authorized": authorized})
        chk.CATEGORIES = [c for c in chk.CATEGORIES if c["label"] == ".user.ini"]
        result = chk.run()
    return [f for f in result.findings if ".user.ini" in f["message"]]


def test_unknown_auto_prepend_file_is_critical():
    found = run("memory_limit = 256M\nauto_prepend_file = '/home/site/public_html/wp-includes/class-wp-cache.php'\n")
    msgs = {f["message"]: f for f in found}
    assert ".user.ini lisible depuis le Web (divulgation d'information)" in msgs
    crit = [f for f in found if f["severity"] == "CRITICAL"]
    assert crit and crit[0]["confidence"] == "potential"
    assert "class-wp-cache.php" in crit[0]["evidence"]


def test_wordfence_waf_loader_is_informational():
    found = run("auto_prepend_file = '/var/www/wordfence-waf.php'\n")
    assert [f["severity"] for f in found] == ["MEDIUM", "INFO"]


def test_html_page_is_not_a_user_ini():
    assert run("<html><body>Not found</body></html>", ctype="text/html") == []


def test_not_requested_without_authorized():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        chk = make_check(FileExposureCheck, config={"authorized": False})
        chk.CATEGORIES = [c for c in chk.CATEGORIES if c["label"] == ".user.ini"]
        chk.run()
        assert not [c for c in rsps.calls if ".user.ini" in c.request.url]
