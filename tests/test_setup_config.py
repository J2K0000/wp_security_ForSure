"""wp-admin/setup-config.php : assistant de configuration resté ouvert."""
import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.database_exposure import DatabaseExposureCheck

URL = "https://cible.test/wp-admin/setup-config.php"

OPEN = ("<html><body><form id='setup' method='post' action='setup-config.php?step=1'>"
        "<select name='language' id='language'></select></form></body></html>")
LOCKED = ("<html><body><p>The file wp-config.php already exists. If you need to reset "
          "any of the configuration items in this file, please delete it first.</p>"
          "</body></html>")


def run(body, status=200):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.HEAD, URL, status=status)
        rsps.add(responses.GET, URL, body=body, status=status, content_type="text/html")
        chk = make_check(DatabaseExposureCheck, config={"authorized": True})
        chk._check_setup_config()
    return [f for f in chk.result.findings if "setup-config" in f["message"]]


def test_open_wizard_is_critical_confirmed():
    f = run(OPEN)[0]
    assert f["severity"] == "CRITICAL" and f["confidence"] == "confirmed"
    assert "setup-config.php?step=1" in f["evidence"]


def test_existing_configuration_is_informational():
    assert [f["severity"] for f in run(LOCKED)] == ["INFO"]


def test_missing_or_redirected_page_gives_nothing():
    assert run("", status=404) == []
    assert run("<html>moved</html>", status=302) == []


def test_not_requested_without_authorized():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        chk = make_check(DatabaseExposureCheck, config={"authorized": False})
        chk.run()
        assert not [c for c in rsps.calls if "setup-config" in c.request.url]
    assert any("setup-config.php" in f["message"] for f in chk.result.findings)
