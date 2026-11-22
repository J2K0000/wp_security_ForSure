"""P3, application-passwords : un WP_Error (endpoint protégé) ne doit pas être
un CRITICAL ; seul un 200 + données réelles l'est."""
import responses
from wp_security_forsure.scanner.checks.rest_api import RestApiCheck
from tests.conftest import make_check

PATH = "https://cible.test/wp-json/wp/v2/users/1/application-passwords"


def _crit(chk):
    return [f for f in chk._result.findings if f["severity"] == "CRITICAL"]


@responses.activate
def test_protected_wp_error_is_not_critical():
    responses.add(responses.GET, PATH, json={"code": "rest_forbidden", "message": "no"},
                  status=401)
    chk = make_check(RestApiCheck)
    chk._check_application_passwords()
    assert _crit(chk) == []


@responses.activate
def test_real_exposure_list_is_critical():
    responses.add(responses.GET, PATH,
                  json=[{"uuid": "x", "app_id": "y", "name": "leak"}], status=200)
    chk = make_check(RestApiCheck)
    chk._check_application_passwords()
    assert len(_crit(chk)) == 1
