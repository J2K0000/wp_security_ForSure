"""P9, ?rest_route= n'est un « bypass » que si /wp-json/ est réellement bloqué."""
import re
import responses
from wp_security_forsure.scanner.checks.rest_api import RestApiCheck
from tests.conftest import make_check


def _bypass(chk):
    return [f for f in chk._result.findings if "bypass" in f["message"].lower()]


@responses.activate
def test_no_bypass_when_wpjson_works():
    responses.add(responses.GET, re.compile(r".*/wp-json/wp/v2/posts.*"),
                  json=[{"id": 1}], status=200)
    responses.add(responses.GET, re.compile(r".*[?&]rest_route=.*"),
                  json=[{"id": 1}], status=200)
    chk = make_check(RestApiCheck)
    chk._check_rest_disabled_bypass()
    assert _bypass(chk) == []


@responses.activate
def test_bypass_flagged_when_wpjson_blocked():
    responses.add(responses.GET, re.compile(r".*/wp-json/wp/v2/posts.*"),
                  body="Forbidden", status=403)
    responses.add(responses.GET, re.compile(r".*[?&]rest_route=.*"),
                  json=[{"id": 1}], status=200)
    chk = make_check(RestApiCheck)
    chk._check_rest_disabled_bypass()
    assert len(_bypass(chk)) >= 1
