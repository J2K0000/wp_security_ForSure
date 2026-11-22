"""get_json, helper factorisant le pattern try/GET/404/.json()/except répété
~15 fois dans rest_api.py (et ailleurs). Pin son contrat exact avant de
brancher les appelants dessus."""
import re
import responses

from wp_security_forsure.scanner.checks.base import BaseCheck
from tests.conftest import make_check


@responses.activate
def test_get_json_returns_data_and_resp_on_success():
    responses.add(responses.GET, re.compile(r".*/some/path"),
                  json={"ok": True}, status=200)
    chk = make_check(BaseCheck)
    data, resp = chk.get_json("some/path")
    assert data == {"ok": True}
    assert resp.status_code == 200


@responses.activate
def test_get_json_bails_on_404_by_default():
    responses.add(responses.GET, re.compile(r".*/missing"),
                  json={"code": "not_used"}, status=404)
    chk = make_check(BaseCheck)
    data, resp = chk.get_json("missing")
    assert data is None
    assert resp.status_code == 404  # resp reste dispo pour l'appelant


@responses.activate
def test_get_json_bail_404_false_still_parses_body():
    responses.add(responses.GET, re.compile(r".*/missing"),
                  json={"code": "rest_no_route"}, status=404)
    chk = make_check(BaseCheck)
    data, resp = chk.get_json("missing", bail_404=False)
    assert data == {"code": "rest_no_route"}
    assert resp.status_code == 404


@responses.activate
def test_get_json_returns_none_data_on_non_json_body():
    responses.add(responses.GET, re.compile(r".*/html-page"),
                  body="<html>not json</html>", status=200,
                  content_type="text/html")
    chk = make_check(BaseCheck)
    data, resp = chk.get_json("html-page")
    assert data is None
    assert resp.status_code == 200


def test_get_json_returns_none_none_on_request_exception():
    chk = make_check(BaseCheck, target="https://unreachable.invalid.test")

    def boom(*a, **kw):
        raise ConnectionError("network down")

    chk.http_get = boom
    data, resp = chk.get_json("anything")
    assert data is None
    assert resp is None


@responses.activate
def test_get_json_forwards_kwargs_to_http_get():
    responses.add(responses.GET, re.compile(r".*/needs-header"),
                  json={"seen": True}, status=200)
    chk = make_check(BaseCheck)
    data, resp = chk.get_json("needs-header", headers={"Accept": "application/json"})
    assert data == {"seen": True}
    sent = responses.calls[0].request
    assert sent.headers.get("Accept") == "application/json"
