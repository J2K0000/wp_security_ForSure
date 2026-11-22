import responses
from wp_security_forsure.scanner.checks.server_security import ServerSecurityCheck
from tests.conftest import make_check

HOME = "<!DOCTYPE html><html><body>" + ("x" * 5000) + "</body></html>"


@responses.activate
def test_methods_mirroring_get_are_not_flagged():
    # Le serveur renvoie la home (200) pour TOUTES les méthodes.
    url = "https://cible.test/"
    for m in (responses.GET, responses.OPTIONS, "PUT", "DELETE", "TRACE", "CONNECT"):
        responses.add(m, url, body=HOME, status=200,
                      content_type="text/html")
    # PUT avec corps sur le fichier de test → renvoie aussi la home
    responses.add("PUT", "https://cible.test/security_audit_put_test.txt",
                  body=HOME, status=200)
    # GET de vérification du fichier uploadé → 404 (rien n'a été écrit)
    responses.add(responses.GET, "https://cible.test/security_audit_put_test.txt",
                  status=404)

    chk = make_check(ServerSecurityCheck)
    chk._check_http_methods()
    msgs = [f["message"] for f in chk._result.findings]
    assert not any("ENABLED" in m for m in msgs), msgs
    assert not any("upload possible" in m for m in msgs), msgs


@responses.activate
def test_dangerous_methods_are_never_sent_only_allow_header_is_read():
    """Inversé : TRACE/CONNECT ne sont plus émis (ni PUT/DELETE). Seul
    OPTIONS part ; les méthodes annoncées dans Allow donnent des constats
    `potential` (prise en charge réelle non évaluable passivement)."""
    url = "https://cible.test/"
    responses.add(responses.OPTIONS, url, status=200,
                  headers={"Allow": "GET, HEAD, TRACE, CONNECT"})
    for m in ("PUT", "DELETE", "TRACE", "CONNECT"):
        responses.add(m, url, body="home", status=200)
    chk = make_check(ServerSecurityCheck)
    chk._check_http_methods()
    assert [c.request.method for c in responses.calls] == ["OPTIONS"]
    adv = [f for f in chk._result.findings if "advertises" in f["message"]]
    assert len(adv) == 1, chk._result.findings
    assert "CONNECT" in adv[0]["message"] and "TRACE" in adv[0]["message"]
    assert adv[0]["confidence"] == "potential"
    assert not any("ENABLED" in f["message"] for f in chk._result.findings)


@responses.activate
def test_options_advertised_but_denied_is_not_flagged():
    url = "https://cible.test/"
    responses.add(responses.GET, url, body="<html>home</html>", status=200)
    responses.add(responses.OPTIONS, url, status=200, headers={"Allow": "GET, POST, TRACE"})
    responses.add("TRACE", url, body="403 Forbidden", status=403)
    responses.add("PUT", url, body="403", status=403)
    responses.add("DELETE", url, body="403", status=403)
    responses.add("CONNECT", url, body="403", status=403)
    responses.add("PUT", "https://cible.test/security_audit_put_test.txt", status=403)
    chk = make_check(ServerSecurityCheck)
    chk._check_http_methods()
    msgs = [f["message"] for f in chk._result.findings]
    assert not any("ENABLED" in m for m in msgs), msgs
