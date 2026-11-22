"""Fix B, le test de méthode PUT/DELETE ne doit JAMAIS écrire sur la cible,
même en mode --aggressive. Détection uniquement passive via l'en-tête Allow
renvoyé par OPTIONS."""
import responses
from wp_security_forsure.scanner.checks.server_security import ServerSecurityCheck
from tests.conftest import make_check

HOME = "<html>home</html>"


@responses.activate
def test_put_advertised_via_options_is_potential_high_and_no_active_write():
    url = "https://cible.test/"
    responses.add(responses.GET, url, body=HOME, status=200)
    responses.add(responses.OPTIONS, url, status=200, headers={"Allow": "GET, POST, PUT"})
    responses.add("TRACE", url, status=403)
    responses.add("CONNECT", url, status=403)

    # Même avec aggressive=True, aucune écriture active ne doit avoir lieu.
    chk = make_check(ServerSecurityCheck, config={"aggressive": True})
    chk._check_http_methods()

    put_findings = [f for f in chk._result.findings if "PUT/DELETE" in f["message"]]
    assert len(put_findings) == 1, chk._result.findings
    assert put_findings[0]["severity"] == "HIGH"
    assert put_findings[0]["confidence"] == "potential"
    assert "non testée activement" in put_findings[0]["message"]

    methods_called = {c.request.method for c in responses.calls}
    assert "PUT" not in methods_called, methods_called
    assert "DELETE" not in methods_called, methods_called
    # Aucun fichier de test n'a été écrit sur la cible.
    assert not any("security_audit_put_test" in c.request.url for c in responses.calls)
    assert not any("upload possible" in f["message"] for f in chk._result.findings)


@responses.activate
def test_delete_advertised_via_options_is_potential_high_and_no_active_write():
    url = "https://cible.test/"
    responses.add(responses.GET, url, body=HOME, status=200)
    responses.add(responses.OPTIONS, url, status=200, headers={"Allow": "GET, POST, DELETE"})
    responses.add("TRACE", url, status=403)
    responses.add("CONNECT", url, status=403)

    chk = make_check(ServerSecurityCheck)
    chk._check_http_methods()

    put_findings = [f for f in chk._result.findings if "PUT/DELETE" in f["message"]]
    assert len(put_findings) == 1, chk._result.findings
    assert put_findings[0]["severity"] == "HIGH"
    assert put_findings[0]["confidence"] == "potential"

    methods_called = {c.request.method for c in responses.calls}
    assert "PUT" not in methods_called, methods_called
    assert "DELETE" not in methods_called, methods_called


@responses.activate
def test_get_post_only_no_dangerous_write_method_finding():
    url = "https://cible.test/"
    responses.add(responses.GET, url, body=HOME, status=200)
    responses.add(responses.OPTIONS, url, status=200, headers={"Allow": "GET, POST"})
    responses.add("TRACE", url, status=403)
    responses.add("CONNECT", url, status=403)

    chk = make_check(ServerSecurityCheck, config={"aggressive": True})
    chk._check_http_methods()

    msgs = [f["message"] for f in chk._result.findings]
    assert not any("PUT/DELETE" in m for m in msgs), msgs

    methods_called = {c.request.method for c in responses.calls}
    assert "PUT" not in methods_called, methods_called
    assert "DELETE" not in methods_called, methods_called
