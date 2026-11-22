"""Chantier 3, Task 5 (révisé) : le test PUT destructif a été supprimé.

Contrainte absolue du projet : le scanner ne doit JAMAIS écrire sur la cible,
même en mode --aggressive. La détection de PUT/DELETE est désormais purement
passive (en-tête Allow renvoyé par OPTIONS), voir test_server_put_passive.py
pour la couverture du nouveau comportement. Ce fichier vérifie que le flag
`aggressive` ne réactive PAS l'ancienne écriture active."""
import responses
from wp_security_forsure.scanner.checks.server_security import ServerSecurityCheck
from tests.conftest import make_check

BODY = "<html>home</html>"
PUT_TEST = "https://cible.test/security_audit_put_test.txt"


def _register_common():
    url = "https://cible.test/"
    responses.add(responses.GET, url, body=BODY, status=200)
    responses.add(responses.OPTIONS, url, status=200)
    for m in ("TRACE", "CONNECT"):
        responses.add(m, url, body=BODY, status=200)  # réponse ≈ home


def _put_writes():
    return [c for c in responses.calls
            if c.request.method == "PUT" and "security_audit_put_test" in c.request.url]


@responses.activate(assert_all_requests_are_fired=False)
def test_no_put_write_without_aggressive():
    _register_common()
    responses.add("PUT", PUT_TEST, status=201)  # ne DOIT pas être appelé
    chk = make_check(ServerSecurityCheck)  # aggressive non défini
    chk._check_http_methods()
    assert _put_writes() == []
    assert not any("upload possible" in f["message"] for f in chk._result.findings)


@responses.activate(assert_all_requests_are_fired=False)
def test_no_put_write_even_with_aggressive():
    """Contrainte absolue : `aggressive=True` ne doit JAMAIS réactiver
    l'écriture active, ce code path a été supprimé définitivement."""
    _register_common()
    responses.add("PUT", PUT_TEST, status=201)  # ne DOIT jamais être appelé
    responses.add(responses.GET, PUT_TEST, body="SECURITY_AUDIT_TEST", status=200)
    chk = make_check(ServerSecurityCheck, config={"aggressive": True})
    chk._check_http_methods()
    assert _put_writes() == []
    assert not any("upload possible" in f["message"] for f in chk._result.findings)

    # Aucune requête PUT ou DELETE, quelle qu'elle soit, n'a été envoyée.
    methods_called = {c.request.method for c in responses.calls}
    assert "PUT" not in methods_called, methods_called
    assert "DELETE" not in methods_called, methods_called
