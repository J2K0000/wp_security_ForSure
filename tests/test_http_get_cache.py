"""BaseCheck.http_get, clé de cache et contournement via headers/method.

Le cache mémoïse les GET par URL pour éviter les appels réseau redondants
(plusieurs checks lisant la même page). Mais certains checks envoient des
requêtes DIFFÉRENTES vers la MÊME URL (en-têtes personnalisés, méthode HTTP
différente) et doivent obtenir une réponse fraîche à chaque fois, pas la
réponse mise en cache de la toute première requête GET simple.
"""
import responses

from wp_security_forsure.scanner.checks.base import BaseCheck
from tests.conftest import make_check

TARGET = "https://cible.test"
HOME = f"{TARGET}/"


class _DummyCheck(BaseCheck):
    name = "dummy"
    title = "Dummy"
    description = "d"

    def run(self):
        return self._result


def _mk():
    return make_check(_DummyCheck, target=TARGET)


@responses.activate
def test_plain_get_same_url_is_cached_one_network_call():
    """Deux http_get('/') sans kwargs -> un seul appel réseau (cache actif)."""
    responses.add(responses.GET, HOME, body="hello", status=200)

    chk = _mk()
    r1 = chk.http_get("/")
    r2 = chk.http_get("/")

    assert r1.text == "hello"
    assert r2.text == "hello"
    assert len(responses.calls) == 1


@responses.activate
def test_get_with_different_headers_same_url_not_cached():
    """Deux http_get('/') avec des headers= différents -> deux appels réseau."""
    responses.add(responses.GET, HOME, status=200, body="baseline")
    responses.add(responses.GET, HOME, status=406, body="blocked")

    chk = _mk()
    r1 = chk.http_get("/")
    r2 = chk.http_get("/", headers={"Accept": "invalid-mime-type"})

    assert len(responses.calls) == 2
    assert r1.status_code == 200
    assert r2.status_code == 406


@responses.activate
def test_get_with_method_kwarg_not_cached():
    """Un http_get(..., method=...) ne doit pas être servi par / polluer le cache GET."""
    responses.add(responses.GET, HOME, status=200, body="baseline")
    responses.add(responses.GET, HOME, status=200, body="second")

    chk = _mk()
    r1 = chk.http_get("/")
    r2 = chk.http_get("/", no_cache=True)

    assert len(responses.calls) == 2
    assert r1.text == "baseline"
    assert r2.text == "second"


@responses.activate
def test_http_request_helper_refuses_trace():
    """http_request(method, path) n'accepte que GET, HEAD et OPTIONS : TRACE
    lève PassivityViolation et rien ne part sur le réseau."""
    import pytest
    from wp_security_forsure.scanner.checks.base import PassivityViolation

    responses.add("TRACE", HOME, status=405)

    chk = _mk()
    with pytest.raises(PassivityViolation):
        chk.http_request("TRACE", "/")
    assert len(responses.calls) == 0


@responses.activate
def test_http_request_helper_sends_options():
    responses.add(responses.OPTIONS, HOME, status=200, headers={"Allow": "GET"})

    chk = _mk()
    resp = chk.http_request("OPTIONS", "/")

    assert resp.status_code == 200
    assert [c.request.method for c in responses.calls] == ["OPTIONS"]
