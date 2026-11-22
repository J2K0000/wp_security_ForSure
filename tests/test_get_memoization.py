"""Chantier 3, Task 2 : les GET idempotents sont mémoïsés au niveau session."""
import requests
import responses
from wp_security_forsure.scanner.checks.base import BaseCheck
from tests.conftest import make_check


class _Probe(BaseCheck):
    name = "probe_memo"
    title = "probe memo"
    description = "test only"

    def run(self):
        return self._result


@responses.activate
def test_same_url_fetched_once():
    responses.add(responses.GET, "https://cible.test/x", body="ok", status=200)
    chk = make_check(_Probe)
    r1 = chk.http_get("/x")
    r2 = chk.http_get("/x")
    assert len(responses.calls) == 1
    # la réponse cachée reste lisible
    assert r1.content == b"ok" and r2.content == b"ok"


@responses.activate
def test_no_cache_bypasses():
    responses.add(responses.GET, "https://cible.test/x", body="ok", status=200)
    chk = make_check(_Probe)
    chk.http_get("/x")
    chk.http_get("/x", no_cache=True)
    assert len(responses.calls) == 2


@responses.activate
def test_different_urls_hit_network_each():
    responses.add(responses.GET, "https://cible.test/a", body="a", status=200)
    responses.add(responses.GET, "https://cible.test/b", body="b", status=200)
    chk = make_check(_Probe)
    chk.http_get("/a")
    chk.http_get("/b")
    assert len(responses.calls) == 2


@responses.activate
def test_post_is_refused_not_sent():
    """Lecture seule : il n'existe plus de helper POST, et une requête POST
    explicite est refusée avant d'atteindre le réseau."""
    import pytest
    from wp_security_forsure.scanner.checks.base import PassivityViolation

    responses.add(responses.POST, "https://cible.test/p", body="p", status=200)
    chk = make_check(_Probe)
    assert not hasattr(chk, "http_post")
    with pytest.raises(PassivityViolation):
        chk.http_request("POST", "/p")
    assert len(responses.calls) == 0


@responses.activate
def test_cache_shared_across_checks_on_same_session():
    responses.add(responses.GET, "https://cible.test/x", body="ok", status=200)
    session = requests.Session()
    session.verify = False
    cfg = {"timeout": 5, "authorized": True}  # /x : chemin deviné (niveau 2)
    c1 = _Probe("https://cible.test", cfg, session)
    c2 = _Probe("https://cible.test", cfg, session)
    c1.http_get("/x")
    c2.http_get("/x")
    assert len(responses.calls) == 1
