"""Chantier 3, Task 1 : les lectures HTTP sont bornées par max_response_bytes."""
import responses
from wp_security_forsure.scanner.checks.base import BaseCheck
from tests.conftest import make_check


class _Probe(BaseCheck):
    name = "probe_bounded"
    title = "probe bounded"
    description = "test only"

    def run(self):
        return self._result


@responses.activate
def test_get_truncates_body_to_max_bytes():
    responses.add(responses.GET, "https://cible.test/big",
                  body="A" * 10000, status=200)
    chk = make_check(_Probe, config={"max_response_bytes": 1000})
    resp = chk.http_get("/big")
    assert len(resp.content) == 1000
    # resp.text reste cohérent avec le contenu tronqué
    assert len(resp.text) == 1000


@responses.activate
def test_get_full_body_when_cap_zero():
    responses.add(responses.GET, "https://cible.test/big",
                  body="A" * 10000, status=200)
    chk = make_check(_Probe, config={"max_response_bytes": 0})
    resp = chk.http_get("/big")
    assert len(resp.content) == 10000


@responses.activate
def test_default_cap_leaves_small_body_intact():
    responses.add(responses.GET, "https://cible.test/small",
                  body="hello", status=200)
    chk = make_check(_Probe)  # pas de max_response_bytes -> défaut
    resp = chk.http_get("/small")
    assert resp.content == b"hello"
