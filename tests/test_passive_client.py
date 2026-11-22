"""Client HTTP passif de BaseCheck : garde de méthode, garde SSRF,
redirections bornées dans le périmètre, budget de requêtes.

Tout est simulé (`responses` pour HTTP, faux `socket.getaddrinfo` pour DNS).
"""
import re
import socket

import pytest
import requests
import responses

from wp_security_forsure.scanner.checks import base as base_mod
from wp_security_forsure.scanner.checks.base import (
    BaseCheck,
    PassivityViolation,
    RequestBudgetExceeded,
    SSRFBlocked,
)
from tests.conftest import FAKE_PUBLIC_IP, make_check

TARGET = "https://cible.test"


class _Probe(BaseCheck):
    name = "probe_passive"
    title = "probe"
    description = "test only"

    def run(self):
        return self._result


def _catch_all():
    """Répond 200 à toute requête, quelle que soit la méthode (pour prouver
    qu'aucune requête refusée n'atteint la couche HTTP)."""
    for method in ("GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH",
                   "TRACE", "CONNECT"):
        responses.add(method, re.compile(r".*"), body="ok", status=200)


def _dns(mapping):
    """Faux résolveur : `mapping` nom -> IP, IP littérale -> elle-même,
    autre nom -> adresse publique."""
    def fake(host, port=None, *args, **kwargs):
        name = str(host)
        try:
            addr = str(base_mod.ipaddress.ip_address(name))
        except ValueError:
            addr = mapping.get(name, FAKE_PUBLIC_IP)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                 (addr, port or 0))]
    return fake


# ── Garde de méthode ────────────────────────────────────────────────────

@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH",
                                    "TRACE", "CONNECT", "post", "PROPFIND"])
@responses.activate
def test_http_request_refuses_non_read_methods(method):
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(PassivityViolation):
        chk.http_request(method, "/")
    assert len(responses.calls) == 0


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH",
                                    "TRACE", "CONNECT"])
@responses.activate
def test_session_bypass_is_refused_too(method):
    """Même un appel direct sur la session (hors helpers) est refusé par
    l'adaptateur monté par BaseCheck."""
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(PassivityViolation):
        chk.session.request(method, f"{TARGET}/")
    assert len(responses.calls) == 0


def test_http_post_helper_no_longer_exists():
    assert not hasattr(BaseCheck, "http_post")


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
@responses.activate
def test_read_methods_are_allowed(method):
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    resp = chk.http_request(method, "/")
    assert resp.status_code == 200
    assert [c.request.method for c in responses.calls] == [method]


def test_passivity_violation_is_not_a_network_error():
    """Une violation ne doit pas être avalée comme une simple erreur réseau."""
    assert not issubclass(PassivityViolation, requests.RequestException)


# ── Garde SSRF ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://10.0.0.5/x.js",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:3306/",
    "http://[::1]/",
    "http://[::ffff:10.0.0.5]/",
    "http://0.0.0.0/",
    "http://192.168.1.1/",
    "http://224.0.0.1/",
    "http://100.64.0.1/",
])
@responses.activate
def test_literal_private_ip_is_refused(url):
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(SSRFBlocked):
        chk.http_get_url(url)
    assert len(responses.calls) == 0


@pytest.mark.parametrize("ip", ["10.1.2.3", "169.254.169.254", "127.0.0.1",
                                "172.16.0.9"])
@responses.activate
def test_name_resolving_to_private_range_is_refused(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"interne.piege.test": ip}))
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(SSRFBlocked):
        chk.http_get_url("https://interne.piege.test/")
    assert len(responses.calls) == 0


@responses.activate
def test_target_itself_is_guarded(monkeypatch):
    """La garde s'applique aussi à la cible : un nom de cible qui résout vers
    une adresse interne n'est pas contacté."""
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"cible.test": "10.0.0.8"}))
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(SSRFBlocked):
        chk.http_get("/")
    with pytest.raises(SSRFBlocked):
        chk.http_head("/")
    assert len(responses.calls) == 0


@responses.activate
def test_unresolvable_host_is_refused(monkeypatch):
    def nxdomain(*args, **kwargs):
        raise socket.gaierror("NXDOMAIN")
    monkeypatch.setattr(socket, "getaddrinfo", nxdomain)
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(SSRFBlocked):
        chk.http_get_url("https://absent.tiers.test/")
    assert len(responses.calls) == 0


@responses.activate
def test_session_bypass_to_private_ip_is_refused():
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(SSRFBlocked):
        chk.session.get("http://169.254.169.254/latest/meta-data/")
    assert len(responses.calls) == 0


@responses.activate
def test_public_third_party_host_is_allowed():
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    assert chk.http_get_url("https://cdn.tiers.test/lib.js").status_code == 200
    assert len(responses.calls) == 1


def test_ssrf_blocked_is_a_connection_error():
    """Les checks traitent un refus SSRF comme un hôte injoignable."""
    assert issubclass(SSRFBlocked, requests.exceptions.ConnectionError)


# ── Redirections ────────────────────────────────────────────────────────

@responses.activate
def test_redirect_to_third_party_host_is_not_followed():
    responses.add(responses.GET, f"{TARGET}/feed/", status=301,
                  headers={"Location": "https://evil.tiers.test/feed"})
    responses.add(responses.GET, "https://evil.tiers.test/feed", body="tiers")
    chk = make_check(_Probe, target=TARGET)
    resp = chk.http_get("/feed/")
    assert resp.status_code == 301
    assert [c.request.url for c in responses.calls] == [f"{TARGET}/feed/"]


@responses.activate
def test_redirect_to_metadata_ip_is_not_followed():
    responses.add(responses.GET, f"{TARGET}/wp-admin/", status=302,
                  headers={"Location": "http://169.254.169.254/latest/meta-data/"})
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    resp = chk.http_get("/wp-admin/")
    assert resp.status_code == 302
    assert all("169.254" not in c.request.url for c in responses.calls)


@responses.activate
def test_redirect_within_scope_is_followed_with_history():
    responses.add(responses.GET, "http://cible.test/", status=301,
                  headers={"Location": "https://www.cible.test/"})
    responses.add(responses.GET, "https://www.cible.test/", status=302,
                  headers={"Location": "/accueil/"})
    responses.add(responses.GET, "https://www.cible.test/accueil/", body="ok")
    chk = make_check(_Probe, target="http://cible.test")
    resp = chk.http_get("/")
    assert resp.status_code == 200
    assert resp.url == "https://www.cible.test/accueil/"
    assert [r.status_code for r in resp.history] == [301, 302]


@responses.activate
def test_redirect_hop_to_private_address_is_guarded(monkeypatch):
    """Un saut vers un nom DANS le périmètre mais qui résout vers une adresse
    interne est refusé par la garde SSRF appliquée à chaque saut."""
    monkeypatch.setattr(socket, "getaddrinfo",
                        _dns({"www.cible.test": "10.0.0.5"}))
    responses.add(responses.GET, f"{TARGET}/", status=301,
                  headers={"Location": "https://www.cible.test/"})
    _catch_all()
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(SSRFBlocked):
        chk.http_get("/")
    assert [c.request.url for c in responses.calls] == [f"{TARGET}/"]


@responses.activate
def test_redirect_chain_is_capped():
    for i in range(10):
        responses.add(responses.GET, f"{TARGET}/r{i}", status=302,
                      headers={"Location": f"/r{i + 1}"})
    chk = make_check(_Probe, target=TARGET)
    with pytest.raises(requests.exceptions.TooManyRedirects):
        chk.http_get("/r0")
    assert len(responses.calls) == base_mod.MAX_REDIRECTS + 1


@responses.activate
def test_allow_redirects_false_returns_first_response():
    responses.add(responses.GET, f"{TARGET}/a", status=302,
                  headers={"Location": "/b"})
    chk = make_check(_Probe, target=TARGET)
    resp = chk.http_get("/a", allow_redirects=False)
    assert resp.status_code == 302
    assert len(responses.calls) == 1


# ── Budget de requêtes ──────────────────────────────────────────────────

@responses.activate
def test_request_budget_is_enforced_and_shared_by_session():
    _catch_all()
    session = requests.Session()
    # /a, /b... : chemins devinés (niveau 2), d'où authorized.
    cfg = {"timeout": 5, "max_requests": 3, "authorized": True}
    c1 = _Probe(TARGET, cfg, session)
    c2 = _Probe(TARGET, cfg, session)
    c1.http_get("/a")
    c1.http_head("/b")
    c2.http_get("/c")
    with pytest.raises(RequestBudgetExceeded):
        c2.http_get("/d")
    assert len(responses.calls) == 3


@responses.activate
def test_cache_hits_do_not_consume_budget():
    _catch_all()
    chk = make_check(_Probe, target=TARGET, config={"max_requests": 1})
    chk.http_get("/x")
    chk.http_get("/x")
    assert len(responses.calls) == 1


def test_default_budget_is_2000():
    assert base_mod.DEFAULT_MAX_REQUESTS == 2000
