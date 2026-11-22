"""Redesign sécurité : brute_force_login doit être 100 % PASSIF.

Contrainte non négociable du propriétaire du projet : le scanner ne doit
JAMAIS soumettre d'identifiants, JAMAIS flooder de tentatives de connexion,
JAMAIS déclencher de pingback sortant, et n'envoie plus AUCUN POST (pas même
l'introspection XML-RPC system.listMethods). Ces tests prouvent :
  1) qu'un run() complet n'émet que des GET/HEAD ;
  2) que XML-RPC est établi passivement par la réponse d'un GET sur
     xmlrpc.php (« XML-RPC server accepts POST requests only. ») ;
  3) que system.multicall / pingback.ping / wp.getUsersBlogs ne sont plus
     affirmés (non évaluables passivement : un seul constat INFO) ;
  4) que le rate-limiting est détecté par signature passive sur la page de
     login, sans jamais soumettre de connexion.
"""
import re

import responses

from wp_security_forsure.scanner.checks.brute_force_login import BruteForceLoginCheck
from tests.conftest import make_check

BASE = "https://cible.test"
XMLRPC_GET_BODY = "XML-RPC server accepts POST requests only."


def _login_body():
    return "<html><body><form id='loginform'><input name='log'></form></body></html>"


def _xmlrpc_findings(chk):
    return [f for f in chk._result.findings if "xml-rpc" in f["message"].lower()
            or "xmlrpc" in f["message"].lower()]


# ── 1) THE key safety test ──

@responses.activate
def test_full_run_sends_no_post_at_all():
    responses.add(responses.GET, f"{BASE}/wp-login.php", status=200, body=_login_body())
    responses.add(responses.GET, f"{BASE}/xmlrpc.php", status=405,
                  content_type="text/plain", body=XMLRPC_GET_BODY)
    responses.add(responses.POST, re.compile(r".*"), status=200, body="")

    chk = make_check(BruteForceLoginCheck)
    chk.run()

    assert {c.request.method for c in responses.calls} <= {"GET", "HEAD"}
    for c in responses.calls:
        assert not c.request.body, c.request.url


# ── 2) XML-RPC : preuve passive par la signature du GET ──

@responses.activate
def test_xmlrpc_get_signature_flags_xmlrpc_active():
    responses.add(responses.GET, f"{BASE}/xmlrpc.php", status=405,
                  content_type="text/plain", body=XMLRPC_GET_BODY)
    chk = make_check(BruteForceLoginCheck)
    chk._check_xmlrpc_surface()

    active = [f for f in chk._result.findings
              if f["message"] == "XML-RPC activé (xmlrpc.php accessible)"]
    assert len(active) == 1, chk._result.findings
    assert active[0]["severity"] == "HIGH"
    assert "aucun appel XML-RPC" in active[0]["evidence"]
    assert [c.request.method for c in responses.calls] == ["GET"]


@responses.activate
def test_risky_methods_reported_as_not_assessable_info_only():
    """multicall / pingback / getUsersBlogs : un seul constat INFO, jamais
    affirmés en HIGH puisque la liste des méthodes n'est pas lue."""
    responses.add(responses.GET, f"{BASE}/xmlrpc.php", status=405,
                  content_type="text/plain", body=XMLRPC_GET_BODY)
    chk = make_check(BruteForceLoginCheck)
    chk._check_xmlrpc_surface()

    for name in ("multicall", "pingback", "getusersblogs"):
        hits = [f for f in chk._result.findings if name in f["message"].lower()]
        assert len(hits) == 1, (name, chk._result.findings)
        assert hits[0]["severity"] == "INFO"
        assert "non évaluables passivement" in hits[0]["message"]


@responses.activate
def test_no_xmlrpc_finding_when_blocked():
    responses.add(responses.GET, f"{BASE}/xmlrpc.php", status=403, body="Forbidden")
    chk = make_check(BruteForceLoginCheck)
    chk._check_xmlrpc_surface()
    assert _xmlrpc_findings(chk) == []


@responses.activate
def test_xmlrpc_without_signature_is_inconclusive_info():
    responses.add(responses.GET, f"{BASE}/xmlrpc.php", status=200,
                  body="<html>autre chose</html>")
    responses.add(responses.GET, re.compile(r".*wpsf-probe.*"), status=404)
    chk = make_check(BruteForceLoginCheck)
    chk._check_xmlrpc_surface()
    found = _xmlrpc_findings(chk)
    assert len(found) == 1
    assert found[0]["severity"] == "INFO"
    assert "non concluant" in found[0]["message"]


# ── 4) rate limiting, passive signature detection only ─────────────────

@responses.activate
def test_rate_limit_protection_detected_via_wordfence_marker():
    responses.add(
        responses.GET, f"{BASE}/wp-login.php", status=200,
        body="<html><!-- Protected by Wordfence --><form id='loginform'></form></html>",
    )
    chk = make_check(BruteForceLoginCheck)
    chk._check_rate_limiting()

    findings = chk._result.findings
    assert any("protection anti-force-brute détectée" in f["message"].lower() for f in findings), findings
    assert any(f["confidence"] == "confirmed" for f in findings)

    # Absolutely no login attempt was submitted.
    posts = [c for c in responses.calls if c.request.method == "POST"]
    assert posts == []


@responses.activate
def test_rate_limit_no_protection_marker_is_potential_and_no_post():
    responses.add(
        responses.GET, f"{BASE}/wp-login.php", status=200, body=_login_body(),
    )
    chk = make_check(BruteForceLoginCheck)
    chk._check_rate_limiting()

    findings = chk._result.findings
    assert any(
        f["confidence"] == "potential" and "aucune protection anti-force-brute" in f["message"].lower()
        for f in findings
    ), findings

    posts = [c for c in responses.calls if c.request.method == "POST"]
    assert posts == []


@responses.activate
def test_rate_limit_never_sends_repeated_failed_logins():
    """Le comportement actif historique envoyait 5 POST wp-login.php avec des
    mots de passe factices en boucle. Ceci ne doit plus jamais se produire."""
    responses.add(responses.GET, f"{BASE}/wp-login.php", status=200, body=_login_body())
    chk = make_check(BruteForceLoginCheck)
    chk._check_rate_limiting()

    post_calls = [c for c in responses.calls if c.request.method == "POST"]
    assert post_calls == []
