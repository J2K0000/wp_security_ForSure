"""XML-RPC : détection 100 % PASSIVE (wp_features et brute_force_login).

Contrainte non négociable du propriétaire du projet : le scanner ne soumet
JAMAIS d'identifiants, ne déclenche JAMAIS de pingback sortant et n'envoie
plus AUCUN POST vers xmlrpc.php (ni demo.sayHello, ni system.listMethods).

Ces tests prouvent :
  1) qu'aucune requête autre que GET/HEAD n'atteint xmlrpc.php ;
  2) que l'activité du serveur XML-RPC se lit dans la réponse d'un GET
     (« XML-RPC server accepts POST requests only. ») ;
  3) que les anciennes méthodes actives ont disparu ;
  4) que pingback.ping / wp.getUsersBlogs / system.multicall ne sont
     signalés que par brute_force_login (propriétaire unique), en INFO
     « non évaluable passivement », jamais en doublon par wp_features.
"""
import re

import responses

from wp_security_forsure.scanner.checks import signatures
from wp_security_forsure.scanner.checks.brute_force_login import BruteForceLoginCheck
from wp_security_forsure.scanner.checks.wp_features import WPFeaturesCheck
from tests.conftest import make_check

BASE = "https://cible.test"
XMLRPC_URL = f"{BASE}/xmlrpc.php"
XMLRPC_GET_BODY = "XML-RPC server accepts POST requests only."


def _xmlrpc_active():
    responses.add(responses.GET, XMLRPC_URL, status=405,
                  content_type="text/plain", body=XMLRPC_GET_BODY)


# ── 1) Aucune requête d'écriture vers xmlrpc.php ────────────────────────

@responses.activate
def test_full_wp_features_run_never_posts():
    _xmlrpc_active()
    responses.add(responses.GET, re.compile(r".*"), status=404, body="absent")
    responses.add(responses.HEAD, re.compile(r".*"), status=404)
    responses.add(responses.POST, re.compile(r".*"), status=200, body="")

    chk = make_check(WPFeaturesCheck)
    chk.run()

    assert {c.request.method for c in responses.calls} <= {"GET", "HEAD"}
    assert any(c.request.url == XMLRPC_URL for c in responses.calls)


def test_active_xmlrpc_methods_removed():
    for attr in ("_check_xmlrpc_list_methods", "_check_xmlrpc_pingback",
                 "_check_xmlrpc_get_users_blogs", "_check_heartbeat",
                 "_LIST_METHODS_XML", "_PINGBACK_XML", "_GET_USERS_BLOGS_XML",
                 "_safe_post"):
        assert not hasattr(WPFeaturesCheck, attr), attr
    for attr in ("_LIST_METHODS_XML", "_safe_post"):
        assert not hasattr(BruteForceLoginCheck, attr), attr
    assert not hasattr(signatures, "xmlrpc_method_unavailable")


# ── 2) Disponibilité établie par le GET ─────────────────────────────────

@responses.activate
def test_get_signature_means_xmlrpc_fully_accessible():
    _xmlrpc_active()
    chk = make_check(WPFeaturesCheck)
    chk._check_xmlrpc_availability()

    found = [f for f in chk._result.findings
             if f["message"] == "XML-RPC endpoint fully accessible (xmlrpc.php)"]
    assert len(found) == 1, chk._result.findings
    assert found[0]["severity"] == "HIGH"
    assert [c.request.method for c in responses.calls] == ["GET"]


@responses.activate
def test_response_without_signature_is_low_maybe_disabled():
    responses.add(responses.GET, XMLRPC_URL, status=405, body="Method Not Allowed")
    responses.add(responses.GET, re.compile(r".*wpsf-probe.*"), status=404)
    chk = make_check(WPFeaturesCheck)
    chk._check_xmlrpc_availability()

    assert [f["severity"] for f in chk._result.findings] == ["LOW"]
    assert "may be disabled" in chk._result.findings[0]["message"]


@responses.activate
def test_blocked_xmlrpc_yields_no_finding():
    responses.add(responses.GET, XMLRPC_URL, status=403, body="Forbidden")
    chk = make_check(WPFeaturesCheck)
    chk._check_xmlrpc_availability()
    assert chk._result.findings == []


def test_signature_helper():
    assert signatures.xmlrpc_server_active(XMLRPC_GET_BODY)
    assert signatures.xmlrpc_server_active("<p>" + XMLRPC_GET_BODY.upper() + "</p>")
    assert not signatures.xmlrpc_server_active("")
    assert not signatures.xmlrpc_server_active("<html>accueil</html>")


# ── 3) Surface à risque : un seul propriétaire, jamais affirmée ─────────

@responses.activate
def test_risky_methods_reported_once_by_brute_force_login_as_info():
    _xmlrpc_active()
    # Attrape-tout qui exclut xmlrpc.php : sinon `responses` retirerait le mock
    # xmlrpc.php après son premier usage (deux correspondances).
    responses.add(responses.GET, re.compile(r"^(?!.*xmlrpc\.php).*$"),
                  status=404, body="absent")
    responses.add(responses.HEAD, re.compile(r".*"), status=404)

    wpf = make_check(WPFeaturesCheck)
    wpf.run()
    bfl = make_check(BruteForceLoginCheck)
    bfl._check_xmlrpc_surface()

    combined = wpf._result.findings + bfl._result.findings
    for name in ("pingback", "getusersblogs", "multicall"):
        hits = [f for f in combined if name in f["message"].lower()]
        assert len(hits) == 1, (name, combined)
        assert hits[0]["severity"] == "INFO"
    assert not any(name in f["message"].lower()
                   for f in wpf._result.findings
                   for name in ("pingback", "getusersblogs", "multicall"))


@responses.activate
def test_wp_features_reports_listmethods_and_heartbeat_not_assessable():
    responses.add(responses.GET, re.compile(r".*"), status=404, body="absent")
    responses.add(responses.HEAD, re.compile(r".*"), status=404)
    chk = make_check(WPFeaturesCheck)
    chk.run()
    info = [f for f in chk._result.findings
            if "non évaluables passivement" in f["message"]]
    assert len(info) == 1
    assert info[0]["severity"] == "INFO"
    assert "system.listMethods" in info[0]["message"]
    assert "Heartbeat" in info[0]["message"]
