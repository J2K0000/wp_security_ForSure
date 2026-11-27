"""Cadence, coupures et blocage des requêtes vers la cible (TargetGuard).

Leçon du premier audit réel : lancé à pleine vitesse sur un hébergement
mutualisé, l'audit --authorized a fait bannir l'adresse de l'auditeur 1 min 40 s
après le début des chemins devinés, puis a continué (346 requêtes de plus, dont
345 refusées ou coupées) en annonçant « audit complet ». Ces tests verrouillent l'inverse : délai entre les requêtes, arrêt
au premier signe de blocage, audit déclaré incomplet.
"""
import pytest
import requests
import responses

from tests.conftest import make_check
from wp_security_forsure.__main__ import exit_code_for
from wp_security_forsure.scanner import access_tiers, engine as engine_mod
from wp_security_forsure.scanner.checks import base
from wp_security_forsure.scanner.checks.base import BaseCheck, TargetBlocked
from wp_security_forsure.scanner.checks.fingerprint import FingerprintCheck
from wp_security_forsure.scanner.checks.forms_upload import FormsUploadCheck
from wp_security_forsure.scanner.status import STATUS_ERROR, STATUS_SKIPPED, audit_is_complete

T = "https://cible.test"
OVH_PAGE = ("<html><head><title>Your IP has been banned - OVHcloud</title></head>"
            "<body>Request blocked due to suspicious activity.</body></html>")


class _Probe(BaseCheck):
    name = "probe"
    title = "Sonde de test"

    def run(self):
        return self._result


def _probe(**config):
    return make_check(_Probe, config=config)


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(base, "_monotonic", lambda: now[0])
    return now


# ── Cadence ──────────────────────────────────────────────────────────────

@responses.activate
def test_requests_to_target_are_spaced_by_request_delay(_sans_attente, clock):
    for path in ("robots.txt", "readme.html"):
        responses.add(responses.GET, f"{T}/{path}", body="ok")
    chk = _probe(request_delay=1.0, unlinked_request_delay=2.0)
    chk.http_get("robots.txt")
    chk.http_get("readme.html")
    assert _sans_attente == [1.0]


@responses.activate
def test_guessed_paths_wait_the_longer_unlinked_delay(_sans_attente, clock):
    for path in ("robots.txt", ".env"):
        responses.add(responses.GET, f"{T}/{path}", status=404)
    chk = _probe(request_delay=1.0, unlinked_request_delay=2.0)
    chk.http_get("robots.txt")
    chk.http_get(".env")
    assert _sans_attente == [2.0]


@responses.activate
def test_third_party_hosts_are_not_paced(_sans_attente, clock):
    responses.add(responses.GET, f"{T}/robots.txt", body="ok")
    responses.add(responses.GET, "https://api.wordpress.org/x", body="{}")
    chk = _probe(request_delay=5.0)
    chk.http_get("robots.txt")
    chk.http_get_url("https://api.wordpress.org/x")
    assert _sans_attente == []


def test_shipped_config_paces_and_detects_blocking():
    import yaml
    from pathlib import Path
    cfg = yaml.safe_load((Path(base.__file__).resolve().parents[2] / "config.yaml")
                         .read_text(encoding="utf-8"))
    assert cfg["request_delay"] >= 1.0
    assert cfg["unlinked_request_delay"] >= cfg["request_delay"]
    assert cfg["block_streak"] > 0 and cfg["connection_retries"] == 1


# ── Blocage reconnu ──────────────────────────────────────────────────────

@pytest.mark.parametrize("kwargs", [
    {"status": 403, "body": OVH_PAGE},
    {"status": 429, "body": "slow down"},
    {"status": 403, "body": "challenge", "headers": {"cf-mitigated": "challenge"}},
])
@responses.activate
def test_block_response_stops_every_later_request(kwargs):
    responses.add(responses.GET, f"{T}/robots.txt", **kwargs)
    chk = _probe()
    with pytest.raises(TargetBlocked):
        chk.http_get("robots.txt")
    with pytest.raises(TargetBlocked):
        chk.http_get("readme.html")
    assert len(responses.calls) == 1  # rien n'est reparti


@responses.activate
def test_streak_of_refusals_then_refused_home_means_blocked():
    for path in ("a.zip", "b.zip", "c.zip"):
        responses.add(responses.HEAD, f"{T}/{path}", status=403)
    responses.add(responses.GET, f"{T}/", status=403, body="Forbidden")
    chk = _probe(block_streak=3)
    base.target_guard(chk.session).home_status = 200
    chk.http_head("a.zip")
    chk.http_head("b.zip")
    with pytest.raises(TargetBlocked) as exc:
        chk.http_head("c.zip")
    assert "HTTP 403" in exc.value.reason and "HTTP 200" in exc.value.reason


@responses.activate
def test_streak_of_refusals_with_healthy_home_continues():
    for path in ("a.zip", "b.zip", "c.zip", "d.zip"):
        responses.add(responses.HEAD, f"{T}/{path}", status=403)
    responses.add(responses.GET, f"{T}/", status=200, body="<html>accueil</html>")
    chk = _probe(block_streak=3)
    base.target_guard(chk.session).home_status = 200
    for path in ("a.zip", "b.zip", "c.zip", "d.zip"):
        assert chk.http_head(path).status_code == 403
    assert base.target_guard(chk.session).blocked is None


# ── Coupures de connexion ────────────────────────────────────────────────

@responses.activate
def test_dropped_connection_is_retried_once():
    url = f"{T}/license.txt"
    responses.add(responses.GET, url, body=requests.exceptions.ConnectionError("reset"))
    responses.add(responses.GET, url, body="GNU GENERAL PUBLIC LICENSE")
    chk = _probe(connection_retries=1)
    assert chk.http_get("license.txt").status_code == 200
    assert base.target_guard(chk.session).lost == {}


@responses.activate
def test_request_lost_after_retry_is_counted_for_its_check():
    url = f"{T}/license.txt"
    for _ in range(2):
        responses.add(responses.GET, url, body=requests.exceptions.ConnectionError("reset"))
    chk = _probe(connection_retries=1)
    with pytest.raises(requests.exceptions.ConnectionError):
        chk.http_get("license.txt")
    assert base.target_guard(chk.session).lost == {"probe": 1}


# ── Moteur : arrêt et audit incomplet ────────────────────────────────────

class _BlockedAtFirstRequest(BaseCheck):
    name = "probe_a"
    title = "Sonde A"

    def run(self):
        self.http_get("robots.txt")
        return self._result


class _NeverRuns(BaseCheck):
    name = "probe_b"
    title = "Sonde B"

    def run(self):
        raise AssertionError("ce check ne doit pas partir après un blocage")


def _engine(monkeypatch):
    monkeypatch.setitem(engine_mod.CHECK_REGISTRY, "probe_a", _BlockedAtFirstRequest)
    monkeypatch.setitem(engine_mod.CHECK_REGISTRY, "probe_b", _NeverRuns)
    return engine_mod.ScanEngine(T, {"timeout": 5, "authorized": False},
                                 ["probe_a", "probe_b"])


@responses.activate
def test_engine_stops_after_block_and_reports_incomplete(monkeypatch):
    responses.add(responses.GET, f"{T}/", body="<html>accueil</html>")
    responses.add(responses.GET, f"{T}/robots.txt", status=403, body=OVH_PAGE)
    results = _engine(monkeypatch).run_all()
    by_name = {r.check_name: r for r in results}
    assert by_name["probe_a"].status == STATUS_ERROR
    assert "Audit interrompu" in by_name["probe_a"].findings[0]["message"]
    assert by_name["probe_b"].status == STATUS_SKIPPED
    assert "audit interrompu" in by_name["probe_b"].skip_reason
    assert not audit_is_complete(results)
    assert exit_code_for(results) == 3
    assert len(responses.calls) == 2


@responses.activate
def test_engine_already_banned_at_home_sends_nothing_else(monkeypatch):
    responses.add(responses.GET, f"{T}/", status=403, body=OVH_PAGE)
    results = _engine(monkeypatch).run_all()
    assert [r.check_name for r in results] == ["reachability"]
    assert results[0].status == STATUS_ERROR
    assert exit_code_for(results) == 3
    assert len(responses.calls) == 1


# ── Passivité : readme.html ne débloque pas install.php ──────────────────

@responses.activate
def test_readme_link_does_not_unlock_core_install_scripts():
    responses.add(responses.GET, f"{T}/readme.html",
                  body='<html><a href="wp-admin/install.php">wp-admin/install.php</a>'
                       '<a href="wp-admin/upgrade.php">upgrade</a></html>',
                  content_type="text/html")
    chk = _probe(authorized=False)
    chk.http_get("readme.html")
    refs = chk.references()
    for script in ("wp-admin/install.php", "wp-admin/upgrade.php",
                   "wp-admin/setup-config.php", "wp-config-sample.php"):
        assert access_tiers.classify("GET", f"{T}/{script}", T, refs) == access_tiers.TIER_UNLINKED
        assert not chk.may_request(script, "HEAD")


# ── Faux positifs du premier audit réel ──────────────────────────────────

@responses.activate
def test_registration_redirected_to_disabled_is_closed():
    responses.add(responses.GET, f"{T}/wp-json/wp/v2/users/register", status=404)
    responses.add(responses.GET, f"{T}/wp-login.php?action=register", status=302,
                  headers={"Location": f"{T}/wp-login.php?registration=disabled"})
    responses.add(responses.GET, f"{T}/wp-login.php?registration=disabled",
                  body='<form name="loginform" id="loginform"><input name="user_login">'
                       "</form>", content_type="text/html")
    chk = make_check(FormsUploadCheck)
    findings = chk._check_registration()
    assert not [f for f in findings if f["severity"] != "INFO"], findings
    assert any("Inscription fermée" in f["message"] for f in findings)


@responses.activate
def test_registration_form_rendered_is_open():
    responses.add(responses.GET, f"{T}/wp-json/wp/v2/users/register", status=404)
    responses.add(responses.GET, f"{T}/wp-login.php?action=register",
                  body='<form name="registerform" id="registerform" '
                       'action="https://cible.test/wp-login.php?action=register">'
                       '<input name="user_login"><input name="user_email"></form>',
                  content_type="text/html")
    chk = make_check(FormsUploadCheck)
    findings = chk._check_registration()
    assert any(f["message"].startswith("Inscription ouverte") and f["severity"] == "MEDIUM"
               for f in findings)


@responses.activate
def test_core_and_mapped_rest_namespaces():
    responses.add(responses.GET, f"{T}/wp-json", json={"namespaces": [
        "oembed/1.0", "wp/v2", "wp-site-health/v1", "wp-block-editor/v1",
        "wp-abilities/v1", "seopress/v1", "wordfence/v1",
        "wordfence-login-security/v1", "code-snippets/v1"]})
    chk = make_check(FingerprintCheck, config={"authorized": False})
    plugins = []
    chk._detect_via_rest_namespaces(plugins)
    slugs = sorted(p["slug"] for p in plugins)
    assert slugs == ["code-snippets", "wordfence", "wp-seopress"]
