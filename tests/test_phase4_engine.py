"""Phase 4 dans le moteur : ordre des visites, passe de rendu facultative,
libellés des rapports, déclencheur du bloc incident."""
import io
import json
import re

import pytest
import responses

from wp_security_forsure.__main__ import build_parser
from wp_security_forsure.scanner import status as st
from wp_security_forsure.scanner.checks import browser_render
from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.engine import ScanEngine
from wp_security_forsure.scanner.render import RenderUnavailable
from wp_security_forsure.scanner.reporters.guidance import is_compromise_indicator
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter
from wp_security_forsure.scanner.reporters.terminal_reporter import TerminalReporter

TARGET = "https://cible.test"
HOME = "<html><body><a href='/2026/05/a/'>a</a></body></html>"


def engine(checks, **cfg):
    config = {"timeout": 5, "authorized": False, "checks": checks}
    config.update(cfg)
    return ScanEngine(TARGET, config)


def serve_all(rsps):
    calls = []

    def cb(req):
        calls.append(req)
        return 200, {"Content-Type": "text/html"}, HOME
    rsps.add_callback(responses.GET, re.compile(r"https://(www\.)?cible\.test/.*"), callback=cb)
    return calls


def test_browser_profile_is_the_very_first_request_of_the_audit():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        calls = serve_all(rsps)
        engine(["fingerprint", "visit_profiles"]).run_all()
    assert calls[0].headers.get("Referer") == "https://www.google.com/"
    assert "Chrome/" in calls[0].headers["User-Agent"]


def test_render_is_skipped_without_the_option_with_its_own_label():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        serve_all(rsps)
        results = engine(["browser_render"], skip_reachability=True).run_all()
    by_name = {r.check_name: r for r in results}
    render = by_name["browser_render"]
    assert st.get_status(render) == st.STATUS_SKIPPED
    assert st.skip_label(render) == browser_render.SKIP_REASON
    data = json.loads(JSONReporter(results, TARGET, {}).generate())
    entry = [r for r in data["results"] if r["check_name"] == "browser_render"][0]
    assert entry["status_label"].startswith("Non réalisé : nécessite --render")
    buf = io.StringIO()
    TerminalReporter(results, TARGET, {}).generate(stream=buf)
    assert "nécessite --render" in " ".join(buf.getvalue().split())
    assert "nécessite --render" in HTMLReporter(results, TARGET, {}).generate()


def test_render_without_playwright_or_sandbox_is_an_error_not_a_pass(monkeypatch):
    def unavailable(self):
        raise RenderUnavailable("Chromium n'a pas pu démarrer avec son bac à sable")
    monkeypatch.setattr(browser_render.Renderer, "__enter__", unavailable)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        serve_all(rsps)
        results = engine(["browser_render"], skip_reachability=True, render=True).run_all()
    render = {r.check_name: r for r in results}["browser_render"]
    assert st.get_status(render) == st.STATUS_ERROR
    assert "bac à sable" in render.findings[0]["message"]


def test_cli_render_flag():
    assert build_parser().parse_args(["audit", TARGET, "--render"]).render is True
    assert build_parser().parse_args(["audit", TARGET]).render is False


@pytest.mark.parametrize("check,severity,confidence,expected", [
    ("visit_profiles", "HIGH", "potential", True),
    ("visit_profiles", "MEDIUM", "potential", False),
    ("client_injection", "CRITICAL", "potential", True),
    ("browser_render", "HIGH", "confirmed", True),
    ("browser_render", "INFO", "confirmed", False),
    ("file_exposure", "CRITICAL", "potential", True),
])
def test_incident_trigger_for_phase4_findings(check, severity, confidence, expected):
    message = ("x" if check != "file_exposure" else
               ".user.ini : auto_prepend_file pointe vers un fichier inconnu, "
               "code injecté possible avant chaque page")
    finding = {"message": message, "severity": severity, "confidence": confidence}
    assert is_compromise_indicator(check, finding) is expected


def test_user_ini_disclosure_alone_does_not_trigger():
    finding = {"message": ".user.ini lisible depuis le Web (divulgation d'information)",
               "severity": "MEDIUM", "confidence": "confirmed"}
    assert is_compromise_indicator("file_exposure", finding) is False


def test_new_checks_are_listed_first_in_the_configuration():
    import yaml
    from pathlib import Path
    cfg = yaml.safe_load((Path(__file__).resolve().parent.parent
                          / "wp_security_forsure" / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["checks"][:3] == ["visit_profiles", "client_injection", "browser_render"]
    assert cfg["render"] is False and cfg["visit_profiles"] is True


def test_direct_call_without_render_never_starts_chromium(monkeypatch):
    """Un appel direct de run() (test de fumée, intégration) sans l'option
    render ne lance pas Chromium et ne fait aucune requête."""
    from tests.conftest import make_check

    def boom(self):
        raise AssertionError("Chromium lancé sans --render")
    monkeypatch.setattr(browser_render.Renderer, "__enter__", boom)
    chk = make_check(browser_render.BrowserRenderCheck)
    result = chk.run()
    assert [f["severity"] for f in result.findings] == ["INFO"]
    assert result.findings[0]["message"] == browser_render.SKIP_REASON
