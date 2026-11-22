"""Mode --authorized et niveaux d'accès côté moteur, rapports et CLI.

- Un check de niveau 2 n'est pas lancé sans --authorized : statut « skipped »,
  affiché « Non réalisé : nécessite --authorized (recherche de chemins non
  liés) » dans les trois rapports, ni échec ni conformité, sans effet sur le
  code de sortie.
- Une requête de niveau 2 non rattrapée donne au check le statut « error »
  (« requête de niveau 2 sans --authorized »), même derrière un
  « except Exception » ; une requête interdite à tout niveau aussi.
- L'option CLI --authorized, son aide en français, l'avertissement en tête du
  rapport terminal et la mention du niveau d'accès dans les trois rapports.
"""
import io
import json
import re

import pytest
import responses

from wp_security_forsure import __main__ as cli
from wp_security_forsure.scanner import status as st
from wp_security_forsure.scanner.access_tiers import AUTHORIZED_WARNING, SKIPPED_LABEL
from wp_security_forsure.scanner.checks.base import BaseCheck, CheckResult
from wp_security_forsure.scanner.engine import CHECK_REGISTRY, ScanEngine
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter
from wp_security_forsure.scanner.reporters.terminal_reporter import TerminalReporter

TARGET = "https://cible.test"


class _Guesser(BaseCheck):
    name = "tier_guesser"
    title = "Recherche de sauvegardes devinées"
    description = "d"
    access_tier = 2

    def run(self):
        self.http_head("backup.sql")
        return self._result


class _Misclassified(BaseCheck):
    name = "tier_misclassified"
    title = "Check mal classé"
    description = "d"
    access_tier = 1

    def run(self):
        try:
            self.http_head(".env")
        except Exception:
            pass  # un check négligent conclurait « non exposé »
        return self._result


class _Executor(BaseCheck):
    name = "tier_executor"
    title = "Check qui demande wp-cron.php"
    description = "d"
    access_tier = 1

    def run(self):
        self.http_head("wp-cron.php")
        return self._result


class _Public(BaseCheck):
    name = "tier_public"
    title = "Contrôle public"
    description = "d"
    access_tier = 1

    def run(self):
        self.http_get("robots.txt")
        return self._result


def _catch_all():
    for method in ("GET", "HEAD", "OPTIONS"):
        responses.add(method, re.compile(r".*"), body="ok", status=200)


def _run(monkeypatch, names, authorized=False):
    for cls in (_Guesser, _Misclassified, _Executor, _Public):
        monkeypatch.setitem(CHECK_REGISTRY, cls.name, cls)
    cfg = {"timeout": 5, "skip_reachability": True, "authorized": authorized}
    return ScanEngine(TARGET, cfg, checks_list=names).run_all()


def _by_name(results):
    return {r.check_name: r for r in results}


# ── Moteur ───────────────────────────────────────────────────────────────

@responses.activate
def test_level_2_check_is_skipped_without_authorized(monkeypatch):
    _catch_all()
    results = _by_name(_run(monkeypatch, ["tier_public", "tier_guesser"]))
    assert st.get_status(results["tier_guesser"]) == st.STATUS_SKIPPED
    assert st.STATUS_LABELS[st.STATUS_SKIPPED] == SKIPPED_LABEL
    assert SKIPPED_LABEL == ("Non réalisé : nécessite --authorized (recherche "
                             "de chemins non liés)")
    assert not any("backup.sql" in c.request.url for c in responses.calls)
    assert st.get_status(results["tier_public"]) == st.STATUS_OK


@responses.activate
def test_level_2_check_runs_with_authorized(monkeypatch):
    _catch_all()
    results = _by_name(_run(monkeypatch, ["tier_guesser"], authorized=True))
    assert st.get_status(results["tier_guesser"]) == st.STATUS_OK
    assert any("backup.sql" in c.request.url for c in responses.calls)


@responses.activate
def test_uncaught_level_2_request_is_an_error_even_behind_except_exception(monkeypatch):
    _catch_all()
    result = _run(monkeypatch, ["tier_misclassified"])[0]
    assert st.get_status(result) == st.STATUS_ERROR
    assert result.findings[0]["message"] == "requête de niveau 2 sans --authorized"
    assert ".env" in result.findings[0]["evidence"]
    assert len(responses.calls) == 0


@responses.activate
@pytest.mark.parametrize("authorized", [False, True])
def test_forbidden_request_is_an_error_in_both_modes(monkeypatch, authorized):
    _catch_all()
    result = _run(monkeypatch, ["tier_executor"], authorized=authorized)[0]
    assert st.get_status(result) == st.STATUS_ERROR
    assert "interdite à tout niveau" in result.findings[0]["message"]
    assert len(responses.calls) == 0


def test_skipped_is_neither_failure_nor_compliance_and_keeps_exit_code():
    def res(name, status=st.STATUS_OK, severity=None):
        r = CheckResult(name, f"Titre {name}", "d", "INFO", True)
        if severity:
            r.add_finding("constat", severity=severity)
        return st.set_status(r, status)

    skipped = res("s", st.STATUS_SKIPPED)
    assert [r.check_name for r in st.ok_results([res("a"), skipped])] == ["a"]
    assert st.error_results([skipped]) == []
    assert st.audit_is_complete([res("a"), skipped])
    assert cli.exit_code_for([res("a"), skipped]) == cli.exit_code_for([res("a")]) == 0
    assert cli.exit_code_for([res("a", severity="CRITICAL"), skipped]) == 1
    assert cli.exit_code_for([skipped]) == cli.exit_code_for([]) == 3


# ── Rapports : statut skipped ───────────────────────────────────────────

@pytest.fixture
def mixed_results(monkeypatch):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for method in ("GET", "HEAD"):
            rsps.add(method, re.compile(r".*"), body="ok", status=200)
        return _run(monkeypatch, ["tier_public", "tier_guesser"])


def test_terminal_report_shows_skipped_label(mixed_results):
    raw = TerminalReporter(mixed_results, TARGET, {}).generate(stream=io.StringIO())
    out = " ".join(raw.split())  # Rich replie les lignes longues
    assert SKIPPED_LABEL in out
    assert "[NON RÉALISÉ] Recherche de sauvegardes devinées" in out
    assert "1 checks OK" in out
    assert "Checks exécutés : 1" in out
    assert "Audit complet" in out


def test_json_report_shows_skipped_status(mixed_results):
    data = json.loads(JSONReporter(mixed_results, TARGET, {}).generate())
    entry = next(r for r in data["results"] if r["check_name"] == "tier_guesser")
    assert entry["status"] == "skipped"
    assert entry["status_label"] == SKIPPED_LABEL
    assert entry["passed"] is None
    assert data["summary"]["skipped"] == 1
    assert data["summary"]["passed"] == 1
    assert data["summary"]["errors"] == 0
    assert data["summary"]["audit_status"] == "complet"


def test_html_report_shows_skipped_label_outside_conformes(mixed_results):
    out = HTMLReporter(mixed_results, TARGET, {}).generate()
    assert SKIPPED_LABEL in out
    start = out.index("<strong>Contrôles conformes</strong>")
    conformes = out[start:out.index("</ul>", start)]
    assert "Contrôle public" in conformes
    assert "Recherche de sauvegardes devinées" not in conformes
    assert "Maîtrisé" in out


# ── Rapports : niveau d'accès et avertissement ──────────────────────────

@pytest.mark.parametrize("authorized", [False, True])
def test_reports_mention_access_level(mixed_results, authorized):
    cfg = {"authorized": authorized}
    term = TerminalReporter(mixed_results, TARGET, cfg).generate(stream=io.StringIO())
    data = json.loads(JSONReporter(mixed_results, TARGET, cfg).generate())
    page = HTMLReporter(mixed_results, TARGET, cfg).generate()
    level = data["scan"]["access_level"]
    assert level["authorized"] is authorized
    assert level["max_tier"] == (2 if authorized else 1)
    assert "Niveau d'accès" in term and "Niveau d'accès" in page
    needle = "Niveaux 0, 1 et 2" if authorized else "Niveaux 0 et 1"
    assert needle in level["label"] and needle in page
    assert needle in " ".join(term.split())
    warning_shown = "AVERTISSEMENT" in term
    assert warning_shown is authorized
    assert ("Mode --authorized actif" in page) is authorized
    assert (AUTHORIZED_WARNING[:30] in " ".join(term.split())) is authorized


def test_terminal_warning_comes_first_when_authorized(mixed_results):
    term = TerminalReporter(mixed_results, TARGET, {"authorized": True}).generate(
        stream=io.StringIO())
    assert term.index("AVERTISSEMENT") < term.index("RAPPORT D'AUDIT")


# ── CLI ──────────────────────────────────────────────────────────────────

def test_cli_authorized_option_defaults_to_false():
    parser = cli.build_parser()
    assert parser.parse_args(["audit", TARGET]).authorized is False
    assert parser.parse_args(["audit", TARGET, "--authorized"]).authorized is True
    assert cli.load_config()["authorized"] is False


def test_cli_authorized_help_is_french_and_explicit():
    text = " ".join(cli.build_parser().format_help().split())
    assert "--authorized" in text
    assert "autorisation écrite du propriétaire" in text
    assert "recherche de chemins non liés (niveau 2" in text
    assert "reste en lecture seule" in text


@pytest.mark.parametrize("argv, expected", [
    ([], False), (["--authorized"], True)])
def test_cli_passes_authorized_to_engine_and_reports(monkeypatch, capsys, argv, expected):
    seen = {}

    def fake_run_all(self):
        seen["authorized"] = self.config.get("authorized")
        return [st.set_status(CheckResult("c", "Titre", "d", "INFO", True), st.STATUS_OK)]

    monkeypatch.setattr(ScanEngine, "run_all", fake_run_all)
    assert cli.main(["audit", TARGET, "--format", "json", *argv]) == 0
    assert seen["authorized"] is expected
    data = json.loads(capsys.readouterr().out.strip())
    assert data["scan"]["access_level"]["authorized"] is expected


# ── Déclaration du niveau par chaque check ──────────────────────────────

def test_every_check_declares_its_access_tier():
    real = {n: c for n, c in CHECK_REGISTRY.items()
            if c.__module__.startswith("wp_security_forsure.scanner.checks.")}
    assert len(real) >= 20
    for name, cls in real.items():
        assert "access_tier" in cls.__dict__, name
        assert cls.access_tier in (0, 1, 2), name
    assert {n for n, c in real.items() if c.access_tier == 2} == {"nulled_plugins"}
