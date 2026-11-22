"""Un contrôle qui plante (ou une cible injoignable) n'est jamais présenté
comme conforme : statut explicite « error », affiché « Contrôle non réalisé
(erreur) » dans les trois rapports, et verdict « audit incomplet »."""
import json

import requests

from wp_security_forsure.scanner import status as st
from wp_security_forsure.scanner.checks.base import BaseCheck, CheckResult
from wp_security_forsure.scanner.engine import CHECK_REGISTRY, ScanEngine
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter
from wp_security_forsure.scanner.reporters.terminal_reporter import TerminalReporter

TARGET = "https://cible.test"


class _Boom(BaseCheck):
    name = "status_boom"
    title = "Controle qui plante"
    description = "d"
    severity = "INFO"

    def run(self):
        raise RuntimeError("panne simulée")


class _ReturnsNone(BaseCheck):
    name = "status_none"
    title = "Controle sans resultat"
    description = "d"
    severity = "INFO"

    def run(self):
        return None


class _Fine(BaseCheck):
    name = "status_fine"
    title = "Controle sain"
    description = "d"
    severity = "INFO"

    def run(self):
        return self._result


def _run(monkeypatch, names):
    for cls in (_Boom, _ReturnsNone, _Fine):
        monkeypatch.setitem(CHECK_REGISTRY, cls.name, cls)
    eng = ScanEngine(TARGET, {"timeout": 5, "skip_reachability": True},
                     checks_list=names)
    return eng.run_all()


def _conformes_list(html_out):
    start = html_out.index("<strong>Contrôles conformes</strong>")
    return html_out[start:html_out.index("</ul>", start)]


def test_engine_marks_crashed_check_as_error(monkeypatch):
    results = _run(monkeypatch, ["status_fine", "status_boom"])
    by_name = {r.check_name: r for r in results}
    assert st.get_status(by_name["status_boom"]) == st.STATUS_ERROR
    assert st.get_status(by_name["status_fine"]) == st.STATUS_OK
    assert not st.audit_is_complete(results)


def test_check_returning_no_result_is_an_error(monkeypatch):
    results = _run(monkeypatch, ["status_none"])
    assert len(results) == 1
    assert isinstance(results[0], CheckResult)
    assert st.get_status(results[0]) == st.STATUS_ERROR


def test_unreachable_target_is_an_error(monkeypatch):
    eng = ScanEngine("https://down.test", {"timeout": 2})

    def _down(*a, **k):
        raise requests.exceptions.ConnectionError("no route to host")

    monkeypatch.setattr(eng.session, "get", _down)
    results = eng.run_all()
    assert st.get_status(results[0]) == st.STATUS_ERROR
    assert not st.audit_is_complete(results)


def test_complete_audit_is_complete(monkeypatch):
    results = _run(monkeypatch, ["status_fine"])
    assert st.audit_is_complete(results)


def test_html_error_is_not_conforme_and_verdict_is_incomplete(monkeypatch):
    results = _run(monkeypatch, ["status_fine", "status_boom"])
    out = HTMLReporter(results, TARGET, {}).generate()
    assert "Contrôle non réalisé (erreur)" in out
    assert "Maîtrisé" not in out
    assert "audit incomplet" in out.lower()
    conformes = _conformes_list(out)
    assert "Controle qui plante" not in conformes
    assert "Controle sain" in conformes


def _down(*a, **k):
    raise requests.exceptions.ConnectionError("down")


def test_html_unreachable_target_is_incomplete_not_high_risk(monkeypatch):
    eng = ScanEngine("https://down.test", {"timeout": 2})
    monkeypatch.setattr(eng.session, "get", _down)
    results = eng.run_all()
    out = HTMLReporter(results, "https://down.test", {}).generate()
    assert "Niveau de risque : Élevé" not in out
    assert "Maîtrisé" not in out
    assert "audit incomplet" in out.lower()


def test_html_complete_audit_keeps_favourable_verdict(monkeypatch):
    results = _run(monkeypatch, ["status_fine"])
    out = HTMLReporter(results, TARGET, {}).generate()
    assert "Niveau de risque : Maîtrisé" in out
    assert "Contrôle non réalisé (erreur)" not in out


def test_html_critical_with_error_still_says_incomplete(monkeypatch):
    results = _run(monkeypatch, ["status_boom"])
    crit = CheckResult("x", "Faille", "d", "INFO", True)
    crit.add_finding("Fichier exposé", severity="CRITICAL")
    st.set_status(crit, st.STATUS_OK)
    out = HTMLReporter(results + [crit], TARGET, {}).generate()
    assert "Niveau de risque : Critique" in out
    assert "audit incomplet" in out.lower()


def test_json_carries_status_and_incomplete_audit(monkeypatch):
    results = _run(monkeypatch, ["status_fine", "status_boom"])
    data = json.loads(JSONReporter(results, TARGET, {}).generate())
    by_name = {r["check_name"]: r for r in data["results"]}
    assert by_name["status_boom"]["status"] == "error"
    assert by_name["status_boom"]["status_label"] == "Contrôle non réalisé (erreur)"
    assert by_name["status_fine"]["status"] == "ok"
    assert data["summary"]["errors"] == 1
    assert data["summary"]["audit_status"] == "incomplet"
    # l'erreur n'est comptée ni comme contrôle conforme, ni comme constat
    assert data["summary"]["passed"] == 1
    assert data["summary"]["findings"] == 0


def test_json_complete_audit(monkeypatch):
    results = _run(monkeypatch, ["status_fine"])
    data = json.loads(JSONReporter(results, TARGET, {}).generate())
    assert data["summary"]["audit_status"] == "complet"
    assert data["summary"]["errors"] == 0


def test_terminal_shows_error_and_incomplete(monkeypatch, capsys):
    results = _run(monkeypatch, ["status_fine", "status_boom"])
    TerminalReporter(results, TARGET, {}).generate()
    out = capsys.readouterr().out
    assert "Contrôle non réalisé (erreur)" in out
    assert "audit incomplet" in out.lower()
