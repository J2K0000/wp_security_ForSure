"""Chantier 3, Task 4 : sonde de joignabilité fail-fast avant les checks."""
import requests
from wp_security_forsure.scanner.engine import ScanEngine, CHECK_REGISTRY
from wp_security_forsure.scanner.checks.base import BaseCheck


class _Marker(BaseCheck):
    name = "c3_marker"; title = "m"; description = "d"; severity = "INFO"
    def run(self):
        self.context["ran"] = True
        return self._result


def _boom(*a, **k):
    raise requests.exceptions.ConnectionError("no route to host")


def test_unreachable_target_short_circuits(monkeypatch):
    monkeypatch.setitem(CHECK_REGISTRY, "c3_marker", _Marker)
    eng = ScanEngine("https://down.test", {"timeout": 2, "checks": ["c3_marker"]})
    monkeypatch.setattr(eng.session, "get", _boom)
    results = eng.run_all()
    assert len(results) == 1
    assert results[0].check_name == "reachability"
    assert results[0].severity == "HIGH"
    assert "ran" not in eng.context  # aucun check exécuté


def test_reachable_target_populates_context_and_runs(monkeypatch):
    monkeypatch.setitem(CHECK_REGISTRY, "c3_marker", _Marker)
    eng = ScanEngine("https://up.test", {"timeout": 2, "checks": ["c3_marker"]})
    resp = requests.Response()
    resp.status_code = 200
    monkeypatch.setattr(eng.session, "get", lambda *a, **k: resp)
    eng.run_all()
    assert eng.context.get("ran") is True
    assert eng.context.get("probe_response") is resp


def test_skip_reachability_bypasses_probe(monkeypatch):
    monkeypatch.setitem(CHECK_REGISTRY, "c3_marker", _Marker)
    eng = ScanEngine("https://down.test",
                     {"timeout": 2, "checks": ["c3_marker"], "skip_reachability": True})
    monkeypatch.setattr(eng.session, "get", _boom)
    eng.run_all()
    # sonde ignorée -> le check tourne (il ne fait pas d'HTTP)
    assert eng.context.get("ran") is True
