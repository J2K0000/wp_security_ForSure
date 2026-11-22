"""Résiduel, dédup inter-checks : deux checks qui émettent le même finding
(message + URL identiques) ne doivent apparaître qu'une fois."""
from wp_security_forsure.scanner.engine import ScanEngine, CHECK_REGISTRY
from wp_security_forsure.scanner.checks.base import BaseCheck


class _HstsA(BaseCheck):
    name = "dd_a"; title = "A"; description = "d"; severity = "INFO"
    def run(self):
        self._result.add_finding(
            message="HSTS (Strict-Transport-Security) header is MISSING",
            severity="HIGH", url="https://cible.test/")
        return self._result


class _HstsB(BaseCheck):
    name = "dd_b"; title = "B"; description = "d"; severity = "INFO"
    def run(self):
        # URL avec slash final : doit quand même être dédupliquée vs _HstsA (sans).
        self._result.add_finding(
            message="HSTS (Strict-Transport-Security) header is MISSING",
            severity="HIGH", url="https://cible.test")
        self._result.add_finding(
            message="Un autre finding distinct", severity="MEDIUM",
            url="https://cible.test/x")
        return self._result


def test_identical_findings_deduped_across_checks(monkeypatch):
    monkeypatch.setitem(CHECK_REGISTRY, "dd_a", _HstsA)
    monkeypatch.setitem(CHECK_REGISTRY, "dd_b", _HstsB)
    eng = ScanEngine("https://cible.test",
                     {"timeout": 5, "skip_reachability": True},
                     checks_list=["dd_a", "dd_b"])
    results = eng.run_all()
    hsts = [f for r in results for f in r.findings
            if "HSTS" in f["message"]]
    assert len(hsts) == 1  # dédupliqué
    # le finding distinct reste présent
    assert any(f["message"] == "Un autre finding distinct"
               for r in results for f in r.findings)
