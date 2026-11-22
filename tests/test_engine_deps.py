from wp_security_forsure.scanner.engine import ScanEngine, CHECK_REGISTRY
from wp_security_forsure.scanner.checks.base import BaseCheck, CheckResult


class _A(BaseCheck):
    name = "aaa_producer"
    title = "A"; description = "d"; severity = "INFO"

    def run(self):
        self.context["order"] = self.context.get("order", []) + ["A"]
        self.context["produced"] = True
        return self._result


class _B(BaseCheck):
    name = "bbb_consumer"
    title = "B"; description = "d"; severity = "INFO"
    depends_on = ["aaa_producer"]

    def run(self):
        assert self.context.get("produced") is True
        self.context["order"] = self.context.get("order", []) + ["B"]
        return self._result


def test_depends_on_is_respected(monkeypatch):
    monkeypatch.setitem(CHECK_REGISTRY, "aaa_producer", _A)
    monkeypatch.setitem(CHECK_REGISTRY, "bbb_consumer", _B)
    # ordre demandé volontairement inversé : B avant A
    eng = ScanEngine("https://cible.test", {"timeout": 5, "skip_reachability": True},
                     checks_list=["bbb_consumer", "aaa_producer"])
    results = eng.run_all()
    assert eng.context["order"] == ["A", "B"]


class _Boom(BaseCheck):
    name = "boom_check"
    title = "Boom"; description = "d"; severity = "INFO"

    def run(self):
        raise RuntimeError("échec délibéré du check")


def test_check_exception_still_produces_info_error_finding(monkeypatch):
    """Le moteur doit continuer à isoler l'exception d'un check dans un
    CheckResult INFO (comportement existant), même après l'ajout du logging
    de la traceback complète, le logging est un ajout, pas un remplacement."""
    monkeypatch.setitem(CHECK_REGISTRY, "boom_check", _Boom)
    eng = ScanEngine("https://cible.test", {"timeout": 5, "skip_reachability": True},
                     checks_list=["boom_check"])
    results = eng.run_all()
    assert len(results) == 1
    result = results[0]
    assert result.check_name == "boom_check"
    assert result.severity == "INFO"
    assert result.passed is False
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["severity"] == "INFO"
    assert "échec délibéré du check" in finding["message"]
