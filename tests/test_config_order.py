"""Chantier 3, Task 3 : l'ordre du config.yaml pilote l'ordre d'exécution."""
from wp_security_forsure.scanner.engine import ScanEngine, CHECK_REGISTRY
from wp_security_forsure.scanner.checks.base import BaseCheck


class _Alpha(BaseCheck):
    name = "c3_alpha"; title = "a"; description = "d"; severity = "INFO"
    def run(self):
        return self._result


class _Beta(BaseCheck):
    name = "c3_beta"; title = "b"; description = "d"; severity = "INFO"
    def run(self):
        return self._result


class _Gamma(BaseCheck):
    name = "c3_gamma"; title = "g"; description = "d"; severity = "INFO"
    def run(self):
        return self._result


def _register(monkeypatch):
    for c in (_Alpha, _Beta, _Gamma):
        monkeypatch.setitem(CHECK_REGISTRY, c.name, c)


def test_config_checks_defines_default_order(monkeypatch):
    _register(monkeypatch)
    eng = ScanEngine("https://cible.test",
                     {"checks": ["c3_gamma", "c3_alpha", "c3_beta"]})
    order = eng._resolve_order(eng._requested_checks())
    assert order == ["c3_gamma", "c3_alpha", "c3_beta"]


def test_cli_checks_override_config_order(monkeypatch):
    _register(monkeypatch)
    eng = ScanEngine("https://cible.test",
                     {"checks": ["c3_gamma", "c3_alpha", "c3_beta"]},
                     checks_list=["c3_beta", "c3_alpha"])
    assert eng._requested_checks() == ["c3_beta", "c3_alpha"]


def test_no_config_checks_falls_back_to_registry():
    eng = ScanEngine("https://cible.test", {})
    assert eng._requested_checks() == list(CHECK_REGISTRY.keys())


def test_unknown_config_names_are_ignored(monkeypatch):
    _register(monkeypatch)
    eng = ScanEngine("https://cible.test",
                     {"checks": ["c3_alpha", "does_not_exist", "c3_beta"]})
    order = eng._resolve_order(eng._requested_checks())
    assert order == ["c3_alpha", "c3_beta"]
