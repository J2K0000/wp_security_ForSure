"""Reporters : génèrent la sortie du scan dans différents formats."""

import copy
from typing import List
from ..checks.base import CheckResult
from ..redact import redact_obj, redact_text


def get_reporter(format_name: str, results: List[CheckResult],
                 target: str, config: dict):
    """Factory : retourne le reporter approprié."""
    if format_name == "json":
        from .json_reporter import JSONReporter
        return JSONReporter(results, target, config)
    elif format_name == "html":
        from .html_reporter import HTMLReporter
        return HTMLReporter(results, target, config)
    else:
        from .terminal_reporter import TerminalReporter
        return TerminalReporter(results, target, config)


def redacted_results(results: List[CheckResult]) -> List[CheckResult]:
    """Copies des résultats dont chaque texte est passé au masquage des
    secrets (défense en profondeur : un check qui aurait recopié un secret
    brut ne le fait pas fuiter dans le rapport). Les originaux sont intacts ;
    les attributs d'instance (statut, fraîcheur des données) sont conservés."""
    out = []
    for r in results or []:
        c = copy.copy(r)
        c.findings = [redact_obj(f) for f in (r.findings or [])]
        c.title = redact_text(r.title)
        c.description = redact_text(r.description)
        out.append(c)
    return out


class BaseReporter:
    """Classe de base pour les reporters.

    Tout reporter travaille sur des copies masquées : dernier passage avant
    le rendu, quel que soit le format."""

    def __init__(self, results: List[CheckResult], target: str, config: dict):
        self.results = redacted_results(results)
        self.target = redact_text(target)
        self.config = config

    def generate(self) -> str:
        raise NotImplementedError
