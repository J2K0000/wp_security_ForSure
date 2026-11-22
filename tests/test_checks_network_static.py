"""Garde-fou statique : aucun module de scanner/checks/ (hors base.py) ne
touche le réseau sans passer par les helpers de BaseCheck.

Interdit (analyse AST du code source) :
  - toute référence à `self.session` (seul base.py la manipule) ;
  - tout appel réseau du module `requests` (get, post, request, Session...) ;
  - les clients HTTP bas niveau (urlopen, http.client, socket.create_connection).
Autorisé : `requests.Response`, `requests.RequestException` et les autres
exceptions ou types, la résolution DNS (socket.getaddrinfo, dns.resolver).
"""
import ast
from pathlib import Path

import pytest

CHECKS_DIR = (Path(__file__).resolve().parent.parent
              / "wp_security_forsure" / "scanner" / "checks")

_REQUESTS_NETWORK = {"get", "post", "put", "patch", "delete", "head",
                     "options", "request", "Session", "session"}
_LOW_LEVEL = {"urlopen", "HTTPConnection", "HTTPSConnection",
              "create_connection"}

# Modules hors du périmètre de ce chantier (modifiés par ailleurs) qui
# contournent encore les helpers : signalés, à corriger dans leur chantier.
_KNOWN_PENDING = {}


def _violations(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and node.attr == "session"
                and isinstance(node.value, ast.Name) and node.value.id == "self"):
            found.append(f"{path.name}:{node.lineno} self.session")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            func = node.func
            owner = func.value
            if (isinstance(owner, ast.Name) and owner.id == "requests"
                    and func.attr in _REQUESTS_NETWORK):
                found.append(f"{path.name}:{node.lineno} requests.{func.attr}()")
            if func.attr in _LOW_LEVEL:
                found.append(f"{path.name}:{node.lineno} {func.attr}()")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in _LOW_LEVEL:
            found.append(f"{path.name}:{node.lineno} {node.func.id}()")
    return found


def _modules():
    params = []
    for path in sorted(CHECKS_DIR.glob("*.py")):
        if path.name in ("base.py", "__init__.py"):
            continue
        marks = []
        if path.name in _KNOWN_PENDING:
            marks.append(pytest.mark.xfail(reason=_KNOWN_PENDING[path.name],
                                           strict=False))
        params.append(pytest.param(path, id=path.name, marks=marks))
    return params


@pytest.mark.parametrize("path", _modules())
def test_check_module_uses_only_basecheck_helpers(path):
    found = _violations(path)
    assert not found, "réseau hors helpers BaseCheck :\n" + "\n".join(found)


def test_static_scan_detects_a_direct_call(tmp_path):
    """Le détecteur lui-même fonctionne (sinon le test ci-dessus serait vide)."""
    bad = tmp_path / "bad_check.py"
    bad.write_text(
        "import requests\n"
        "class C:\n"
        "    def run(self):\n"
        "        self.session.get('https://x.test')\n"
        "        requests.post('https://x.test')\n",
        encoding="utf-8",
    )
    found = _violations(bad)
    assert any("self.session" in f for f in found)
    assert any("requests.post" in f for f in found)


def test_modules_are_discovered():
    assert len(_modules()) >= 20
