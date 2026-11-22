"""CLI : codes de sortie documentés, checks inconnus, format déduit de
l'extension, liste générée depuis le registre, plus d'option de mode actif."""
import json

import pytest
import responses

from wp_security_forsure import __main__ as cli
from wp_security_forsure.scanner import status as st
from wp_security_forsure.scanner.checks.base import BaseCheck, CheckResult
from wp_security_forsure.scanner.engine import CHECK_REGISTRY, ScanEngine

TARGET = "https://cible.test"


def _result(name="c", status=st.STATUS_OK, severity=None, confidence="confirmed"):
    r = CheckResult(name, f"Titre {name}", "d", "INFO", True)
    if severity:
        r.add_finding(f"constat {name}", severity=severity, confidence=confidence)
    return st.set_status(r, status)


def _patch_run(monkeypatch, results):
    monkeypatch.setattr(ScanEngine, "run_all", lambda self: results)


@pytest.mark.parametrize("results, expected", [
    ([_result()], 0),
    ([_result(severity="HIGH")], 0),
    ([_result(severity="CRITICAL", confidence="potential")], 0),
    ([_result(severity="CRITICAL")], 1),
    ([_result(), _result("e", status=st.STATUS_ERROR)], 3),
    ([_result(severity="CRITICAL"), _result("e", status=st.STATUS_ERROR)], 1),
    ([], 3),
])
def test_exit_code_for(results, expected):
    assert cli.exit_code_for(results) == expected


def test_exit_code_constants():
    assert (cli.EXIT_OK, cli.EXIT_CRITICAL, cli.EXIT_USAGE,
            cli.EXIT_INCOMPLETE) == (0, 1, 2, 3)


def test_main_returns_3_when_target_unreachable(capsys):
    # Aucune réponse enregistrée : toute requête lève ConnectionError (hors ligne).
    with responses.RequestsMock():
        code = cli.main(["audit", "https://down.test", "--checks", "fingerprint",
                         "--format", "json"])
    assert code == 3
    data = json.loads(capsys.readouterr().out.strip())
    assert data["summary"]["audit_status"] == "incomplet"


def test_main_returns_1_on_confirmed_critical_even_if_incomplete(monkeypatch, capsys):
    _patch_run(monkeypatch, [_result(severity="CRITICAL"),
                             _result("e", status=st.STATUS_ERROR)])
    assert cli.main(["audit", TARGET, "--format", "json"]) == 1


def test_main_returns_0_when_complete(monkeypatch, capsys):
    _patch_run(monkeypatch, [_result()])
    assert cli.main(["audit", TARGET, "--format", "json"]) == 0


def test_main_returns_3_when_a_check_errors(monkeypatch, capsys):
    _patch_run(monkeypatch, [_result(), _result("e", status=st.STATUS_ERROR)])
    assert cli.main(["audit", TARGET, "--format", "json"]) == 3


def test_unknown_check_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", TARGET, "--checks", "fingerprint,nexistepas"])
    assert exc.value.code == 2
    assert "nexistepas" in capsys.readouterr().err


def test_engine_rejects_unknown_cli_check():
    from wp_security_forsure.scanner.engine import UnknownCheckError
    with pytest.raises(UnknownCheckError) as exc:
        ScanEngine(TARGET, {}, checks_list=["fingerprint", "nexistepas"])
    assert exc.value.names == ["nexistepas"]


def test_empty_checks_option_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", TARGET, "--checks", " , "])
    assert exc.value.code == 2


def test_missing_config_file_is_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", TARGET, "--config", str(tmp_path / "absent.yaml")])
    assert exc.value.code == 2


def test_help_documents_exit_codes_and_no_active_mode(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Codes de sortie" in out
    for line in ("0 ", "1 ", "2 ", "3 "):
        assert f"\n  {line}" in out
    assert "audit incomplet" in out
    low = out.lower()
    assert "aggressive" not in low
    assert "destructi" not in low


def test_aggressive_option_is_gone(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", TARGET, "--aggressive"])
    assert exc.value.code == 2


def test_output_html_extension_infers_html(monkeypatch, tmp_path, capsys):
    _patch_run(monkeypatch, [_result()])
    out_file = tmp_path / "rapport.html"
    cli.main(["audit", TARGET, "--output", str(out_file)])
    content = out_file.read_text(encoding="utf-8")
    assert content.startswith("<!DOCTYPE html>")


def test_output_json_extension_infers_json(monkeypatch, tmp_path, capsys):
    _patch_run(monkeypatch, [_result()])
    out_file = tmp_path / "rapport.json"
    cli.main(["audit", TARGET, "-o", str(out_file)])
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["scan"]["target"] == TARGET


def test_explicit_format_wins_over_extension(monkeypatch, tmp_path, capsys):
    _patch_run(monkeypatch, [_result()])
    out_file = tmp_path / "rapport.html"
    cli.main(["audit", TARGET, "--format", "json", "--output", str(out_file)])
    json.loads(out_file.read_text(encoding="utf-8"))


def test_terminal_report_to_file_is_not_empty(monkeypatch, tmp_path, capsys):
    _patch_run(monkeypatch, [_result(severity="HIGH")])
    out_file = tmp_path / "rapport.txt"
    cli.main(["audit", TARGET, "--output", str(out_file)])
    content = out_file.read_text(encoding="utf-8")
    assert "RAPPORT" in content
    assert "constat c" in content


class _ListedCheck(BaseCheck):
    name = "zz_listed_check"
    title = "Contrôle de démonstration"
    description = "Description issue du registre."
    severity = "INFO"
    priority = 2

    def run(self):
        return self._result


def test_list_is_generated_from_registry(monkeypatch, capsys):
    monkeypatch.setitem(CHECK_REGISTRY, _ListedCheck.name, _ListedCheck)
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    for name, cls in CHECK_REGISTRY.items():
        assert name in out
        assert cls.title in out
    assert "Description issue du registre." in out
    assert f"{len(CHECK_REGISTRY)} " in out


def test_catalog_carries_priority(monkeypatch):
    from wp_security_forsure.scanner.engine import check_catalog
    monkeypatch.setitem(CHECK_REGISTRY, _ListedCheck.name, _ListedCheck)
    by_name = {c["name"]: c for c in check_catalog()}
    assert by_name["zz_listed_check"]["priority"] == 2
    assert by_name["fingerprint"]["priority"] == 1
    assert set(by_name) == set(CHECK_REGISTRY)
