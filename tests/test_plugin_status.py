"""SEC-16 : extensions fermées, abandonnées ou d'outillage de maintenance.

Fixtures : réponses réelles de l'API plugins de wordpress.org (1.2,
plugin_information) enregistrées en novembre 2026 : reset-database et
advance-guest-post fermées (servies en HTTP 404), ultimate-addons-for-
contact-form-7 publiée (tests/fixtures/wporg_kev/).
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks import common_components
from wp_security_forsure.scanner.checks.base import SEVERITY_ORDER
from wp_security_forsure.scanner.checks.maintenance_tools import MAINTENANCE_TOOLS
from wp_security_forsure.scanner.checks.plugin_status import PluginStatusCheck
from wp_security_forsure.scanner.vulndb import wporg

FIX = Path(__file__).parent / "fixtures" / "wporg_kev"
NOW = int(datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc).timestamp())


def _fixture(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


RESET_DB = _fixture("wp_reset-database.json")
GUEST_POST = _fixture("wp_advance-guest-post.json")
UACF7 = _fixture("wp_ultimate-addons-for-contact-form-7.json")
UACF7_SLUG = "ultimate-addons-for-contact-form-7"


def _serve(slug, body, status=200):
    responses.add(responses.GET, wporg.plugin_info_url(slug), json=body, status=status)


def _run(*plugins, now=NOW):
    chk = make_check(PluginStatusCheck)
    chk._now = now
    inv = [p if isinstance(p, dict) else {"slug": p, "version": None, "source": "ver_param"}
           for p in plugins]
    chk.context = {"inventory": {"core": None, "plugins": inv, "themes": []}}
    return chk.run().findings


def _by_sev(findings, sev):
    return [f for f in findings if f["severity"] == sev]


# ── Fermée ───────────────────────────────────────────────────────────────

@responses.activate
def test_closed_plugin_is_high_with_date_and_reason():
    _serve("advance-guest-post", GUEST_POST, status=404)
    findings = _run("advance-guest-post")
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "HIGH" and f["confidence"] == "confirmed"
    assert "fermée sur wordpress.org le 2026-10-28" in f["message"]
    assert "(motif : non précisé)" in f["message"]
    assert "plus aucune mise à jour possible" in f["message"]
    assert "désactiver ne suffit pas, un plugin désactivé reste exploitable" in f["message"]
    assert "pending a full review" in f["evidence"]   # texte publié par wordpress.org
    assert f["url"] == "https://wordpress.org/plugins/advance-guest-post/"


@responses.activate
def test_closed_reset_database_is_also_maintenance_tooling():
    _serve("reset-database", RESET_DB, status=404)
    findings = _run("reset-database")
    high = _by_sev(findings, "HIGH")
    assert len(high) == 2
    closed = next(f for f in high if "fermée" in f["message"])
    assert "le 2026-11-09" in closed["message"]
    tool = next(f for f in high if "outil" in f["message"])
    assert "outil de maintenance à retirer de la production" in tool["message"]
    assert "Motif : " in tool["evidence"]


@responses.activate
def test_closed_reason_text_is_quoted_when_given():
    body = dict(GUEST_POST, reason="security-issue", reason_text="Security Issue")
    _serve("advance-guest-post", body, status=404)
    f = _run("advance-guest-post")[0]
    assert "(motif : Security Issue)" in f["message"]


# ── Publiée : récente ou abandonnée ──────────────────────────────────────

@responses.activate
def test_recent_active_plugin_gives_nothing():
    _serve(UACF7_SLUG, UACF7)
    assert _run(UACF7_SLUG) == []


@responses.activate
def test_stale_plugin_is_medium_probably_abandoned_with_threshold():
    _serve(UACF7_SLUG, dict(UACF7, last_updated="2023-05-02 1:15pm GMT"))
    findings = _run(UACF7_SLUG)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "MEDIUM"
    assert "probablement abandonnée" in f["message"]
    assert "2023-05-02" in f["message"]
    assert "seuil choisi par l'outil" in f["message"]
    assert "Seuil : 2 ans" in f["evidence"] and "choix de wp_security_ForSure" in f["evidence"]
    assert f["confidence"] == "potential"


@responses.activate
def test_update_just_under_two_years_is_not_abandoned():
    _serve(UACF7_SLUG, dict(UACF7, last_updated="2024-12-01 9:00am GMT"))
    assert _run(UACF7_SLUG) == []


# ── Absente, réseau, réponses inexploitables ─────────────────────────────

@responses.activate
def test_absent_from_directory_draws_no_conclusion():
    _serve("mon-extension-maison", {"error": "Plugin not found."}, status=404)
    findings = _run("mon-extension-maison")
    assert [f["severity"] for f in findings] == ["INFO"]
    assert "absentes du répertoire" in findings[0]["message"]
    assert "mon-extension-maison" in findings[0]["message"]


@responses.activate
def test_network_down_gives_info_not_verified():
    responses.add(responses.GET, wporg.plugin_info_url("reset-database"),
                  body=ConnectionError("hors ligne"))
    findings = _run({"slug": "reset-database", "version": None, "source": "readme"})
    assert not [f for f in findings if "fermée" in f["message"]]
    info = _by_sev(findings, "INFO")
    assert len(info) == 1 and "non vérifié" in info[0]["message"]
    assert "reset-database" in info[0]["message"]


@responses.activate
def test_rate_limit_is_unknown_and_never_cached():
    responses.add(responses.GET, wporg.plugin_info_url(UACF7_SLUG), status=429)
    assert "non vérifié" in _run(UACF7_SLUG)[0]["message"]
    responses.reset()
    _serve(UACF7_SLUG, UACF7)
    assert _run(UACF7_SLUG) == []
    assert len(responses.calls) == 1


@responses.activate
def test_404_without_json_is_unknown_not_absent():
    responses.add(responses.GET, wporg.plugin_info_url(UACF7_SLUG),
                  body="<html>introuvable</html>", status=404)
    f = _run(UACF7_SLUG)[0]
    assert "non vérifié" in f["message"]


@responses.activate
def test_directory_answers_cached_seven_days():
    _serve("advance-guest-post", GUEST_POST, status=404)
    _run("advance-guest-post")
    responses.reset()
    f = _run("advance-guest-post", now=NOW + 6 * 86400)[0]
    assert len(responses.calls) == 0
    assert f["severity"] == "HIGH" and f["confidence"] == "confirmed"
    responses.add(responses.GET, wporg.plugin_info_url("advance-guest-post"),
                  body=ConnectionError("hors ligne"))
    f = _run("advance-guest-post", now=NOW + 8 * 86400)[0]
    assert len(responses.calls) == 1
    assert f["severity"] == "HIGH" and f["confidence"] == "potential"
    assert "cache périmé" in f["evidence"]


@responses.activate
def test_request_url_and_invalid_slug_never_sent():
    _serve(UACF7_SLUG, UACF7)
    _run(UACF7_SLUG, {"slug": "../../etc/passwd", "version": None,
                      "source": "rest_namespace"})
    assert len(responses.calls) == 1
    url = responses.calls[0].request.url
    assert url.startswith("https://api.wordpress.org/plugins/info/1.2/?")
    assert "action=plugin_information" in url and UACF7_SLUG in url


# ── Outillage de maintenance ─────────────────────────────────────────────

@responses.activate
def test_file_manager_is_high_tooling_and_debug_tool_is_low():
    _serve("wp-file-manager", {"name": "WP File Manager", "slug": "wp-file-manager",
                               "version": "8.0.2", "last_updated": "2026-10-01 8:00am GMT"})
    _serve("query-monitor", {"name": "Query Monitor", "slug": "query-monitor",
                             "version": "3.20.0", "last_updated": "2026-09-14 2:00pm GMT"})
    findings = _run("wp-file-manager", "query-monitor")
    fm = next(f for f in findings if "wp-file-manager" in f["message"])
    assert fm["severity"] == "HIGH"
    assert "outil de maintenance à retirer de la production" in fm["message"]
    assert fm["url"].endswith("/wp-content/plugins/wp-file-manager/")
    qm = next(f for f in findings if "query-monitor" in f["message"])
    assert qm["severity"] == "LOW"
    assert "outil de débogage à retirer de la production" in qm["message"]


@responses.activate
def test_slug_guessed_from_rest_namespace_stays_potential():
    _serve("wp-file-manager", {"error": "Plugin not found."}, status=404)
    findings = _run({"slug": "wp-file-manager", "version": None, "source": "rest_namespace"})
    tool = next(f for f in findings if f["severity"] == "HIGH")
    assert tool["confidence"] == "potential"
    assert "namespace REST" in tool["evidence"]


def test_maintenance_tools_entries_are_justified_and_probed():
    assert "health-check" not in MAINTENANCE_TOOLS   # écarté, motif en tête du module
    for slug, tool in MAINTENANCE_TOOLS.items():
        assert wporg.valid_slug(slug), slug
        assert tool["severity"] in SEVERITY_ORDER and tool["severity"] != "INFO", slug
        assert len(tool["reason"]) > 40, slug
        assert tool["remediation"], slug
        assert slug in common_components.COMMON_PLUGINS, slug
    for cat in ("reset", "files", "database", "debug"):
        assert any(t["category"] == cat for t in MAINTENANCE_TOOLS.values()), cat


def test_sec16_slugs_are_probed_by_readme_under_authorized():
    for slug in ("advance-guest-post", UACF7_SLUG, "reset-database"):
        assert slug in common_components.COMMON_PLUGINS
    assert len(common_components.COMMON_PLUGINS) == len(set(common_components.COMMON_PLUGINS))


def test_new_modules_have_no_em_dash():
    root = Path(__file__).resolve().parent.parent / "wp_security_forsure"
    for rel in ("scanner/checks/core_branch.py", "scanner/checks/plugin_status.py",
                "scanner/checks/maintenance_tools.py", "scanner/vulndb/wporg.py",
                "scanner/vulndb/kev.py", "scanner/vulndb/freshness.py",
                "scanner/checks/vulnerability_scan.py"):
        text = (root / rel).read_text(encoding="utf-8")
        assert chr(0x2014) not in text, rel


def test_parse_date_reads_wporg_formats():
    assert wporg.parse_date("2026-11-20 4:29pm GMT").isoformat() == "2026-11-20"
    assert wporg.parse_date("2026-11-09").isoformat() == "2026-11-09"
    assert wporg.parse_date(False) is None
    assert re.match(r"^\d{4}-\d{2}-\d{2}", UACF7["last_updated"])
