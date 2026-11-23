"""SEC-13 : version du cœur et branche face aux données de wordpress.org.

Fixtures : réponses réelles de stable-check (1.0) et version-check (1.7)
enregistrées le 2026-11-21 (tests/fixtures/wporg_kev/). Dans ces données,
7.1.5 est « latest », 7.1.4 « insecure » et 7.0.9 « outdated » bien que
dernière de la branche 7.0.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.core_branch import CoreBranchCheck
from wp_security_forsure.scanner.vulndb import wporg

FIX = Path(__file__).parent / "fixtures" / "wporg_kev"
STABLE = json.loads((FIX / "wporg_core_stable-check_2026-11-21.json").read_text(encoding="utf-8"))
OFFERS = json.loads((FIX / "wporg_core_version-check_2026-11-21.json").read_text(encoding="utf-8"))
NOW = int(datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc).timestamp())


def _serve(stable=True, offers=True):
    if stable:
        responses.add(responses.GET, wporg.STABLE_CHECK_URL, json=STABLE)
    else:
        responses.add(responses.GET, wporg.STABLE_CHECK_URL, body=ConnectionError("hors ligne"))
    if offers:
        responses.add(responses.GET, wporg.VERSION_CHECK_URL, json=OFFERS)
    else:
        responses.add(responses.GET, wporg.VERSION_CHECK_URL, body=ConnectionError("hors ligne"))


def _run(version, source="generator", confidence="confirmed", now=NOW):
    chk = make_check(CoreBranchCheck)
    chk._now = now
    core = ({"version": version, "source": source, "confidence": confidence}
            if version else None)
    chk.context = {"inventory": {"core": core, "plugins": [], "themes": []}}
    return chk.run().findings


def _real(findings):
    return [f for f in findings if f["severity"] != "INFO"]


# ── Les quatre cas sur les vraies données ────────────────────────────────

@responses.activate
def test_insecure_version_is_high_with_branch_and_latest():
    _serve()
    findings = _run("7.1.4")
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "HIGH"
    assert "version marquée insecure par wordpress.org" in f["message"]
    assert "dernière version de la branche 7.1 : 7.1.5" in f["message"]
    assert "dernière version : 7.1.5" in f["message"]
    assert f["confidence"] == "confirmed"
    assert f["access_class"] == "recon"
    assert "Remédiation : mettre à jour vers 7.1.5" in f["evidence"]


@responses.activate
def test_latest_of_old_branch_is_low():
    _serve()
    findings = _run("7.0.9")
    assert [f["severity"] for f in findings] == ["LOW"]
    assert "dernière version de la branche 7.0" in findings[0]["message"]
    assert "branche ancienne" in findings[0]["message"]
    assert "7.1.5" in findings[0]["message"]


@responses.activate
def test_latest_version_gives_nothing():
    _serve()
    assert _run("7.1.5") == []


@responses.activate
def test_unknown_version_is_info_not_verified():
    _serve()
    findings = _run("9.9.9")
    assert _real(findings) == []
    assert len(findings) == 1
    assert "version inconnue de wordpress.org" in findings[0]["message"]
    assert findings[0]["confidence"] == "potential"


def test_behind_branch_without_insecure_is_medium():
    """Cas défini par la règle mais absent des données réelles (toute version
    non dernière y est insecure) : stable-check modifié pour 7.0.8."""
    stable = dict(STABLE, **{"7.0.8": "outdated"})
    a = wporg.assess_core("7.0.8", stable, {"offers": OFFERS["offers"]})
    assert a.verdict == wporg.BEHIND_BRANCH
    assert a.branch_latest == "7.0.9" and a.latest == "7.1.5"


@pytest.mark.parametrize("version,verdict,branch_latest", [
    ("7.1.4", wporg.INSECURE, "7.1.5"),
    ("7.0.9", wporg.OLD_BRANCH, "7.0.9"),
    ("7.1.5", wporg.LATEST, "7.1.5"),
    ("6.9.12", wporg.OLD_BRANCH, "6.9.12"),
    ("6.4.0", wporg.INSECURE, "6.4.15"),     # 6.4.0 = clé « 6.4 »
    ("9.9.9", wporg.UNKNOWN_VERSION, None),
])
def test_assess_core_on_real_data(version, verdict, branch_latest):
    a = wporg.assess_core(version, STABLE, {"offers": OFFERS["offers"]})
    assert a.verdict == verdict
    assert a.branch_latest == branch_latest


# ── Confiance, réseau, cache ─────────────────────────────────────────────

@responses.activate
def test_confidence_follows_detected_version():
    _serve()
    f = _run("7.1.4", confidence="potential")[0]
    assert f["severity"] == "HIGH" and f["confidence"] == "potential"
    assert "incohérente entre sources" in f["evidence"]


@responses.activate
def test_network_down_gives_info_not_verified():
    _serve(stable=False, offers=False)
    findings = _run("7.1.4")
    assert _real(findings) == []
    assert len(findings) == 1
    assert "non vérifié" in findings[0]["message"]


@responses.activate
def test_version_check_down_still_uses_stable_check():
    _serve(offers=False)
    f = _run("7.1.4")[0]
    assert f["severity"] == "HIGH"
    assert "7.1.5" in f["message"]
    assert "version-check indisponible" in f["evidence"]


@responses.activate
def test_no_core_version_sends_no_request():
    _serve()
    findings = _run(None)
    assert len(findings) == 1 and findings[0]["severity"] == "INFO"
    assert len(responses.calls) == 0


@responses.activate
def test_requests_carry_no_site_data():
    _serve()
    _run("7.1.4")
    urls = sorted(c.request.url for c in responses.calls)
    assert urls == sorted([wporg.STABLE_CHECK_URL, wporg.VERSION_CHECK_URL])
    assert all(c.request.method == "GET" for c in responses.calls)


@responses.activate
def test_core_data_cached_24h_then_stale_when_offline():
    _serve()
    _run("7.1.4")
    assert len(responses.calls) == 2
    # Moins de 24 h plus tard : servi du cache, aucune requête.
    responses.reset()
    f = _run("7.1.4", now=NOW + 23 * 3600)[0]
    assert len(responses.calls) == 0
    assert f["confidence"] == "confirmed"
    # Plus de 24 h et réseau coupé : cache périmé, constat « à vérifier ».
    _serve(stable=False, offers=False)
    f = _run("7.1.4", now=NOW + 25 * 3600)[0]
    assert len(responses.calls) == 2
    assert f["severity"] == "HIGH" and f["confidence"] == "potential"
    assert "cache périmé" in f["evidence"]
