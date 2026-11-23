"""SEC-13 : catalogue CISA KEV (instantané local, commande refresh-kev).

Fixture : extrait réel du flux CISA KEV enregistré le 2026-11-20
(tests/fixtures/wporg_kev/kev_wordpress_extract_2026-11-20.json). Le vrai flux
range ses entrées sous ``vulnerabilities`` ; l'extrait les range sous
``wordpress_entries_2025_2026`` : _feed() reconstruit le format réel.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import responses

from tests.conftest import make_check
from wp_security_forsure import __main__ as cli
from wp_security_forsure.scanner.checks.vulnerability_scan import (
    REMEDIATION_UNFIXED, REMEDIATION_UPDATE, VulnerabilityScanCheck)
from wp_security_forsure.scanner.vulndb import freshness
from wp_security_forsure.scanner.vulndb.cache import VulnCache, kev_path
from wp_security_forsure.scanner.vulndb.epss import load_epss
from wp_security_forsure.scanner.vulndb.kev import KEV_URL, load_kev

FIX = Path(__file__).parent / "fixtures" / "wporg_kev"
NOW = int(datetime(2026, 11, 23, 8, 0, tzinfo=timezone.utc).timestamp())

CORE_PAYLOAD = {"data": {"vulnerability": [
    {   # Dans le KEV (ajoutée le 2026-11-03).
        "name": "WordPress Core 4.7.0 - 7.1.3 - Upgrade-Window RCE",
        "operator": {"min_version": "7.1", "min_operator": "ge",
                     "max_version": "7.1.4", "max_operator": "lt"},
        "source": [{"id": "CVE-2026-119977",
                    "link": "https://www.cve.org/CVERecord?id=CVE-2026-119977"}],
        "impact": {"cvss": {"score": "8.1", "vector": "CVSS:3.1/AV:N/AC:H"}},
    },
    {   # Absente du KEV.
        "name": "WordPress Core < 7.1.5 - Stored XSS",
        "operator": {"max_version": "7.1.5", "max_operator": "lt"},
        "source": [{"id": "CVE-2026-999001", "link": "https://x.test"}],
        "impact": {"cvss": {"score": "6.4", "vector": "v"}},
    },
]}}

PLUGIN_PAYLOAD = {"data": {"vulnerability": [
    {"name": "Démo < 2.0 - Upload", "operator": {"max_version": "2.0", "max_operator": "lt"},
     "source": [{"id": "CVE-2026-999002", "link": "https://x.test"}],
     "impact": {"cvss": {"score": "7.5", "vector": "v"}}},
    {"name": "Démo <= 2.5 - Sans correctif",
     "operator": {"max_version": "2.5", "max_operator": "le", "unfixed": "1"},
     "source": [{"id": "CVE-2026-999003", "link": "https://x.test"}],
     "impact": {"cvss": {"score": "5.0", "vector": "v"}}},
]}}


def _feed():
    extract = json.loads((FIX / "kev_wordpress_extract_2026-11-20.json")
                         .read_text(encoding="utf-8"))
    entries = extract["wordpress_entries_2025_2026"]
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": extract["catalogVersion"],
            "dateReleased": extract["dateReleased"],
            "count": len(entries), "vulnerabilities": entries}


def _kev_file(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps(_feed()), encoding="utf-8")
    return p


def _scan(tmp_path, inventory, payloads, kev=None):
    cache = VulnCache(str(tmp_path / "vulncache.sqlite"))
    for (ctype, slug), payload in payloads.items():
        cache.put(ctype, slug, payload, now=NOW)
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": inventory}
    chk._cache = cache
    chk._client = lambda t, s: None
    chk._epss = load_epss(tmp_path / "absent.csv")
    if kev is not None:
        chk._kev = kev
    chk._now = NOW
    return chk.run()


def _core_inventory(version="7.1.3", confidence="confirmed"):
    return {"plugins": [], "themes": [],
            "core": {"version": version, "source": "generator",
                     "confidence": confidence}}


# ── Chargement de l'instantané ───────────────────────────────────────────

def test_load_kev_indexes_real_feed_entries(tmp_path):
    idx = load_kev(_kev_file(tmp_path))
    assert idx.present and idx.count == 5
    assert idx.catalog_version == "2026.11.20"
    assert idx.snapshot_date.isoformat() == "2026-11-20"
    assert idx.date_source == "dateReleased"
    entry = idx.entry_for(["CVE-2026-119977"])
    assert entry.as_finding() == {"date_added": "2026-11-03",
                                  "due_date": "2026-11-06",
                                  "ransomware": "Unknown"}
    assert idx.entry_for(["cve-2026-41940"]).ransomware == "Known"
    assert idx.entry_for(["CVE-2026-102435"]) is None   # Ultra Addons : pas au KEV
    assert idx.entry_for([]) is None


def test_load_kev_absent_or_invalid_is_empty(tmp_path):
    assert load_kev(tmp_path / "absent.json").present is False
    bad = tmp_path / "bad.json"
    bad.write_text('{"wordpress_entries_2025_2026": []}', encoding="utf-8")
    assert load_kev(bad).present is False
    assert load_kev(bad).entry_for(["CVE-2026-119977"]) is None


# ── Appariement pendant l'audit ──────────────────────────────────────────

def test_matched_cve_in_kev_is_critical_with_kev_field(tmp_path):
    kev = load_kev(_kev_file(tmp_path))
    result = _scan(tmp_path, _core_inventory(), {("core", "7.1.3"): CORE_PAYLOAD}, kev)
    hit = next(f for f in result.findings if "CVE-2026-119977" in f["evidence"])
    assert hit["severity"] == "CRITICAL"            # CVSS 8.1 seul : HIGH
    assert hit["confidence"] == "confirmed"
    assert hit["kev"] == {"date_added": "2026-11-03", "due_date": "2026-11-06",
                          "ransomware": "Unknown"}
    assert hit["scoring"]["kev"] == hit["kev"]
    assert ("activement exploitée (catalogue CISA KEV, ajoutée le 2026-11-03)"
            in hit["message"])
    assert "échéance de correction 2026-11-06" in hit["evidence"]
    assert hit["impact"]["enables"].startswith("Faille activement exploitée (catalogue CISA KEV")


def test_matched_cve_absent_from_kev_keeps_cvss_severity(tmp_path):
    kev = load_kev(_kev_file(tmp_path))
    result = _scan(tmp_path, _core_inventory(), {("core", "7.1.3"): CORE_PAYLOAD}, kev)
    other = next(f for f in result.findings if "CVE-2026-999001" in f["evidence"])
    assert other["severity"] == "MEDIUM"
    assert "kev" not in other and "kev" not in other["scoring"]
    assert "KEV" not in other["message"]


def test_kev_keeps_potential_confidence(tmp_path):
    kev = load_kev(_kev_file(tmp_path))
    result = _scan(tmp_path, _core_inventory(confidence="potential"),
                   {("core", "7.1.3"): CORE_PAYLOAD}, kev)
    hit = next(f for f in result.findings if "CVE-2026-119977" in f["evidence"])
    assert hit["severity"] == "CRITICAL"
    assert hit["confidence"] == "potential"


def test_absent_kev_snapshot_changes_nothing_and_is_declared(tmp_path):
    # Pas d'injection : lecture de kev_path() dans le dossier de cache isolé,
    # où aucun instantané n'existe.
    assert not kev_path().exists()
    result = _scan(tmp_path, _core_inventory(), {("core", "7.1.3"): CORE_PAYLOAD})
    hit = next(f for f in result.findings if "CVE-2026-119977" in f["evidence"])
    assert hit["severity"] == "HIGH" and "kev" not in hit
    ds = result.data_sources["kev"]
    assert ds["present"] is False
    assert ds["label"] == "KEV absent : lancer refresh-kev"


def test_data_sources_give_kev_snapshot_date(tmp_path):
    kev = load_kev(_kev_file(tmp_path))
    result = _scan(tmp_path, _core_inventory(), {("core", "7.1.3"): CORE_PAYLOAD}, kev)
    ds = result.data_sources["kev"]
    assert ds["present"] is True
    assert ds["snapshot_date"] == "2026-11-20"
    assert ds["age_days"] == 3
    assert ds["catalog_version"] == "2026.11.20"
    assert "2026-11-20" in ds["label"]
    assert freshness.not_consulted()["kev"]["present"] is None


@responses.activate
def test_audit_never_downloads_kev(tmp_path):
    _scan(tmp_path, _core_inventory(), {("core", "7.1.3"): CORE_PAYLOAD})
    assert not [c for c in responses.calls if "cisa.gov" in c.request.url]


# ── Remédiation d'une extension vulnérable ───────────────────────────────

def test_vulnerable_plugin_remediation_says_delete_if_unused(tmp_path):
    inv = {"core": None, "themes": [],
           "plugins": [{"slug": "demo", "version": "1.0", "source": "readme"}]}
    result = _scan(tmp_path, inv, {("plugin", "demo"): PLUGIN_PAYLOAD},
                   load_kev(tmp_path / "absent.json"))
    fixable = next(f for f in result.findings if "CVE-2026-999002" in f["evidence"])
    assert f"Remédiation : {REMEDIATION_UPDATE}" in fixable["evidence"]
    assert REMEDIATION_UPDATE == ("mettre à jour ; si inutilisé, supprimer "
                                  "(désactiver ne suffit pas)")
    unfixed = next(f for f in result.findings if "CVE-2026-999003" in f["evidence"])
    assert f"Remédiation : {REMEDIATION_UNFIXED}" in unfixed["evidence"]


# ── Commande refresh-kev (hors ligne) ────────────────────────────────────

@responses.activate
def test_refresh_kev_downloads_and_writes_snapshot(tmp_path):
    responses.add(responses.GET, KEV_URL, json=_feed(), status=200)
    dest = tmp_path / "sub" / "kev.json"
    path, count, version = cli.refresh_kev(dest)
    assert path == dest and count == 5 and version == "2026.11.20"
    assert len(responses.calls) == 1
    assert responses.calls[0].request.method == "GET"
    assert "wp_security_ForSure" in responses.calls[0].request.headers["User-Agent"]
    assert load_kev(dest).entry_for(["CVE-2026-119977"]).date_added == "2026-11-03"


@responses.activate
def test_refresh_kev_failure_keeps_existing_snapshot(tmp_path):
    dest = _kev_file(tmp_path)
    before = dest.read_bytes()
    responses.add(responses.GET, KEV_URL, status=503)
    try:
        cli.refresh_kev(dest)
    except Exception:
        pass
    responses.replace(responses.GET, KEV_URL, body="<html>pas du JSON</html>", status=200)
    try:
        cli.refresh_kev(dest)
    except Exception:
        pass
    assert dest.read_bytes() == before
    assert not (tmp_path / "kev.json.tmp").exists()


@responses.activate
def test_cli_refresh_kev_writes_user_cache_and_reports_failure(capsys):
    responses.add(responses.GET, KEV_URL, json=_feed(), status=200)
    assert cli.main(["refresh-kev"]) == cli.EXIT_OK
    assert "5 entrées" in capsys.readouterr().out
    assert load_kev(kev_path()).present
    responses.replace(responses.GET, KEV_URL, body=ConnectionError("hors ligne"))
    assert cli.main(["refresh-kev"]) == cli.EXIT_INCOMPLETE
    assert "Instantané existant conservé" in capsys.readouterr().err
    assert load_kev(kev_path()).present
