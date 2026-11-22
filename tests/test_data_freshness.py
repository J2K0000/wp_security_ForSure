"""Fraîcheur des données : source des CVE, date des fiches en cache utilisées
et âge du snapshot EPSS (ou « EPSS absent ») dans les rapports JSON et HTML."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from tests.conftest import make_check
from wp_security_forsure.scanner import status as st
from wp_security_forsure.scanner.checks.vulnerability_scan import VulnerabilityScanCheck
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter
from wp_security_forsure.scanner.vulndb.cache import VulnCache
from wp_security_forsure.scanner.vulndb.epss import load_epss

TARGET = "https://cible.test"
FIXTURE = Path(__file__).parent / "fixtures" / "epss_sample.csv"
FETCHED_AT = int(datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc).timestamp())
NOW = int(datetime(2026, 11, 22, 8, 0, tzinfo=timezone.utc).timestamp())

PAYLOAD = {"data": {"vulnerability": [{
    "name": "CF7 < 5.3.2", "operator": {"max_version": "5.3.2", "max_operator": "lt"},
    "source": [{"id": "CVE-2021-24145", "link": "https://x"}],
    "impact": {"cvss": {"score": "7.2", "vector": "v"}},
}]}}


def _scan(tmp_path, epss_path):
    cache = VulnCache(str(tmp_path / "vulncache.sqlite"))
    cache.put("plugin", "contact-form-7", PAYLOAD, now=FETCHED_AT)
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"core": None, "themes": [], "plugins": [
        {"slug": "contact-form-7", "version": "5.2.0", "source": "readme"}]}}
    chk._cache = cache
    chk._client = lambda t, s: None
    chk._epss = load_epss(epss_path)
    chk._now = NOW
    result = chk.run()
    return [st.set_status(result, st.STATUS_OK)]


def test_epss_index_exposes_snapshot_date():
    idx = load_epss(FIXTURE)
    assert idx.present is True
    assert idx.snapshot_date.isoformat() == "2026-07-20"
    absent = load_epss(Path("does-not-exist.csv"))
    assert absent.present is False
    assert absent.snapshot_date is None


def test_epss_date_falls_back_to_file_mtime(tmp_path):
    p = tmp_path / "epss.csv"
    p.write_text("cve,epss,percentile\nCVE-2021-0001,0.5,0.9\n", encoding="utf-8")
    idx = load_epss(p)
    assert idx.snapshot_date == datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).date()
    assert idx.date_source == "mtime"


def test_cache_reports_fetched_at(tmp_path):
    cache = VulnCache(str(tmp_path / "c.sqlite"))
    cache.put("plugin", "cf7", {"data": {}}, now=FETCHED_AT)
    assert cache.fetched_at("plugin", "cf7") == FETCHED_AT
    assert cache.fetched_at("plugin", "absent") is None


def test_json_reports_cve_source_cache_date_and_epss_age(tmp_path):
    results = _scan(tmp_path, FIXTURE)
    data = json.loads(JSONReporter(results, TARGET, {}).generate())
    ds = data["data_sources"]
    assert ds["cve"]["source"] == "wpvulnerability.net"
    assert ds["cve"]["entries"][0]["slug"] == "contact-form-7"
    assert ds["cve"]["entries"][0]["fetched_at"].startswith("2026-11-20")
    assert ds["cve"]["oldest_fetched_at"].startswith("2026-11-20")
    assert ds["epss"]["present"] is True
    assert ds["epss"]["snapshot_date"] == "2026-07-20"
    assert ds["epss"]["age_days"] == 125


def test_html_reports_cve_source_cache_date_and_epss_age(tmp_path):
    out = HTMLReporter(_scan(tmp_path, FIXTURE), TARGET, {}).generate()
    assert "wpvulnerability.net" in out
    assert "2026-11-20" in out
    assert "2026-07-20" in out
    assert "125 jours" in out


def test_epss_absent_is_said_not_silenced(tmp_path):
    results = _scan(tmp_path, tmp_path / "absent.csv")
    data = json.loads(JSONReporter(results, TARGET, {}).generate())
    assert data["data_sources"]["epss"]["present"] is False
    assert "EPSS absent" in data["data_sources"]["epss"]["label"]
    out = HTMLReporter(results, TARGET, {}).generate()
    assert "EPSS absent" in out


def test_reports_say_when_cve_database_was_not_consulted():
    from wp_security_forsure.scanner.checks.base import CheckResult
    r = st.set_status(CheckResult("ssl_tls", "TLS", "d", "INFO", True), st.STATUS_OK)
    data = json.loads(JSONReporter([r], TARGET, {}).generate())
    assert data["data_sources"]["cve"]["source"] == "wpvulnerability.net"
    assert data["data_sources"]["cve"]["entries"] == []
    assert "wpvulnerability.net" in HTMLReporter([r], TARGET, {}).generate()


def test_stale_cache_entry_is_flagged(tmp_path):
    cache = VulnCache(str(tmp_path / "vulncache.sqlite"))
    cache.put("plugin", "contact-form-7", PAYLOAD, now=int(time.time()) - 30 * 86400)
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"core": None, "themes": [], "plugins": [
        {"slug": "contact-form-7", "version": "5.2.0", "source": "readme"}]}}
    chk._cache = cache
    chk._client = lambda t, s: None   # réseau indisponible : fiche périmée servie
    chk._epss = load_epss(FIXTURE)
    result = st.set_status(chk.run(), st.STATUS_OK)
    data = json.loads(JSONReporter([result], TARGET, {}).generate())
    assert data["data_sources"]["cve"]["entries"][0]["stale"] is True
    assert data["data_sources"]["cve"]["stale_count"] == 1
