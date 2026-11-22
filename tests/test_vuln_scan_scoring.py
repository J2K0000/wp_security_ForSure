"""vulnerability_scan attache cvss/cve/epss au finding (chantier B)."""
from tests.conftest import make_check
from wp_security_forsure.scanner.checks.vulnerability_scan import VulnerabilityScanCheck


def _payload():
    return {"data": {"vulnerability": [{
        "name": "RCE plugin démo",
        "operator": {"max_version": "2.0", "max_operator": "lt"},
        "impact": {"cvss": {"score": "8.8", "vector": "CVSS:3.1/AV:N/AC:L"}},
        "source": [{"id": "CVE-2021-24145", "link": "https://x"}],
    }]}}


def test_finding_carries_cvss_cve_and_epss(tmp_path):
    epss_csv = tmp_path / "epss.csv"
    epss_csv.write_text("cve,epss,percentile\nCVE-2021-24145,0.9421,0.999\n",
                        encoding="utf-8")

    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"plugins": [
        {"slug": "demo", "version": "1.0", "source": "readme"}],
        "themes": [], "core": {}}}

    from wp_security_forsure.scanner.vulndb import epss as epss_mod

    class _Cache:
        def get_or_fetch(self, ctype, slug, client, ttl_days=7):
            return _payload(), False

    # Court-circuite le backend réseau : cache mocké + index EPSS de la fixture.
    def _fake_backend():
        chk._cache = _Cache()
        chk._epss = epss_mod.load_epss(epss_csv)
    chk._ensure_backend = _fake_backend

    result = chk.run()
    vuln_findings = [f for f in result.findings if f.get("scoring")]
    assert vuln_findings, "aucun finding avec scoring"
    sc = vuln_findings[0]["scoring"]
    assert sc["cvss"] == 8.8
    assert "CVE-2021-24145" in sc["cve_ids"]
    assert sc["epss"] == 0.9421


def test_finding_without_epss_snapshot_has_epss_none(tmp_path):
    # Pas de snapshot EPSS -> epss None, mais cvss/cve toujours présents.
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"plugins": [
        {"slug": "demo", "version": "1.0", "source": "readme"}],
        "themes": [], "core": {}}}

    from wp_security_forsure.scanner.vulndb import epss as epss_mod

    class _Cache:
        def get_or_fetch(self, ctype, slug, client, ttl_days=7):
            return _payload(), False

    def _fake_backend():
        chk._cache = _Cache()
        chk._epss = epss_mod.load_epss(tmp_path / "absent.csv")  # index vide
    chk._ensure_backend = _fake_backend

    result = chk.run()
    sc = [f for f in result.findings if f.get("scoring")][0]["scoring"]
    assert sc["cvss"] == 8.8
    assert sc["epss"] is None
