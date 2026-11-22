"""vulnerability_scan porte un narratif d'attaquant sur chaque CVE (chantier A+B).

Chaine : version detectable de l'exterieur (source du fingerprint) -> CVE
publique -> exploitabilite reelle (EPSS) -> ce que l'attaquant obtient. Sert
add_finding(access_class=..., impact={data,path,enables}) avec des donnees
deja disponibles au moment du matching (pas de nouvel appel reseau).
"""
from tests.conftest import make_check
from wp_security_forsure.scanner.checks.vulnerability_scan import VulnerabilityScanCheck


def _payload(score):
    return {"data": {"vulnerability": [{
        "name": "RCE plugin démo",
        "operator": {"max_version": "2.0", "max_operator": "lt"},
        "impact": {"cvss": {"score": str(score), "vector": "CVSS:3.1/AV:N/AC:L"}},
        "source": [{"id": "CVE-2021-24145", "link": "https://x"}],
    }]}}


def _make(tmp_path, score, epss_rows=None, source="generator"):
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"plugins": [
        {"slug": "demo", "version": "1.0", "source": source}],
        "themes": [], "core": {}}}

    from wp_security_forsure.scanner.vulndb import epss as epss_mod

    class _Cache:
        def get_or_fetch(self, ctype, slug, client, ttl_days=7):
            return _payload(score), False

    epss_csv = tmp_path / "epss.csv"
    if epss_rows:
        header = "cve,epss,percentile\n"
        body = "\n".join(f"{cve},{val},0.9" for cve, val in epss_rows)
        epss_csv.write_text(header + body + "\n", encoding="utf-8")

    def _fake_backend():
        chk._cache = _Cache()
        chk._epss = epss_mod.load_epss(epss_csv)
    chk._ensure_backend = _fake_backend
    return chk


def _vuln_finding(result):
    fs = [f for f in result.findings if f.get("scoring")]
    assert fs, "aucun finding avec scoring"
    return fs[0]


def test_critical_high_epss_carries_controle_and_epss_narrative(tmp_path):
    chk = _make(tmp_path, 9.8, epss_rows=[("CVE-2021-24145", 0.9421)], source="generator")
    result = chk.run()
    f = _vuln_finding(result)

    assert f["access_class"] == "controle"
    imp = f["impact"]
    assert "generator" in imp["path"].lower() or "balise generator" in imp["path"].lower()
    assert "CVE-2021-24145" in imp["path"]
    assert "activement exploitée" in imp["enables"]
    assert "94" in imp["enables"] or "0.94" in imp["enables"]


def test_medium_cvss_is_prive_not_controle(tmp_path):
    chk = _make(tmp_path, 5.0, epss_rows=None, source="readme")
    result = chk.run()
    f = _vuln_finding(result)

    assert f["access_class"] == "prive"


def test_no_epss_snapshot_has_no_epss_clause_but_sensible_outcome(tmp_path):
    chk = _make(tmp_path, 9.8, epss_rows=None, source="rest_namespace")
    result = chk.run()
    f = _vuln_finding(result)

    assert f["access_class"] == "controle"
    imp = f["impact"]
    assert "EPSS" not in imp["enables"]
    assert "activement exploitée" not in imp["enables"]
    assert imp["enables"]  # narratif toujours present


def test_impact_data_includes_component_version_and_title(tmp_path):
    chk = _make(tmp_path, 9.8, epss_rows=None, source="generator")
    result = chk.run()
    f = _vuln_finding(result)

    imp = f["impact"]
    assert "demo" in imp["data"]
    assert "1.0" in imp["data"]
    assert "RCE plugin démo" in imp["data"]


def test_low_cvss_is_recon(tmp_path):
    chk = _make(tmp_path, 2.0, epss_rows=None, source="readme")
    result = chk.run()
    f = _vuln_finding(result)

    assert f["access_class"] == "recon"
