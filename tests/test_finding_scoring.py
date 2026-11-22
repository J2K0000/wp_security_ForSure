"""Le finding porte un dict scoring (cvss/cve/epss) et le JSON le propage."""
import json
from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter


def _result():
    return CheckResult(check_name="vulnerability_scan", title="CVE",
                       description="", severity="HIGH", passed=True)


def test_add_finding_stores_scoring_when_present():
    r = _result()
    sc = {"cvss": 8.8, "cvss_vector": "CVSS:3.1/AV:N", "cve_ids": ["CVE-1"],
          "epss": 0.42}
    r.add_finding("plugin x vulnérable", severity="HIGH", scoring=sc)
    assert r.findings[0]["scoring"] == sc


def test_add_finding_omits_scoring_when_absent():
    r = _result()
    r.add_finding("rien", severity="LOW")
    assert "scoring" not in r.findings[0]


def test_json_reporter_serializes_scoring():
    r = _result()
    r.add_finding("plugin x vulnérable", severity="HIGH",
                  scoring={"cvss": 8.8, "cvss_vector": "V", "cve_ids": ["CVE-1"],
                           "epss": 0.42})
    data = json.loads(JSONReporter([r], "https://cible.test", {}).generate())
    entry = data["results"][0]["findings"][0]
    assert entry["scoring"]["cvss"] == 8.8
    assert entry["scoring"]["epss"] == 0.42
