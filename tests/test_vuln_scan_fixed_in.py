"""vulnerability_scan : « Corrigé dans » n'affiche jamais la dernière version
vulnérable, et une fiche à l'opérateur inconnu est « non appariée, à vérifier »."""
from tests.conftest import make_check
from wp_security_forsure.scanner.checks.vulnerability_scan import VulnerabilityScanCheck


class _FakeCache:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_or_fetch(self, type_, slug, client, ttl_days=7, now=None):
        return self.mapping.get(slug), False


def _payload(operator):
    return {"data": {"vulnerability": [{
        "name": "CF7 faille", "operator": operator,
        "source": [{"id": "CVE-2020-35489", "link": "https://x"}],
        "impact": {"cvss": {"score": "7.2", "vector": "v"}},
    }]}}


def _findings(operator, version="5.3.2"):
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"core": None, "themes": [], "plugins": [
        {"slug": "contact-form-7", "version": version, "source": "readme"}]}}
    chk._cache = _FakeCache({"contact-form-7": _payload(operator)})
    chk._client = lambda t, s: None
    chk.run()
    return chk.result.findings


def test_inclusive_bound_does_not_claim_fixed_version():
    findings = _findings({"max_version": "5.3.2", "max_operator": "le"})
    vuln = [f for f in findings if "CVE-2020-35489" in f["evidence"]][0]
    assert "Corrigé dans : 5.3.2" not in vuln["evidence"]
    assert "corrigé après 5.3.2 (version exacte inconnue)" in vuln["evidence"]


def test_strict_bound_gives_fixed_version():
    findings = _findings({"max_version": "5.3.3", "max_operator": "lt"})
    vuln = [f for f in findings if "CVE-2020-35489" in f["evidence"]][0]
    assert "Corrigé dans : 5.3.3" in vuln["evidence"]


def test_unknown_operator_is_flagged_not_vulnerable():
    findings = _findings({"max_version": "5.3.2", "max_operator": "eq"})
    flagged = [f for f in findings if "CVE-2020-35489" in f["evidence"]]
    assert len(flagged) == 1
    f = flagged[0]
    assert f["severity"] == "INFO"
    assert f["confidence"] == "potential"
    assert "non appariée, à vérifier" in f["message"]
    assert "eq" in f["evidence"]
