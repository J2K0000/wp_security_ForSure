import re

import responses
from wp_security_forsure.scanner.checks.wp_features import WPFeaturesCheck
from tests.conftest import make_check

NAMESPACE_ROOT_RESPONSE = """{
  "namespace": "wp-site-health/v1",
  "routes": {
    "/wp-site-health/v1/tests/background-updates": {},
    "/wp-site-health/v1/tests/loopback-requests": {},
    "/wp-site-health/v1/directory-sizes": {}
  }
}"""


@responses.activate
def test_site_health_namespace_root_is_info_not_critical():
    url = "https://cible.test/wp-json/wp-site-health/v1"
    responses.add(
        responses.GET,
        url,
        body=NAMESPACE_ROOT_RESPONSE,
        status=200,
        content_type="application/json",
    )

    chk = make_check(WPFeaturesCheck)
    chk._check_site_health()

    findings = chk._result.findings
    assert findings, "expected a finding for the namespace root"

    # No CRITICAL finding should come from the bare namespace-root exposure.
    assert not any(f["severity"] == "CRITICAL" for f in findings), findings

    root_finding = findings[0]
    assert root_finding["severity"] == "INFO"
    assert root_finding["confidence"] == "potential"
    assert "listing de routes public" in root_finding["message"]


@responses.activate
def test_site_health_test_endpoints_are_never_called():
    """Inversé : les sous-endpoints de test (chacun exécute un diagnostic côté
    serveur) ne sont plus appelés, même ouverts ; constat INFO « non évaluable
    de l'extérieur sans déclencher un traitement côté serveur »."""
    root_url = "https://cible.test/wp-json/wp-site-health/v1"
    responses.add(responses.GET, root_url, status=401, content_type="application/json",
                  body='{"code": "rest_forbidden"}')
    responses.add(responses.GET, re.compile(r".*/wp-site-health/v1/tests/.*"),
                  status=200, content_type="application/json",
                  body='{"status": "good"}')

    chk = make_check(WPFeaturesCheck)
    chk._check_site_health()

    assert not any("/tests/" in c.request.url for c in responses.calls)
    assert not any(f["severity"] in ("HIGH", "CRITICAL") for f in chk._result.findings)
    info = [f for f in chk._result.findings
            if "Points de test Site Health" in f["message"]]
    assert len(info) == 1 and info[0]["severity"] == "INFO"
    assert "sans déclencher un traitement côté serveur" in info[0]["message"]
    assert "à vérifier en mode authentifié" in info[0]["message"]
