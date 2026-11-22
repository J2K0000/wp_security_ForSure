"""P1, database_exposure ne signale rien sur un site soft-404 (via _head_then_get)."""
import re
import responses
from wp_security_forsure.scanner.checks.database_exposure import DatabaseExposureCheck
from tests.conftest import make_check

HOME = "<!DOCTYPE html><html><body>" + ("H" * 3000) + "</body></html>"
ADMINER = "<html><title>Login - Adminer</title> auth[driver] auth[server] </html>" + ("x" * 200)


def _real(chk):
    return [f for f in chk._result.findings if f["severity"] != "INFO"]


@responses.activate
def test_phpmyadmin_soft404_no_finding():
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"), body=HOME, status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_phpmyadmin()
    assert _real(chk) == []


@responses.activate
def test_phpmyadmin_real_adminer_is_flagged():
    responses.add(responses.HEAD, re.compile(r".*/wpsf-probe.*"), status=404)
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"), body="404", status=404)
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"), body=ADMINER, status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_phpmyadmin()
    assert any(f["severity"] == "CRITICAL" for f in chk._result.findings)
