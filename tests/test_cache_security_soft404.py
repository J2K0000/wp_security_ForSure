"""P1, cache_security ne signale pas de chemin de cache « accessible » sur soft-404."""
import re
import responses
from wp_security_forsure.scanner.checks.cache_security import CacheSecurityCheck
from tests.conftest import make_check

HOME = "<!DOCTYPE html><html><body>" + ("H" * 3000) + "</body></html>"


def _real(chk):
    return [f for f in chk._result.findings if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]


@responses.activate
def test_w3tc_dbcache_soft404_no_finding():
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"), body=HOME, status=200)
    chk = make_check(CacheSecurityCheck)
    chk._check_w3tc_dbcache_exposure()
    assert _real(chk) == []
