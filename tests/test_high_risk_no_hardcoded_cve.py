import re
import inspect
from wp_security_forsure.scanner.checks import high_risk_plugins as hrp


def test_no_hardcoded_cve_strings():
    src = inspect.getsource(hrp)
    # plus aucune CVE en dur dans ce module (matching CVE délégué à vulnerability_scan)
    assert not re.search(r"CVE-\d{4}-\d+", src)
