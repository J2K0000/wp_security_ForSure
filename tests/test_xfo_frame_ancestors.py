"""P9, X-Frame-Options manquant n'est pas un HIGH clickjacking si la CSP
définit frame-ancestors (protection moderne équivalente)."""
from wp_security_forsure.scanner.checks.security_headers import SecurityHeadersCheck
from tests.conftest import make_check


def _high_xfo(chk):
    return [f for f in chk._result.findings
            if f["severity"] == "HIGH" and "X-Frame-Options" in f["message"]]


def test_xfo_missing_without_csp_is_high():
    chk = make_check(SecurityHeadersCheck)
    chk._check_x_frame_options({}, "https://cible.test/")
    assert len(_high_xfo(chk)) == 1


def test_xfo_missing_with_frame_ancestors_not_high():
    chk = make_check(SecurityHeadersCheck)
    chk._check_x_frame_options(
        {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"},
        "https://cible.test/")
    assert _high_xfo(chk) == []
