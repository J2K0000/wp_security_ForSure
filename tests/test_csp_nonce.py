"""P9, CSP 'unsafe-inline' est neutralisé par un nonce/hash (ignoré par les
navigateurs conformes) → pas un CRITICAL."""
from wp_security_forsure.scanner.checks.security_headers import SecurityHeadersCheck
from tests.conftest import make_check


def _crit_unsafe(chk):
    return [f for f in chk._result.findings
            if f["severity"] == "CRITICAL" and "unsafe-inline" in f["message"]]


def test_unsafe_inline_with_nonce_not_critical():
    chk = make_check(SecurityHeadersCheck)
    chk._check_csp(
        {"Content-Security-Policy": "script-src 'self' 'nonce-abc123' 'unsafe-inline'"},
        "https://cible.test/")
    assert _crit_unsafe(chk) == []


def test_unsafe_inline_without_nonce_is_critical():
    chk = make_check(SecurityHeadersCheck)
    chk._check_csp(
        {"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"},
        "https://cible.test/")
    assert len(_crit_unsafe(chk)) == 1
