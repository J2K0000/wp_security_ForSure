"""P4/P9, crypto-miner : termes génériques retirés ; .htaccess : règles WP par
défaut ne sont pas « malveillantes »."""
import re
import responses
from wp_security_forsure.scanner.checks.third_party_scripts import ThirdPartyScriptsCheck
from wp_security_forsure.scanner.checks.malware_detection import MalwareDetectionCheck
from tests.conftest import make_check


def test_crypto_patterns_drop_generic_terms():
    pats = [p.lower() for p in ThirdPartyScriptsCheck.CRYPTO_MINER_INLINE_PATTERNS]
    # Termes ubiquitaires en JS légitime → retirés
    for generic in (r"\bthrottle\b", r"\bhashrate\b", "isrunning", "miner",
                    "anonymous", "sitekey", "_client"):
        assert generic not in pats
    # Signatures fortes conservées
    assert any("cryptonight" in p for p in pats)
    assert any("coinimp" in p or "coinhive" in p for p in pats)


WP_DEFAULT_HTACCESS = (
    "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\n"
    "RewriteBase /\nRewriteRule ^index\\.php$ - [L]\n"
    "RewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\n"
    "RewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n"
)


@responses.activate
def test_wp_default_htaccess_not_critical():
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"), body="404", status=404)
    responses.add(responses.GET, "https://cible.test/.htaccess",
                  body=WP_DEFAULT_HTACCESS, status=200)
    chk = make_check(MalwareDetectionCheck)
    chk._check_htaccess()
    assert not any(f["severity"] == "CRITICAL" for f in chk._result.findings)


@responses.activate
def test_htaccess_external_redirect_is_critical():
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"), body="404", status=404)
    responses.add(responses.GET, "https://cible.test/.htaccess",
                  body="RewriteRule (.*) http://evil.example/$1 [R,L]\n", status=200)
    chk = make_check(MalwareDetectionCheck)
    chk._check_htaccess()
    assert any(f["severity"] == "CRITICAL" for f in chk._result.findings)
