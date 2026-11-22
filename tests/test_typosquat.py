"""P4, les regex de typosquatting ne doivent PAS matcher les domaines légitimes
(orthographe correcte), seulement les variantes falsifiées."""
import re
from wp_security_forsure.scanner.checks.third_party_scripts import ThirdPartyScriptsCheck

LEGIT = [
    "cloudflare.com", "cdnjs.cloudflare.com", "challenges.cloudflare.com",
    "jsdelivr.net", "cdn.jsdelivr.net", "fastly.jsdelivr.net",
    "google.com", "www.google.com", "googleapis.com",
    "facebook.net", "connect.facebook.net", "paypal.com", "stripe.com", "js.stripe.com",
]


def test_legit_domains_are_not_typosquat():
    for _legit, squat, _desc in ThirdPartyScriptsCheck.TYPOSQUAT_PATTERNS:
        for dom in LEGIT:
            assert not re.search(squat, dom, re.IGNORECASE), (squat, dom)


def test_actual_typos_are_caught():
    # au moins une variante falsifiée matche encore
    joined = [squat for _l, squat, _d in ThirdPartyScriptsCheck.TYPOSQUAT_PATTERNS]
    assert any(re.search(s, "cl0udflare.com", re.I) for s in joined)
    assert any(re.search(s, "g00gle.com", re.I) for s in joined)
