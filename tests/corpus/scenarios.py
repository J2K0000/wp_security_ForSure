"""Corpus de validation : scénarios vulnérables connus + constats attendus.

Chaque scénario est une fonction `run(monkeypatch) -> CheckResult` (elle monte
ses propres mocks déterministes) et un prédicat sur `result.findings`. Le test
`test_corpus.py` exécute chaque scénario et vérifie que le constat attendu est
présent (mesure de rappel). Ajouter des scénarios ici étend la couverture.
"""
import re

import responses

from tests.conftest import make_check


def _has(findings, needle, severity=None):
    for f in findings:
        if needle in f["message"].lower() and (severity is None or f["severity"] == severity):
            return True
    return False


# ---- Scénario : SPF + DMARC absents -----------------------------------------
def scenario_email_auth_absent(monkeypatch):
    from wp_security_forsure.scanner.checks import email_auth as ea_mod
    from wp_security_forsure.scanner.checks.email_auth import EmailAuthCheck
    monkeypatch.setattr(ea_mod, "_resolve_txt", lambda name: [])
    return make_check(EmailAuthCheck, target="https://cible-demo.com").run()


# ---- Scénario : plugin avec CVE connue --------------------------------------
def scenario_known_cve(monkeypatch):
    from wp_security_forsure.scanner.checks.vulnerability_scan import VulnerabilityScanCheck
    from wp_security_forsure.scanner.vulndb import epss as epss_mod
    payload = {"data": {"vulnerability": [{
        "name": "RCE plugin démo",
        "operator": {"max_version": "2.0", "max_operator": "lt"},
        "impact": {"cvss": {"score": "8.8", "vector": "CVSS:3.1/AV:N"}},
        "source": [{"id": "CVE-2021-24145", "link": "https://x"}],
    }]}}
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"plugins": [
        {"slug": "demo", "version": "1.0", "source": "readme"}], "themes": [], "core": {}}}

    class _Cache:
        def get_or_fetch(self, ctype, slug, client, ttl_days=7):
            return payload, False
    def _fake():
        chk._cache = _Cache()
        chk._epss = epss_mod.load_epss("does-not-exist.csv")
    monkeypatch.setattr(chk, "_ensure_backend", _fake)
    return chk.run()


# ---- Scénario : wp-config.php.bak exposé (fuite de credentials) ------------
_FE_TARGET = "https://cible-demo.com"
_FE_EXPOSED_URL = f"{_FE_TARGET}/wp-config.php.bak"
_FE_SECRET_BODY = (
    "<?php\ndefine('DB_NAME','wp');\ndefine('DB_PASSWORD','s3cr3t');\n" + ("X" * 200)
)


def scenario_file_exposure_wpconfig(monkeypatch):
    from wp_security_forsure.scanner.checks.file_exposure import FileExposureCheck
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        # Sonde soft-404 (base.py::_soft404_baseline) : chemin aléatoire absent -> 404.
        rsps.add(responses.HEAD, re.compile(r".*/wpsf-probe.*"), status=404)
        rsps.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                 body="404 Not Found", status=404)
        # Le seul fichier réellement exposé : wp-config.php.bak, contenu réel.
        rsps.add(responses.HEAD, _FE_EXPOSED_URL, status=200)
        rsps.add(responses.GET, _FE_EXPOSED_URL, body=_FE_SECRET_BODY, status=200)
        # Catch-all : tous les autres chemins sensibles testés par le check -> absents.
        rsps.add(responses.HEAD, re.compile(re.escape(_FE_TARGET) + r"/.*"), status=404)
        rsps.add(responses.GET, re.compile(re.escape(_FE_TARGET) + r"/.*"),
                 body="404 Not Found", status=404)
        chk = make_check(FileExposureCheck, target=_FE_TARGET)
        return chk.run()


# TODO scénario rest_api (énumération d'utilisateurs via /wp-json/wp/v2/users) :
# nécessite en plus de mocker la pagination éventuelle du endpoint -> reporté pour
# rester sur un corpus 100% déterministe (le scénario file_exposure ci-dessus
# couvre déjà la surface HTTP + soft-404 baseline).


# ---- Scénario : cookie d'authentification sans Secure/HttpOnly ------------
_CS_TARGET = "https://cible-demo.com"


def scenario_cookies_sessions_insecure(monkeypatch):
    from wp_security_forsure.scanner.checks.cookies_sessions import CookiesSessionsCheck
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.GET, f"{_CS_TARGET}/", body="<html></html>", status=200,
                 headers=[("Set-Cookie", "wordpress_logged_in_x=abc; Path=/")])
        rsps.add(responses.GET, f"{_CS_TARGET}/wp-login.php",
                 body="<html></html>", status=200)
        rsps.add(responses.GET, f"{_CS_TARGET}/wp-admin/admin-ajax.php",
                 body="", status=200)
        rsps.add(responses.GET, f"{_CS_TARGET}/wp-json/wp/v2/users/me",
                 body="{}", status=200)
        return make_check(CookiesSessionsCheck, target=_CS_TARGET).run()


# ---- Scénario : Cloudflare détecté via en-têtes ----------------------------
_WC_TARGET = "https://cible-demo.com"


def scenario_waf_cdn_cloudflare(monkeypatch):
    from wp_security_forsure.scanner.checks.waf_cdn import WafCdnCheck
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.HEAD, f"{_WC_TARGET}/",
                 headers={"cf-ray": "abcd1234-CDG", "Server": "cloudflare"}, status=200)
        rsps.add(responses.GET, f"{_WC_TARGET}/", body="<html></html>", status=200)
        rsps.add(responses.GET, f"{_WC_TARGET}/wp-login.php",
                 body="<html></html>", status=200)
        rsps.add(responses.GET, re.compile(re.escape(_WC_TARGET) + r"/.+"),
                 body="<html></html>", status=200)
        return make_check(WafCdnCheck, target=_WC_TARGET).run()


# ---- Scénario : CSP absente -------------------------------------------------
_SH_TARGET = "https://cible-demo.com"


def scenario_security_headers_missing_csp(monkeypatch):
    from wp_security_forsure.scanner.checks.security_headers import SecurityHeadersCheck
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.HEAD, f"{_SH_TARGET}/", status=200)
        return make_check(SecurityHeadersCheck, target=_SH_TARGET).run()


# Registre : (id, fonction_run, prédicat(findings)->bool)
SCENARIOS = [
    ("email_auth:spf-dmarc-absents", scenario_email_auth_absent,
     lambda fs: _has(fs, "spf", "MEDIUM") and _has(fs, "dmarc", "MEDIUM")),
    ("vulnerability_scan:cve-connue", scenario_known_cve,
     lambda fs: any((f.get("scoring") or {}).get("cvss") == 8.8 for f in fs)),
    ("file_exposure:wp-config-expose", scenario_file_exposure_wpconfig,
     lambda fs: _has(fs, "wp-config", "CRITICAL")),
    ("cookies_sessions:cookie-non-secure", scenario_cookies_sessions_insecure,
     lambda fs: _has(fs, "missing secure flag", "CRITICAL")),
    ("waf_cdn:cloudflare-detecte", scenario_waf_cdn_cloudflare,
     lambda fs: _has(fs, "cloudflare detected", "INFO")),
    ("security_headers:csp-absente", scenario_security_headers_missing_csp,
     lambda fs: _has(fs, "content-security-policy) header is missing", "HIGH")),
]
