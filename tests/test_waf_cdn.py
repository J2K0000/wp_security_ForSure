"""waf_cdn, détection de WAF/CDN (Cloudflare, Sucuri, Fastly, Akamai,
ModSecurity, Wordfence, générique, rate limiting, CDN géographique).

Détection PASSIVE : run() ne lit que des pages servies normalement (home,
wp-login.php) et envoie 3 GET de la home pour le rate limiting. Aucune charge
d'attaque, aucun en-tête malformé, aucune requête TRACE. TOUT le trafic HTTP est
mocké via `responses` (catch-all compris) pour rester déterministe et hors
réseau.
"""
import re

import responses
from responses import matchers

from wp_security_forsure.scanner.checks.waf_cdn import WafCdnCheck
from tests.conftest import make_check

# Matcher forçant une correspondance EXACTE sur "/" sans query string : évite
# qu'une réponse enregistrée pour HOME soit consommée par une sonde payload
# (SQLi/XSS/path traversal) qui cible en réalité "/" + query string, celles-ci
# doivent tomber sur le catch-all regex ci-dessous.
_NO_QUERY = [matchers.query_string_matcher("")]

TARGET = "https://cible.test"
HOME = f"{TARGET}/"
LOGIN = f"{TARGET}/wp-login.php"

_CLEAN_BODY = "<html><head><title>OK</title></head><body>Bienvenue</body></html>"


def _register_baseline(head_headers=None, get_headers=None,
                        home_body=_CLEAN_BODY, home_status=200,
                        login_body=_CLEAN_BODY, login_status=200,
                        catch_body=None, catch_status=200):
    """Mocke tout le trafic qu'un run() complet peut émettre.

    HEAD "/" -> `head_headers` ; GET "/" -> `get_headers`/`home_body` ;
    GET "/wp-login.php" -> `login_body` ; catch-all GET pour les sondes
    payload (SQLi/XSS/path traversal) et le rate-limiting (mêmes URLs,
    mémoïsées par le cache de BaseCheck.http_get).
    """
    responses.add(responses.HEAD, HOME, headers=head_headers or {}, status=200)
    # match=_NO_QUERY : sans ça, `responses` matche aussi HOME sur des URLs
    # "/" + query string (ignore la query par défaut). Comme le catch-all
    # ci-dessous matche également ces mêmes URLs, la présence des deux matches
    # fait que `responses` retire silencieusement l'entrée HOME de son
    # registre dès qu'une sonde payload (query string) est envoyée après un
    # premier GET "/" simple, cassant les appels "/" simples suivants (ex:
    # boucle de rate-limiting, sonde headers= ModSecurity). Voir
    # responses/registries.py::FirstMatchRegistry.find.
    responses.add(responses.GET, HOME, body=home_body,
                   headers=get_headers or {}, status=home_status,
                   match=_NO_QUERY)
    responses.add(responses.GET, LOGIN, body=login_body, status=login_status)
    responses.add(
        responses.GET, re.compile(re.escape(TARGET) + r"/.+"),
        body=catch_body if catch_body is not None else _CLEAN_BODY,
        status=catch_status,
    )


def _mk():
    return make_check(WafCdnCheck, target=TARGET)


def _named(findings, needle):
    return [f for f in findings if needle.lower() in f["message"].lower()]


# ---------------------------------------------------------------------------
# Vendors, détection via en-têtes / cookies / corps de page
# ---------------------------------------------------------------------------

@responses.activate
def test_cloudflare_detected_via_headers():
    _register_baseline(head_headers={"cf-ray": "abcd1234-CDG", "Server": "cloudflare"})
    chk = _mk()
    result = chk.run()

    cf = _named(result.findings, "cloudflare detected")
    assert cf, result.findings
    assert cf[0]["severity"] == "INFO"
    assert "cf-ray" in cf[0]["evidence"]


@responses.activate
def test_sucuri_detected_via_headers():
    _register_baseline(head_headers={"X-Sucuri-ID": "12345", "X-Sucuri-Cache": "HIT"})
    chk = _mk()
    result = chk.run()

    sucuri = _named(result.findings, "sucuri detected")
    assert sucuri, result.findings
    assert sucuri[0]["severity"] == "INFO"
    assert "X-Sucuri-ID" in sucuri[0]["evidence"]


@responses.activate
def test_fastly_detected_via_headers():
    _register_baseline(head_headers={"X-Served-By": "cache-cdg1234", "X-Cache": "HIT"})
    chk = _mk()
    result = chk.run()

    fastly = _named(result.findings, "fastly detected")
    assert fastly, result.findings
    assert fastly[0]["severity"] == "INFO"


@responses.activate
def test_akamai_detected_via_headers():
    _register_baseline(head_headers={"Server": "AkamaiGHost"})
    chk = _mk()
    result = chk.run()

    akamai = _named(result.findings, "akamai detected")
    assert akamai, result.findings
    assert akamai[0]["severity"] == "INFO"


@responses.activate
def test_wordfence_detected_via_cookie():
    _register_baseline(head_headers={"Set-Cookie": "wfvt_1234=abcd; Path=/"})
    chk = _mk()
    result = chk.run()

    wf = _named(result.findings, "wordfence detected")
    assert wf, result.findings
    assert "wfvt_" in wf[0]["message"] or "wfvt_" in wf[0]["evidence"]


@responses.activate
def test_wordfence_detected_via_block_page():
    _register_baseline(login_body="<html><body>Blocked by Wordfence</body></html>")
    chk = _mk()
    result = chk.run()

    wf = _named(result.findings, "wordfence detected")
    assert wf, result.findings
    assert "block page" in wf[0]["message"]


@responses.activate
def test_modsecurity_detected_via_sec_headers():
    _register_baseline(get_headers={"X-Mod-Security": "Active"})
    chk = _mk()
    result = chk.run()

    modsec = _named(result.findings, "modsecurity detected")
    assert modsec, result.findings
    assert modsec[0]["severity"] == "INFO"


@responses.activate
def test_run_sends_no_trace_no_payload_no_malformed_header():
    """Ancienne sonde active (TRACE, SQLi/XSS/traversée, Accept invalide) :
    plus rien de tout cela ne part. Uniquement des GET/HEAD sur des pages
    normales, sans query string ni en-tête Accept trafiqué."""
    _register_baseline()
    responses.add("TRACE", HOME, status=405)

    chk = _mk()
    chk.run()

    assert {c.request.method for c in responses.calls} <= {"GET", "HEAD"}
    for c in responses.calls:
        url = c.request.url
        assert "?" not in url, url
        assert "invalid-mime-type" not in c.request.headers.get("Accept", "")
        for needle in ("<script", "%3cscript", "' or '", "%27", "../", "etc/passwd"):
            assert needle not in url.lower(), url


@responses.activate
def test_cdn_geographic_headers_detected():
    _register_baseline(head_headers={"Vary": "Accept-Encoding, Cookie", "X-Geo": "CDG"})
    chk = _mk()
    result = chk.run()

    geo = _named(result.findings, "cdn geographic")
    assert geo, result.findings
    assert geo[0]["severity"] == "INFO"


# ---------------------------------------------------------------------------
# Détection générique (comparaison payload vs baseline) et challenge pages
# ---------------------------------------------------------------------------

@responses.activate
def test_generic_waf_no_longer_inferred_from_payload_responses():
    """Les URL hors home répondent 403 : sans sonde payload, aucun « Generic
    WAF detected » ne peut plus être déduit d'un écart de statut."""
    _register_baseline(catch_status=403, catch_body="Forbidden")
    chk = _mk()
    result = chk.run()

    assert _named(result.findings, "generic waf detected") == []


@responses.activate
def test_challenge_page_vendor_marker_detected():
    _register_baseline(
        home_body="<html><body><script>window._cf_chl_opt={cType:'managed'};"
                  "</script><div id='challenge-platform'></div></body></html>",
    )
    chk = _mk()
    result = chk.run()

    challenge = _named(result.findings, "challenge page")
    assert challenge, result.findings
    assert "challenge-platform" in challenge[0]["evidence"].lower()


@responses.activate
def test_captcha_word_is_not_read_as_a_waf():
    """Un widget reCAPTCHA de formulaire ou un faux CAPTCHA (ClickFix) ne
    prouvent pas un WAF : les présenter comme une protection rassure à tort."""
    _register_baseline(
        home_body="<html><body>Please solve the "
                  "<div class='g-recaptcha'></div> captcha. Verify you are "
                  "human: press Windows + R</body></html>",
    )
    chk = _mk()
    result = chk.run()

    assert _named(result.findings, "challenge page") == []


@responses.activate
def test_rate_limiting_probe_sends_no_burst():
    """Plus de rafale de 3 requêtes vers l'accueil pour provoquer un 429 :
    chercher à déclencher la protection du site fait bannir l'adresse de
    l'audit. Un 429 reçu pendant l'audit l'arrête (tests/test_target_guard.py)."""
    _register_baseline(home_status=200)
    chk = _mk()
    chk.run()
    home_gets = [c for c in responses.calls
                 if c.request.method == "GET" and c.request.url.rstrip("/") == HOME.rstrip("/")]
    assert len(home_gets) <= 1, [c.request.url for c in responses.calls]


@responses.activate
def test_clean_site_yields_no_findings():
    _register_baseline()
    chk = _mk()
    result = chk.run()

    assert result.findings == []
    assert result.passed is True
