"""P1/P7-bis, fingerprint ne doit PAS confirmer de composants fantômes sur un
site soft-404 (sinon vulnerability_scan les transforme en CVE confirmées)."""
import re
import responses
from wp_security_forsure.scanner.checks.fingerprint import FingerprintCheck
from wp_security_forsure.scanner.checks import common_components
from tests.conftest import make_check

# Home renvoyée pour TOUTE URL (soft-404) et contenant un « Version: » parasite
# que l'ancien code capturait via readme/style.
GHOST_HOME = ("<!DOCTYPE html><html><head><title>Home</title></head><body>"
              "\nVersion: 9.9.9\n" + ("H" * 3000) + "</body></html>")


@responses.activate
def test_soft404_does_not_confirm_ghost_components(monkeypatch):
    monkeypatch.setattr(common_components, "COMMON_PLUGINS", ["contact-form-7", "woocommerce"])
    monkeypatch.setattr(common_components, "COMMON_THEMES", ["astra"])
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body=GHOST_HOME, status=200, content_type="text/html")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    assert inv["plugins"] == []
    assert inv["themes"] == []


@responses.activate
def test_real_plugin_still_confirmed(monkeypatch):
    monkeypatch.setattr(common_components, "COMMON_PLUGINS", ["contact-form-7"])
    monkeypatch.setattr(common_components, "COMMON_THEMES", [])
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body="404 Not Found", status=404)
    responses.add(responses.GET, "https://cible.test/",
                  body="<html><body>ok</body></html>", status=200, content_type="text/html")
    responses.add(responses.GET,
                  "https://cible.test/wp-content/plugins/contact-form-7/readme.txt",
                  body="=== Contact Form 7 ===\nStable tag: 5.9.0\n", status=200)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    plugins = {p["slug"]: p for p in chk.context["inventory"]["plugins"]}
    assert plugins.get("contact-form-7", {}).get("version") == "5.9.0"
