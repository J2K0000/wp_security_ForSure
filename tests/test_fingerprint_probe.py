import responses
from wp_security_forsure.scanner.checks.fingerprint import FingerprintCheck
from wp_security_forsure.scanner.checks import common_components
from tests.conftest import make_check

# Home "cache-optimisée" : AUCUN chemin /wp-content/plugins|themes/ visible.
HOME = ("<html><head><meta name='generator' content='WordPress 6.4.3'/>"
        "<link rel='stylesheet' href='https://cible.test/wp-content/cache/min/1/combined.css?ver=x'/>"
        "</head><body>ok</body></html>")


@responses.activate
def test_active_probe_finds_hidden_plugin(monkeypatch):
    # liste réduite pour le test
    monkeypatch.setattr(common_components, "COMMON_PLUGINS", ["contact-form-7", "akismet"])
    monkeypatch.setattr(common_components, "COMMON_THEMES", ["astra"])
    responses.add(responses.GET, "https://cible.test/", body=HOME, status=200,
                  content_type="text/html; charset=UTF-8")
    # cf7 présent (readme.txt 200), akismet absent (404)
    responses.add(responses.GET,
                  "https://cible.test/wp-content/plugins/contact-form-7/readme.txt",
                  body="Stable tag: 5.2.0\n", status=200)
    responses.add(responses.GET,
                  "https://cible.test/wp-content/plugins/akismet/readme.txt", status=404)
    responses.add(responses.GET,
                  "https://cible.test/wp-content/themes/astra/style.css", status=404)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    plugins = {p["slug"]: p for p in inv["plugins"]}
    assert "contact-form-7" in plugins
    assert plugins["contact-form-7"]["version"] == "5.2.0"
    assert plugins["contact-form-7"]["source"] == "readme"   # confirmé -> vulnerability_scan le traitera en confirmed
    assert "akismet" not in plugins
