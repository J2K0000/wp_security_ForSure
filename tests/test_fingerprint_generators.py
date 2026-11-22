"""Détection passive de plugins (avec version) via les balises
<meta name="generator"> qu'ils s'attribuent eux-mêmes (Yoast, WooCommerce,
Elementor, Slider Revolution, Rank Math...). Lue depuis le HTML de la home
déjà récupéré par fingerprint, aucune requête supplémentaire.

Les listes COMMON_PLUGINS/COMMON_THEMES sont vidées par monkeypatch dans
chaque test : sans ce blindage, la sonde active _probe_common() pourrait
trouver certains de ces mêmes slugs (woocommerce, wordpress-seo...) toute
seule et les tests passeraient même sans l'implémentation generator, ce
qui ne prouverait rien (cf. test_fingerprint_rest.py)."""
import responses
from wp_security_forsure.scanner.checks.fingerprint import FingerprintCheck
from wp_security_forsure.scanner.checks import common_components
from tests.conftest import make_check


def _no_common_probe(monkeypatch):
    monkeypatch.setattr(common_components, "COMMON_PLUGINS", [])
    monkeypatch.setattr(common_components, "COMMON_THEMES", [])


def _home(body):
    return responses.add(
        responses.GET, "https://cible.test/", body=body, status=200,
        content_type="text/html; charset=UTF-8")


@responses.activate
def test_yoast_generator_gives_confirmed_version(monkeypatch):
    _no_common_probe(monkeypatch)
    html = """<html><head>
    <meta name="generator" content="Yoast SEO 21.5" />
    </head><body>ok</body></html>"""
    _home(html)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    plugins = {p["slug"]: p for p in inv["plugins"]}
    assert "wordpress-seo" in plugins
    assert plugins["wordpress-seo"]["version"] == "21.5"
    assert plugins["wordpress-seo"]["source"] == "generator"


@responses.activate
def test_elementor_and_elementor_pro_both_detected(monkeypatch):
    _no_common_probe(monkeypatch)
    html = """<html><head>
    <meta name="generator" content="Elementor 3.16.0; features: e_dom_optimization, Elementor Pro 3.16.0" />
    </head><body>ok</body></html>"""
    _home(html)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    plugins = {p["slug"]: p for p in inv["plugins"]}
    assert plugins["elementor"]["version"] == "3.16.0"
    assert plugins["elementor"]["source"] == "generator"
    assert plugins["elementor-pro"]["version"] == "3.16.0"
    assert plugins["elementor-pro"]["source"] == "generator"


@responses.activate
def test_name_only_generator_has_no_version(monkeypatch):
    _no_common_probe(monkeypatch)
    html = """<html><head>
    <meta name="generator" content="Rank Math WordPress SEO plugin - https://rankmath.com/" />
    </head><body>ok</body></html>"""
    _home(html)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    plugins = {p["slug"]: p for p in inv["plugins"]}
    assert "seo-by-rank-math" in plugins
    assert plugins["seo-by-rank-math"]["version"] is None


@responses.activate
def test_core_generator_alone_creates_no_phantom_plugin(monkeypatch):
    _no_common_probe(monkeypatch)
    html = """<html><head>
    <meta name="generator" content="WordPress 6.4.2" />
    </head><body>ok</body></html>"""
    _home(html)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    assert inv["core"]["version"] == "6.4.2"
    assert inv["plugins"] == []


@responses.activate
def test_generator_upgrades_versionless_plugin_found_via_html_asset(monkeypatch):
    _no_common_probe(monkeypatch)
    # WooCommerce visible via un asset HTML sans ?ver= (donc version=None,
    # source=None après _collect) ET annoncé par sa balise generator.
    html = """<html><head>
    <meta name="generator" content="WooCommerce 8.2.1" />
    <script src="https://cible.test/wp-content/plugins/woocommerce/assets/js/frontend.js"></script>
    </head><body>ok</body></html>"""
    _home(html)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    plugins = {p["slug"]: p for p in inv["plugins"]}
    assert plugins["woocommerce"]["version"] == "8.2.1"
    assert plugins["woocommerce"]["source"] == "generator"
    # Une seule entrée woocommerce, pas de doublon.
    assert len([p for p in inv["plugins"] if p["slug"] == "woocommerce"]) == 1


@responses.activate
def test_generator_does_not_downgrade_already_confirmed_version(monkeypatch):
    _no_common_probe(monkeypatch)
    # contact-form-7 confirmé via readme.txt (source "readme") ; un
    # générateur annonçant une autre version ne doit PAS l'écraser.
    html = """<html><head>
    <meta name="generator" content="WooCommerce 8.2.1" />
    <link rel="stylesheet" href="https://cible.test/wp-content/plugins/woocommerce/style.css?ver=1.0.0" />
    </head><body>ok</body></html>"""
    _home(html)
    responses.add(
        responses.GET,
        "https://cible.test/wp-content/plugins/woocommerce/readme.txt",
        body="=== WooCommerce ===\nStable tag: 8.1.0\n", status=200)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    plugins = {p["slug"]: p for p in inv["plugins"]}
    # La version confirmée par readme.txt (8.1.0, source "readme") l'emporte
    # sur celle annoncée par la balise generator (8.2.1).
    assert plugins["woocommerce"]["version"] == "8.1.0"
    assert plugins["woocommerce"]["source"] == "readme"
