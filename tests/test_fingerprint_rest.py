"""Découverte passive de plugins via les namespaces REST /wp-json.
Un plugin peut être invisible dans le HTML de la home (assets chargés
conditionnellement, cache agressif) mais son namespace REST reste exposé
par défaut, un attaquant énumère /wp-json pour ça, on doit faire pareil.

Les listes COMMON_PLUGINS/COMMON_THEMES sont vidées par monkeypatch dans
chaque test : plusieurs des slugs utilisés ici (woocommerce, wordpress-seo,
contact-form-7...) y figurent déjà, donc sans ce blindage la sonde active
_probe_common() les trouverait toute seule et les tests passeraient même
sans l'implémentation REST, ce qui ne prouverait rien."""
import responses
from wp_security_forsure.scanner.checks.fingerprint import FingerprintCheck
from wp_security_forsure.scanner.checks import common_components
from tests.conftest import make_check

# Home sans aucune référence /wp-content/plugins|themes/, le passif HTML seul
# ne doit rien trouver.
BARE_HOME = "<html><head></head><body>ok</body></html>"


def _no_common_probe(monkeypatch):
    monkeypatch.setattr(common_components, "COMMON_PLUGINS", [])
    monkeypatch.setattr(common_components, "COMMON_THEMES", [])


def _wpjson(namespaces, status=200):
    return responses.Response(
        method=responses.GET,
        url="https://cible.test/wp-json",
        json={"namespaces": namespaces},
        status=status,
    )


@responses.activate
def test_rest_namespaces_add_plugins_invisible_in_html(monkeypatch):
    _no_common_probe(monkeypatch)
    responses.add(responses.GET, "https://cible.test/", body=BARE_HOME, status=200,
                  content_type="text/html; charset=UTF-8")
    responses.add(_wpjson(["oembed/1.0", "wp/v2", "woocommerce/v3", "wc/v3", "yoast/v1"]))
    responses.add(responses.GET,
                  "https://cible.test/wp-content/plugins/woocommerce/readme.txt",
                  body="Stable tag: 8.5.0\n", status=200)
    responses.add(responses.GET,
                  "https://cible.test/wp-content/plugins/wordpress-seo/readme.txt",
                  body="Stable tag: 21.5\n", status=200)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    plugins = {p["slug"]: p for p in inv["plugins"]}

    assert "woocommerce" in plugins
    assert plugins["woocommerce"]["version"] == "8.5.0"
    assert "wordpress-seo" in plugins
    assert plugins["wordpress-seo"]["version"] == "21.5"

    # Pas de plugins fantômes issus des namespaces core.
    assert "oembed" not in plugins
    assert "wp" not in plugins


@responses.activate
def test_rest_namespaces_only_core_adds_nothing(monkeypatch):
    _no_common_probe(monkeypatch)
    responses.add(responses.GET, "https://cible.test/", body=BARE_HOME, status=200,
                  content_type="text/html; charset=UTF-8")
    responses.add(_wpjson(["oembed/1.0", "wp/v2", "wp-site-health/v1", "wp-block-editor/v1"]))
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    assert inv["plugins"] == []


@responses.activate
def test_rest_namespaces_soft404_or_non_json_no_crash(monkeypatch):
    _no_common_probe(monkeypatch)
    responses.add(responses.GET, "https://cible.test/", body=BARE_HOME, status=200,
                  content_type="text/html; charset=UTF-8")
    # Soft-404 : renvoie la home HTML avec un statut 200.
    responses.add(responses.GET, "https://cible.test/wp-json", body=BARE_HOME, status=200,
                  content_type="text/html; charset=UTF-8")
    chk = make_check(FingerprintCheck)
    chk.context = {}
    result = chk.run()  # ne doit pas lever
    inv = chk.context["inventory"]
    assert inv["plugins"] == []
    assert result is not None


@responses.activate
def test_rest_namespaces_unreachable_no_crash(monkeypatch):
    _no_common_probe(monkeypatch)
    responses.add(responses.GET, "https://cible.test/", body=BARE_HOME, status=200,
                  content_type="text/html; charset=UTF-8")
    responses.add(responses.GET, "https://cible.test/wp-json", status=500)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    assert inv["plugins"] == []


@responses.activate
def test_rest_namespace_plugin_not_duplicated_when_already_in_html(monkeypatch):
    _no_common_probe(monkeypatch)
    # contact-form-7 visible dans le HTML (chemin plugin explicite) ET dans
    # les namespaces REST -> une seule entrée, pas de doublon.
    home = ("<html><body><script src='/wp-content/plugins/contact-form-7/js/x.js'>"
            "</script></body></html>")
    responses.add(responses.GET, "https://cible.test/", body=home, status=200,
                  content_type="text/html; charset=UTF-8")
    responses.add(_wpjson(["oembed/1.0", "wp/v2", "contact-form-7/v1"]))
    responses.add(responses.GET,
                  "https://cible.test/wp-content/plugins/contact-form-7/readme.txt",
                  body="Stable tag: 5.2.0\n", status=200)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    matches = [p for p in inv["plugins"] if p["slug"] == "contact-form-7"]
    assert len(matches) == 1
