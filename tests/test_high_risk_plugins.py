"""high_risk_plugins, signalement (INFO) des plugins à forte surface
d'attaque, via l'inventaire partagé (`context["inventory"]`, chemin
prioritaire) ou, à défaut, une sonde HTTP best-effort (readme.txt/style.css).

`test_high_risk_no_hardcoded_cve.py` couvre déjà le lint « pas de CVE en
dur » ; ce module couvre le comportement réel de détection.
"""
import re

import responses

from wp_security_forsure.scanner.checks.high_risk_plugins import HighRiskPluginsCheck
from tests.conftest import make_check

TARGET = "https://cible.test"


def _mk():
    return make_check(HighRiskPluginsCheck, target=TARGET)


# ---------------------------------------------------------------------------
# Chemin inventaire (context["inventory"], produit par le check fingerprint)
# ---------------------------------------------------------------------------

def test_inventory_detects_known_notable_plugin():
    chk = _mk()
    chk.context = {"inventory": {
        "plugins": [{"slug": "elementor", "version": "3.5.0", "source": "readme.txt"}],
        "themes": [], "core": {},
    }}
    result = chk.run()

    el = [f for f in result.findings if "Elementor" in f["message"]]
    assert len(el) == 1
    assert "3.5.0" in el[0]["message"]
    assert el[0]["severity"] == "INFO"
    assert "wp-content/plugins/elementor/" in el[0]["url"]
    assert "readme.txt" in el[0]["evidence"]


def test_inventory_detects_multiple_notable_plugins():
    chk = _mk()
    chk.context = {"inventory": {
        "plugins": [
            {"slug": "elementor", "version": "3.5.0", "source": "readme.txt"},
            {"slug": "woocommerce", "version": "8.1.0", "source": "style.css"},
        ],
        "themes": [], "core": {},
    }}
    result = chk.run()

    names = {f["message"].split(" ")[0] for f in result.findings}
    assert "Elementor" in names
    assert "WooCommerce" in names
    assert len(result.findings) == 2


def test_inventory_without_notable_plugin_yields_no_finding():
    """Un plugin présent mais absent de la liste notable -> pas de finding."""
    chk = _mk()
    chk.context = {"inventory": {
        "plugins": [{"slug": "some-random-plugin", "version": "1.0", "source": "readme"}],
        "themes": [], "core": {},
    }}
    result = chk.run()

    assert result.findings == []


# ---------------------------------------------------------------------------
# Chemin sonde HTTP (fallback, pas d'inventaire disponible)
# ---------------------------------------------------------------------------

@responses.activate
def test_http_probe_detects_known_plugin_via_readme():
    slug = "contact-form-7"
    responses.add(
        responses.GET, f"{TARGET}/wp-content/plugins/{slug}/readme.txt",
        body="=== Contact Form 7 ===\nStable tag: 5.8.4\n", status=200,
    )
    # Tous les autres plugins notables -> absents (404) en readme.txt/style.css.
    responses.add(
        responses.GET,
        re.compile(re.escape(TARGET) + r"/wp-content/plugins/.*/readme\.txt"),
        status=404,
    )
    responses.add(
        responses.GET,
        re.compile(re.escape(TARGET) + r"/wp-content/plugins/.*/style\.css"),
        status=404,
    )

    chk = _mk()
    # Pas d'inventaire dans le contexte -> bascule sur la sonde HTTP.
    result = chk.run()

    cf7 = [f for f in result.findings if "Contact Form 7" in f["message"]]
    assert len(cf7) == 1
    assert "5.8.4" in cf7[0]["message"]
    assert cf7[0]["severity"] == "INFO"
    assert "readme.txt" in cf7[0]["evidence"]


@responses.activate
def test_http_probe_no_plugins_present_yields_no_findings():
    responses.add(
        responses.GET,
        re.compile(re.escape(TARGET) + r"/wp-content/plugins/.*/readme\.txt"),
        status=404,
    )
    responses.add(
        responses.GET,
        re.compile(re.escape(TARGET) + r"/wp-content/plugins/.*/style\.css"),
        status=404,
    )

    chk = _mk()
    result = chk.run()

    assert result.findings == []
