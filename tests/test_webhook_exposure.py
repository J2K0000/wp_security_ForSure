"""Exposition d'endpoints récepteurs de webhooks, détection strictement PASSIVE.

Matrice couverte :
  - index REST exposant une route au motif récepteur (…/webhook, …/stripe/ipn)
      → MEDIUM potential
  - index REST sans motif récepteur → pas de MEDIUM (INFO discret)
  - surface héritée WooCommerce ?wc-api= présente → MEDIUM potential
  - PREUVE de non-nocuité : AUCUNE requête mutante (POST/PUT/DELETE) n'est émise -
      aucun mock non-GET n'est enregistré et responses.calls ne contient que des GET.
"""
import re

import responses

from wp_security_forsure.scanner.checks.webhook_exposure import (
    WebhookExposureCheck,
    WEBHOOK_ROUTE_PATTERNS,
)
from tests.conftest import make_check

WP_JSON_URL = re.compile(r"https://cible\.test/wp-json/$")
WC_API_URL = re.compile(r"https://cible\.test/\?wc-api=.*")

# Index REST exposant deux routes réceptrices : un webhook et un IPN Stripe.
_INDEX_WITH_WEBHOOKS = {
    "namespaces": ["oembed/1.0", "wp/v2", "wc/v3", "my-stripe/v1"],
    "routes": {
        "/": {},
        "/wp/v2/posts": {},
        "/wc/v3/webhooks": {},
        "/my-stripe/v1/ipn": {},
    },
}

# Index REST « propre » : aucune route au motif récepteur de webhook.
_INDEX_CLEAN = {
    "namespaces": ["oembed/1.0", "wp/v2", "contact-form-7/v1"],
    "routes": {
        "/": {},
        "/wp/v2/posts": {},
        "/contact-form-7/v1/contact-forms": {},
    },
}


def _make(config=None, plugins=None):
    chk = make_check(WebhookExposureCheck, config=config)
    chk.context = {"inventory": {"core": {}, "plugins": plugins or [], "themes": []}}
    return chk


def test_patterns_base_shape():
    """Les motifs récepteurs attendus sont présents et le 'hook' nu est évité."""
    assert "webhook" in WEBHOOK_ROUTE_PATTERNS
    assert "/hook" in WEBHOOK_ROUTE_PATTERNS
    assert "ipn" in WEBHOOK_ROUTE_PATTERNS
    assert "stripe" in WEBHOOK_ROUTE_PATTERNS
    # Le substring générique "hook" seul ne doit PAS être un motif (faux positifs).
    assert "hook" not in WEBHOOK_ROUTE_PATTERNS


@responses.activate
def test_webhook_routes_are_medium_potential():
    """Index exposant …/webhook et …/stripe/ipn → UN finding MEDIUM agrégé."""
    responses.add(responses.GET, WP_JSON_URL, json=_INDEX_WITH_WEBHOOKS, status=200)
    chk = _make()
    chk.run()

    med = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    # Anti-bruit : un seul finding agrégé, les routes sont listées dans l'évidence.
    assert len(med) == 1
    f = med[0]
    assert "/wc/v3/webhooks" in f["evidence"]
    assert "/my-stripe/v1/ipn" in f["evidence"]
    assert f["confidence"] == "potential"
    assert "NON vérifiable à distance" in f["message"]
    assert "SURFACE à auditer côté code" in f["evidence"]
    assert chk._result.passed is False


@responses.activate
def test_inventory_cross_reference_names_plugin():
    """Le recoupement inventaire nomme le plugin quand son slug apparaît dans une route."""
    responses.add(responses.GET, WP_JSON_URL, json=_INDEX_WITH_WEBHOOKS, status=200)
    chk = _make(plugins=[{"slug": "my-stripe", "version": "2.1.0"}])
    chk.run()
    med = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    assert med
    ev = med[0]["evidence"]
    assert "/my-stripe/v1/ipn" in ev
    assert "Recoupement inventaire" in ev
    assert "2.1.0" in ev


@responses.activate
def test_clean_index_yields_no_medium():
    """Index sans motif récepteur → aucun MEDIUM, seulement un INFO discret."""
    responses.add(responses.GET, WP_JSON_URL, json=_INDEX_CLEAN, status=200)
    chk = _make()
    chk.run()
    assert not any(f["severity"] == "MEDIUM" for f in chk._result.findings)
    assert any(f["severity"] == "INFO"
               and "Aucun endpoint récepteur de webhook évident" in f["message"]
               for f in chk._result.findings)
    assert chk._result.passed is True


@responses.activate
def test_wc_api_surface_is_medium_potential():
    """?wc-api= répondant autrement qu'en 404 simple → MEDIUM potential."""
    responses.add(responses.GET, WP_JSON_URL, json=_INDEX_CLEAN, status=200)
    responses.add(responses.GET, WC_API_URL, body="0", status=200)
    chk = _make()
    chk.run()
    wc = [f for f in chk._result.findings
          if f["severity"] == "MEDIUM" and "?wc-api=" in f["message"]]
    assert len(wc) == 1
    assert wc[0]["confidence"] == "potential"


@responses.activate
def test_wc_api_404_is_not_flagged():
    """?wc-api= renvoyant un 404 « ressource absente » → pas de surface notée."""
    responses.add(responses.GET, WP_JSON_URL, json=_INDEX_CLEAN, status=200)
    responses.add(responses.GET, WC_API_URL, json={"code": "rest_no_route"}, status=404)
    chk = _make()
    chk.run()
    assert not any("?wc-api=" in f["message"] for f in chk._result.findings)


@responses.activate
def test_non_json_index_does_not_crash():
    """Un index REST non-JSON est toléré sans crash ni faux positif."""
    responses.add(responses.GET, WP_JSON_URL, body="<html>not json</html>", status=200)
    chk = _make()
    chk.run()  # ne doit pas lever
    assert not any(f["severity"] == "MEDIUM" for f in chk._result.findings)


@responses.activate
def test_no_mutating_request_is_ever_emitted():
    """PREUVE : aucune requête mutante émise.

    Aucun mock POST/PUT/DELETE n'est enregistré (assert_all_requests_are_fired
    par défaut) ET on vérifie via responses.calls qu'aucun appel non-GET n'a eu
    lieu, l'audit ne déclenche JAMAIS de webhook.
    """
    responses.add(responses.GET, WP_JSON_URL, json=_INDEX_WITH_WEBHOOKS, status=200)
    responses.add(responses.GET, WC_API_URL, body="0", status=200)
    chk = _make()
    chk.run()

    assert responses.calls, "au moins un GET passif attendu"
    for call in responses.calls:
        assert call.request.method == "GET", (
            f"requête non-GET émise : {call.request.method} {call.request.url}"
        )
