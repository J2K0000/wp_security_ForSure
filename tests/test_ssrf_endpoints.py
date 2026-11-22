"""SSRF pré-auth via endpoints REST : détection passive uniquement.

Matrice couverte :
  - index REST exposant une route à risque (dittyeditor/v1) : HIGH potential
  - index REST sans route à risque : pas de HIGH SSRF
  - anciennes clés de mode actif (active_exploitation, oast_collaborator) :
    ignorées, aucune requête vers les routes à risque, aucune URL soumise
"""
import re

import responses

from wp_security_forsure.scanner.checks.ssrf_endpoints import (
    SsrfEndpointsCheck,
    SSRF_PRONE_ROUTES,
)
from tests.conftest import make_check

INDEX_URL = re.compile(r"https://cible\.test/(wp-json/|\?rest_route=/).*")
PROBE_URL = re.compile(r"https://cible\.test/wp-json/.+")

# Index REST exposant la route à risque Ditty (namespace dittyeditor/v1).
_INDEX_WITH_DITTY = {
    "namespaces": ["oembed/1.0", "wp/v2", "dittyeditor/v1"],
    "routes": {
        "/": {},
        "/wp/v2/posts": {},
        "/dittyeditor/v1/displayItems": {},
    },
}

# Index REST « propre » : aucune route à risque connue.
_INDEX_CLEAN = {
    "namespaces": ["oembed/1.0", "wp/v2", "contact-form-7/v1"],
    "routes": {
        "/": {},
        "/wp/v2/posts": {},
        "/contact-form-7/v1/contact-forms": {},
    },
}


def _make(config=None, plugins=None):
    chk = make_check(SsrfEndpointsCheck, config=config)
    chk.context = {"inventory": {"core": {}, "plugins": plugins or [], "themes": []}}
    return chk


def test_prone_routes_base_shape():
    """La base bundlée expose bien les clés attendues pour chaque entrée."""
    assert SSRF_PRONE_ROUTES
    for e in SSRF_PRONE_ROUTES:
        for key in ("match", "endpoint", "param", "plugin", "cve", "sink", "reco"):
            assert key in e, (e, key)


@responses.activate
def test_exposed_ditty_route_is_high_potential():
    """Index exposant dittyeditor/v1 → finding HIGH potential (exposition SSRF)."""
    responses.add(responses.GET, INDEX_URL, json=_INDEX_WITH_DITTY, status=200)
    chk = _make()
    chk.run()
    ssrf = [f for f in chk._result.findings
            if f["severity"] == "HIGH" and "dittyeditor/v1" in f["message"]]
    assert len(ssrf) == 1
    f = ssrf[0]
    assert f["confidence"] == "potential"
    assert "source_url" in f["message"]
    assert "CVE-2025-8085" in f["message"]
    assert chk._result.passed is False


@responses.activate
def test_inventory_cross_reference_strengthens_evidence():
    """Le recoupement avec l'inventaire des plugins enrichit l'évidence."""
    responses.add(responses.GET, INDEX_URL, json=_INDEX_WITH_DITTY, status=200)
    chk = _make(plugins=[{"slug": "ditty", "version": "3.1.50", "source": "readme"}])
    chk.run()
    ssrf = [f for f in chk._result.findings if "dittyeditor/v1" in f["message"]]
    assert ssrf
    assert "3.1.50" in ssrf[0]["evidence"]
    assert "Recoupement inventaire" in ssrf[0]["evidence"]


@responses.activate
def test_clean_index_yields_no_ssrf_high():
    """Index sans route à risque → aucun finding HIGH SSRF (seul le rappel INFO cœur)."""
    responses.add(responses.GET, INDEX_URL, json=_INDEX_CLEAN, status=200)
    chk = _make()
    chk.run()
    assert not any(f["severity"] == "HIGH" for f in chk._result.findings)
    # Le rappel de contexte cœur wontfix reste émis (INFO).
    assert any(f["severity"] == "INFO" and "wp_http_validate_url" in f["message"]
               for f in chk._result.findings)
    assert chk._result.passed is True


@responses.activate
def test_core_wontfix_context_always_emitted():
    """Le rappel cœur wp_http_validate_url() est présent même sur index à risque."""
    responses.add(responses.GET, INDEX_URL, json=_INDEX_WITH_DITTY, status=200)
    chk = _make()
    chk.run()
    ctx = [f for f in chk._result.findings if "wp_http_validate_url" in f["message"]]
    assert len(ctx) == 1
    assert ctx[0]["severity"] == "INFO"
    assert ctx[0]["confidence"] == "potential"


@responses.activate
def test_legacy_active_keys_never_trigger_a_probe():
    """Même avec les anciennes clés de mode actif, aucune requête n'atteint les
    routes à risque et aucune URL de collaborateur n'est soumise : seul l'index
    REST est lu (GET)."""
    responses.add(responses.GET, INDEX_URL, json=_INDEX_WITH_DITTY, status=200)
    responses.add(responses.GET, PROBE_URL, json={"ok": False}, status=200)
    responses.add(responses.POST, PROBE_URL, json={"ok": False}, status=200)
    chk = _make(config={
        "active_exploitation": True,
        "oast_collaborator": "http://abc123.collab.test",
    })
    chk.run()
    assert {c.request.method for c in responses.calls} <= {"GET"}
    for c in responses.calls:
        assert "dittyeditor" not in c.request.url
        assert "collab.test" not in c.request.url
    assert not any("Sonde SSRF" in f["message"] for f in chk._result.findings)
    assert not hasattr(SsrfEndpointsCheck, "_run_active")
    assert not hasattr(SsrfEndpointsCheck, "_emit_probe")
