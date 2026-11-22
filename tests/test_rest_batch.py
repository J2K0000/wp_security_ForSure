"""wp2shell / CVE-2026-63030 : détection PASSIVE de l'exposition batch.

Aucune requête n'est envoyée au contrôleur batch (aucun POST). L'exposition se
lit dans l'index REST public, ou à défaut via OPTIONS sur la route.

Matrice couverte :
  - version affectée + route batch dans l'index         : CRITICAL confirmed
  - version affectée + route absente de l'index          : MEDIUM (patch impératif)
  - version inconnue + route exposée                     : HIGH potential
  - version corrigée + route présente                    : INFO (non vulnérable)
  - sans index : OPTIONS rest_no_route                   : aucun finding réel
  - sans index : OPTIONS 401                             : non exposée
  - sans index : OPTIONS décrit la route                 : exposée
  - anciennes clés de mode actif                         : ignorées, jamais de POST
"""
import re

import responses

from wp_security_forsure.scanner.checks.rest_batch import RestBatchCheck, _core_is_affected
from tests.conftest import make_check

INDEX_URL = re.compile(r"https://cible\.test/(wp-json/|\?rest_route=/)$")
BATCH_URL = re.compile(r"https://cible\.test/(wp-json/batch/v1|\?rest_route=/batch/v1).*")

_INDEX_WITH_BATCH = {
    "namespaces": ["wp/v2", "batch/v1"],
    "routes": {"/": {}, "/batch/v1": {"methods": ["POST"]}, "/wp/v2/posts": {}},
}
_INDEX_WITHOUT_BATCH = {
    "namespaces": ["wp/v2"],
    "routes": {"/": {}, "/wp/v2/posts": {}},
}
_OPTIONS_BATCH = {"namespace": "batch/v1", "methods": ["POST"],
                  "endpoints": [{"methods": ["POST"], "args": {}}]}


def _run(core, index=None, options=None, options_status=200, config=None):
    chk = make_check(RestBatchCheck, config=config)
    chk.context = {"inventory": {"core": core, "plugins": [], "themes": []}}
    if index is not None:
        responses.add(responses.GET, INDEX_URL, json=index, status=200)
    else:
        responses.add(responses.GET, INDEX_URL, body="introuvable", status=404)
    if options is not None:
        responses.add("OPTIONS", BATCH_URL, json=options, status=options_status)
    return chk


def _assert_no_post():
    assert {c.request.method for c in responses.calls} <= {"GET", "OPTIONS"}


def test_affected_range_boundaries():
    """Bornes des plages affectées, incluses ; voisines exclues."""
    for v in ("6.9.0", "6.9.4", "7.0.0", "7.0.1"):
        assert _core_is_affected(v), v
    for v in ("6.8.5", "6.8.6", "6.9.5", "7.0.2", "7.1.0", None):
        assert not _core_is_affected(v), v


@responses.activate
def test_affected_version_indexed_route_is_critical():
    chk = _run({"version": "6.9.4", "source": "generator"}, index=_INDEX_WITH_BATCH)
    chk.run()
    crit = [f for f in chk._result.findings if f["severity"] == "CRITICAL"]
    assert len(crit) == 1
    assert "wp2shell" in crit[0]["message"]
    assert crit[0]["confidence"] == "confirmed"
    assert "index REST" in crit[0]["evidence"]
    assert chk._result.passed is False
    _assert_no_post()


@responses.activate
def test_affected_version_route_absent_is_medium():
    """Version vulnérable mais route absente de l'index (retirée / filtrée) :
    MEDIUM, patch requis."""
    chk = _run({"version": "7.0.1", "source": "wpinc_ver"}, index=_INDEX_WITHOUT_BATCH)
    chk.run()
    sev = {f["severity"] for f in chk._result.findings}
    assert sev == {"MEDIUM"}
    assert "mis à jour" in chk._result.findings[0]["message"]
    _assert_no_post()


@responses.activate
def test_unknown_version_indexed_route_is_high_potential():
    chk = _run({"version": None, "source": None}, index=_INDEX_WITH_BATCH)
    chk.run()
    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    assert high[0]["confidence"] == "potential"
    assert "à vérifier" in high[0]["message"]


@responses.activate
def test_patched_version_indexed_route_is_info():
    """Route présente mais cœur corrigé : INFO, pas de vraie vuln."""
    chk = _run({"version": "6.9.5", "source": "generator"}, index=_INDEX_WITH_BATCH)
    chk.run()
    assert chk._result.findings
    assert all(f["severity"] == "INFO" for f in chk._result.findings)
    assert chk._result.passed is True


@responses.activate
def test_absent_controller_yields_no_real_finding():
    """Sans index, OPTIONS rest_no_route sur les deux formes : aucun finding réel."""
    chk = _run({"version": "6.9.5"},
               options={"code": "rest_no_route", "message": "No route"},
               options_status=404)
    chk.run()
    assert all(f["severity"] == "INFO" for f in chk._result.findings)
    assert chk._result.passed is True
    _assert_no_post()


@responses.activate
def test_auth_gated_route_not_counted_as_exposed():
    """Sans index, OPTIONS 401 = route protégée : pas « exposée sans auth »."""
    chk = _run({"version": "6.9.4", "source": "generator"},
               options={"code": "rest_forbidden"}, options_status=401)
    chk.run()
    assert not any(f["severity"] == "CRITICAL" for f in chk._result.findings)
    assert any(f["severity"] == "MEDIUM" for f in chk._result.findings)


@responses.activate
def test_options_route_description_counts_as_exposed():
    """Sans index, OPTIONS qui décrit la route batch (JSON REST) = exposée."""
    chk = _run({"version": "6.9.4", "source": "generator"}, options=_OPTIONS_BATCH)
    chk.run()
    crit = [f for f in chk._result.findings if f["severity"] == "CRITICAL"]
    assert len(crit) == 1
    assert "OPTIONS" in crit[0]["evidence"]
    _assert_no_post()


@responses.activate
def test_legacy_active_key_never_posts():
    """L'ancienne clé active_exploitation est sans effet : aucun POST, aucune
    sonde de désalignement."""
    responses.add(responses.POST, BATCH_URL, json={"responses": []}, status=207)
    chk = _run({"version": "6.9.4", "source": "generator"},
               index=_INDEX_WITH_BATCH, config={"active_exploitation": True})
    chk.run()
    _assert_no_post()
    assert not any("EXPLOITABLE" in f["message"] for f in chk._result.findings)
    assert not hasattr(RestBatchCheck, "_active_misalignment_probe")
    assert not hasattr(RestBatchCheck, "_safe_post_json")
