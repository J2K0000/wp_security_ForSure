"""Chantier A / Tâche 5, narratif de prise de contrôle porté à la source.

Vérifie que les deux checks flagship « prise de contrôle » (RCE wp2shell via
rest_batch, upload arbitraire via forms_upload) attachent explicitement
`access_class="controle"` et un `impact` structuré sur le finding dict au
moment de l'émission, plutôt que de compter uniquement sur le repli par
correspondance de message (`impact.classify/narrative`).

L'assertion discriminante : la clé `access_class`/`impact` est ABSENTE avant
l'annotation à la source, PRÉSENTE après.

Les gestionnaires d'upload des extensions (fichiers PHP) ne sont plus demandés
(un GET les exécuterait) : forms_upload ne produit plus ce constat, seule la
boucle d'émission reste vérifiée.
"""
import re

import responses

from wp_security_forsure.scanner.checks.forms_upload import FormsUploadCheck
from wp_security_forsure.scanner.checks.rest_batch import RestBatchCheck
from tests.conftest import make_check

BATCH_URL = re.compile(r"https://cible\.test/(wp-json/batch/v1|\?rest_route=/batch/v1).*")
_BATCH_ENVELOPE = {"failed": "validation", "responses": [None]}
_REST_INDEX_WITH_BATCH = {"namespaces": ["batch/v1"], "routes": {"/batch/v1": {}}}


# ── forms_upload : le builder annote directement le finding dict ──────────

@responses.activate
def test_plugin_upload_handlers_are_never_requested():
    """_check_plugin_upload_paths() : sonde retirée, aucun fichier PHP de
    plugin n'est demandé ; un seul constat INFO « non évaluable »."""
    responses.add(responses.HEAD, re.compile(r".*"), status=200)
    responses.add(responses.GET, re.compile(r".*"), status=200,
                  body="<?php // gestionnaire d'upload réel")

    chk = make_check(FormsUploadCheck)
    findings = chk._check_plugin_upload_paths()

    assert len(responses.calls) == 0
    assert len(findings) == 1 and findings[0]["severity"] == "INFO"
    assert "non évaluable de l'extérieur sans exécuter le fichier" in findings[0]["message"]
    assert FormsUploadCheck.PLUGIN_UPLOAD_PATHS[0] in findings[0]["evidence"]


# ── forms_upload : la boucle d'émission (run()) transmet l'annotation ─────

def test_run_emit_loop_forwards_access_class_and_impact():
    """La boucle d'émission de run() (around line ~720) doit transmettre
    access_class/impact du finding dict construit par un builder vers
    CheckResult.add_finding(), et donc vers CheckResult.findings[0]."""
    chk = make_check(FormsUploadCheck)

    known_dict = {
        "message": "Endpoint d'upload détecté : wp-content/plugins/x/upload.php (HTTP 200)",
        "severity": "HIGH",
        "evidence": "Le fichier existe et retourne HTTP 200.",
        "url": "https://cible.test/wp-content/plugins/x/upload.php",
        "confidence": "potential",
        "access_class": "controle",
        "impact": {
            "data": "Dépôt de fichier arbitraire (potentiel webshell).",
            "path": "Formulaire / endpoint d'upload sans restriction de type.",
            "enables": "Exécution de code à distance puis contrôle du site.",
        },
    }

    # On neutralise tous les sous-checks de run() sauf un, connu et déjà
    # annoté : aucun appel HTTP réel n'est nécessaire, on exerce uniquement
    # la boucle d'émission (le "forwarding").
    chk._check_plugin_upload_paths = lambda: [known_dict]
    chk._check_media_endpoint = lambda: []
    chk._detect_plugins = lambda: []
    chk._check_comment_nonce = lambda: []
    chk._check_login_autocomplete = lambda: []
    chk._check_registration = lambda: []
    chk._check_lostpassword_enumeration = lambda: []
    chk._not_assessable = lambda: []

    result = chk.run()

    assert len(result.findings) == 1
    emitted = result.findings[0]
    assert emitted["access_class"] == "controle"
    assert "webshell" in emitted["impact"]["data"]


# ── rest_batch : le finding CRITICAL "vulnérable à wp2shell" porte l'impact ─

@responses.activate
def test_rest_batch_wp2shell_critical_carries_controle_impact():
    """Version affectée + contrôleur batch exposé sans auth → CRITICAL,
    et ce finding doit porter access_class="controle" + impact["data"]
    mentionnant « code arbitraire » directement à l'émission."""
    chk = make_check(RestBatchCheck)
    chk.context = {"inventory": {"core": {"version": "6.9.4", "source": "generator"},
                                 "plugins": [], "themes": []}}
    # Détection passive : la route batch figure dans l'index REST public.
    responses.add(responses.GET, re.compile(r"https://cible\.test/wp-json/$"),
                  json=_REST_INDEX_WITH_BATCH, status=200)

    chk.run()

    crit = [f for f in chk._result.findings if f["severity"] == "CRITICAL"]
    assert len(crit) == 1
    assert "vulnérable à wp2shell" in crit[0]["message"]
    assert crit[0].get("access_class") == "controle"
    assert "code arbitraire" in crit[0].get("impact", {}).get("data", "")
