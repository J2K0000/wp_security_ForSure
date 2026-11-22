"""forms_upload, contrat PASSIF strict pour 3 sous-checks qui envoyaient
auparavant de vraies requêtes mutantes sur la cible :

  1) _check_media_endpoint  : n'envoie plus JAMAIS un vrai fichier (le POST
     est un probe à corps vide, incapable de créer une ressource).
  2) _check_registration    : ne POST plus jamais un vrai compte utilisateur ;
     l'inscription ouverte est détectée en lisant passivement le formulaire
     wp-login.php?action=register.
  3) _check_lostpassword_enumeration : ne POST plus jamais de vraie demande
     de réinitialisation de mot de passe (ce qui déclencherait un email réel
     côté cible) ; détection passive de la seule accessibilité du formulaire.

PREUVE d'innocuité : pour chaque scénario, on inspecte `responses.calls` et
on vérifie qu'aucune requête POST/PUT/DELETE avec un corps « exploitable »
(fichier, identifiants de compte, user_login) n'a été émise.
"""
import re

import responses

from wp_security_forsure.scanner.checks.forms_upload import FormsUploadCheck
from tests.conftest import make_check

MEDIA_URL = re.compile(r"https://cible\.test/wp-json/wp/v2/media$")
REGISTER_PAGE_URL = re.compile(r"https://cible\.test/wp-login\.php\?action=register$")
REGISTER_REST_URL = re.compile(r"https://cible\.test/wp-json/wp/v2/users/register$")
LOSTPW_URL = re.compile(r"https://cible\.test/wp-login\.php\?action=lostpassword$")


def _assert_no_mutating_calls_with_payload():
    """Aucun appel POST/PUT/DELETE ne doit porter de contenu de fichier ou
    de données de compte exploitables, ni dans le corps, ni dans les
    en-têtes (un `filename=` peut aussi bien voyager via un en-tête
    Content-Disposition que via le corps : les deux sont vérifiés).

    Deux profils de POST sont tolérés :
      - corps STRICTEMENT VIDE (le cas général : media probe, etc.) ;
      - le probe historique d'action admin-ajax.php
        (`_check_upload_actions`, HORS PÉRIMÈTRE de ce durcissement) dont
        le corps est *uniquement* `action=<nom_action>`, aucun contenu de
        fichier, aucune donnée de compte, juste un nom d'action à sonder.
    Tout le reste (filename= où que ce soit, identifiants, corps non vide
    sur un autre endpoint) est interdit.
    """
    for call in responses.calls:
        method = call.request.method
        if method in ("GET", "HEAD"):
            continue
        assert method not in ("PUT", "DELETE"), (
            f"méthode mutante interdite : {method} {call.request.url}"
        )
        if method != "POST":
            continue

        body = call.request.body or b""
        if isinstance(body, str):
            body = body.encode()
        # Aucun contenu de fichier, aucun identifiant de compte réel, quel
        # que soit l'endpoint.
        assert b"test_wpsf_audit" not in body
        assert b"TestAudit123" not in body
        assert b"filename=" not in body
        assert b"user_login=admin" not in body

        # filename= ne doit apparaître dans AUCUN en-tête (p.ex.
        # Content-Disposition), un upload de fichier peut se cacher là
        # même si le corps semble anodin.
        for header_name, header_value in call.request.headers.items():
            assert "filename=" not in str(header_value), (
                f"en-tête {header_name}={header_value!r} contient filename= "
                f"sur POST {call.request.url}"
            )

        if "/admin-ajax.php" in call.request.url and re.fullmatch(
                rb"action=[\w\-]+", body):
            # Probe d'existence d'action (hors périmètre de ce durcissement :
            # ne transporte ni fichier ni donnée de compte, juste un nom
            # d'action).
            continue

        assert len(body) == 0, (
            f"POST avec corps non vide (potentiellement mutant) : "
            f"{method} {call.request.url} -> {body!r}"
        )


# --- A) _check_media_endpoint -------------------------------------------

@responses.activate
def test_media_endpoint_401_yields_no_upload_finding():
    responses.add(responses.GET, MEDIA_URL, status=401)
    responses.add(responses.POST, MEDIA_URL, status=401)
    chk = make_check(FormsUploadCheck)
    fs = chk._check_media_endpoint()
    assert not any("upload" in f["message"].lower() and f["severity"] == "CRITICAL"
                   for f in fs)
    assert not any(f["severity"] in ("CRITICAL", "HIGH") for f in fs)
    _assert_no_mutating_calls_with_payload()


@responses.activate
def test_media_endpoint_is_read_only():
    """Plus de POST sur l'API media : seule la lecture (GET) est faite ;
    l'upload anonyme est non évaluable passivement (aucun HIGH possible)."""
    responses.add(responses.GET, MEDIA_URL, status=401)
    responses.add(responses.POST, MEDIA_URL, status=400,
                  json={"code": "rest_upload_no_data", "message": "No data supplied"})
    chk = make_check(FormsUploadCheck)
    fs = chk._check_media_endpoint()
    assert not any(f["severity"] in ("HIGH", "CRITICAL") for f in fs)
    assert [c.request.method for c in responses.calls] == ["GET"]


@responses.activate
def test_media_endpoint_never_sends_file_content():
    """Le POST de probe ne doit jamais transporter de contenu de fichier."""
    responses.add(responses.GET, MEDIA_URL, status=200, json=[])
    responses.add(responses.POST, MEDIA_URL, status=201, json={"id": 1})
    chk = make_check(FormsUploadCheck)
    chk._check_media_endpoint()
    for call in responses.calls:
        if call.request.method == "POST":
            body = call.request.body or b""
            if isinstance(body, str):
                body = body.encode()
            assert body == b"", "un corps de fichier a été envoyé sur le POST media"
            headers = call.request.headers
            cd = headers.get("Content-Disposition", "")
            assert "filename=" not in cd


# --- B) _check_registration ----------------------------------------------

@responses.activate
def test_registration_open_form_detected_without_post():
    responses.add(responses.GET, REGISTER_REST_URL, status=404)
    responses.add(
        responses.GET, REGISTER_PAGE_URL, status=200,
        body=(
            '<html><body><form id="registerform" action="wp-login.php?action=register">'
            '<input type="text" name="user_login">'
            '<input type="email" name="user_email">'
            '</form></body></html>'
        ),
    )
    chk = make_check(FormsUploadCheck)
    fs = chk._check_registration()
    medium = [f for f in fs if f["severity"] == "MEDIUM"]
    assert len(medium) == 1
    assert medium[0]["confidence"] == "confirmed"
    assert "inscription" in medium[0]["message"].lower()
    # Aucun POST n'a jamais été effectué vers l'endpoint d'inscription.
    for call in responses.calls:
        assert call.request.method == "GET"
    _assert_no_mutating_calls_with_payload()


@responses.activate
def test_registration_closed_redirect_yields_no_finding():
    responses.add(responses.GET, REGISTER_REST_URL, status=404)
    responses.add(responses.GET, REGISTER_PAGE_URL, status=302,
                   headers={"Location": "https://cible.test/wp-login.php"})
    chk = make_check(FormsUploadCheck)
    fs = chk._check_registration()
    assert not any(f["severity"] == "MEDIUM" for f in fs)
    for call in responses.calls:
        assert call.request.method == "GET"


@responses.activate
def test_registration_never_posts_to_rest_register():
    responses.add(responses.GET, REGISTER_REST_URL, status=200, json={})
    responses.add(responses.GET, REGISTER_PAGE_URL, status=200, body="nope")
    chk = make_check(FormsUploadCheck)
    chk._check_registration()
    for call in responses.calls:
        assert call.request.method == "GET", (
            f"requête non-GET vers l'inscription : {call.request.method} "
            f"{call.request.url}"
        )


@responses.activate
def test_rest_register_route_present_is_potential_not_confirmed():
    """WP core enregistre TOUJOURS wp-json/wp/v2/users/register (403 quand
    fermée) : sa seule présence n'est pas une preuve d'inscription ouverte,
    donc `confidence="potential"`, la preuve confirmée reste le formulaire
    wp-login.php?action=register (testé séparément, `confirmed`)."""
    responses.add(responses.GET, REGISTER_REST_URL, status=403, json={})
    responses.add(responses.GET, REGISTER_PAGE_URL, status=302,
                   headers={"Location": "https://cible.test/wp-login.php"})
    chk = make_check(FormsUploadCheck)
    fs = chk._check_registration()
    route_findings = [f for f in fs if "wp-json/wp/v2/users/register" in f["url"]]
    assert len(route_findings) == 1
    assert route_findings[0]["confidence"] == "potential"
    assert route_findings[0]["severity"] == "MEDIUM"
    for call in responses.calls:
        assert call.request.method == "GET"


# --- C) _check_lostpassword_enumeration -----------------------------------

@responses.activate
def test_lostpassword_never_posts_real_reset():
    responses.add(responses.GET, LOSTPW_URL, status=200,
                   body='<form id="lostpasswordform">'
                        '<input type="text" name="user_login"></form>')
    chk = make_check(FormsUploadCheck)
    fs = chk._check_lostpassword_enumeration()
    for call in responses.calls:
        assert call.request.method == "GET", (
            f"POST interdit vers lostpassword : {call.request.method}"
        )
    assert not any(f["severity"] in ("MEDIUM", "HIGH", "CRITICAL") for f in fs)
    assert any(f["severity"] == "INFO" for f in fs)


@responses.activate
def test_lostpassword_unreachable_yields_no_finding():
    responses.add(responses.GET, LOSTPW_URL, status=404)
    chk = make_check(FormsUploadCheck)
    fs = chk._check_lostpassword_enumeration()
    assert fs == []
    for call in responses.calls:
        assert call.request.method == "GET"


# --- Contrat global : run() complet ne mute jamais la cible ---------------

@responses.activate
def test_full_run_never_emits_mutating_request_with_payload():
    """Exécute run() avec toutes les réponses mockées et vérifie qu'aucun
    appel HTTP n'aurait pu créer/modifier une ressource côté cible."""
    responses.add(responses.POST, re.compile(r".*/admin-ajax\.php"), body="0", status=200)
    responses.add(responses.HEAD, re.compile(r".*"), status=404)
    responses.add(responses.GET, MEDIA_URL, status=401)
    responses.add(responses.POST, MEDIA_URL, status=401)
    responses.add(responses.GET, REGISTER_REST_URL, status=404)
    responses.add(responses.GET, REGISTER_PAGE_URL, status=302,
                   headers={"Location": "https://cible.test/wp-login.php"})
    responses.add(responses.GET, LOSTPW_URL, status=404)
    responses.add(responses.GET, re.compile(r".*"), body="nope", status=404)

    chk = make_check(FormsUploadCheck)
    chk.run()

    # Filet de sécurité renforcé : corps strictement vide (via le helper
    # partagé) ET aucun `filename=`/Content-Disposition transportant un
    # fichier dans les EN-TÊTES de toute requête non-GET/HEAD. Un simple
    # test de sous-chaîne sur le corps ne suffit pas : un ancien code
    # vulnérable pouvait faire porter `filename=` par un en-tête plutôt
    # que par le corps (cf. l'ancien `_check_media_endpoint`).
    _assert_no_mutating_calls_with_payload()

    # Vérification explicite et redondante (lisibilité du filet de
    # sécurité) : corps vide ET en-têtes sans filename= sur chaque requête
    # mutante, à l'exception du probe d'existence d'action admin-ajax.php
    # (`action=<nom>` seul, hors périmètre de ce durcissement, ne
    # transporte ni fichier ni donnée de compte).
    for call in responses.calls:
        if call.request.method in ("GET", "HEAD"):
            continue
        body = call.request.body or b""
        if isinstance(body, str):
            body = body.encode()
        is_admin_ajax_action_probe = (
            "/admin-ajax.php" in call.request.url
            and re.fullmatch(rb"action=[\w\-]+", body)
        )
        if not is_admin_ajax_action_probe:
            assert len(body) == 0, (
                f"corps non vide sur requête mutante : {call.request.method} "
                f"{call.request.url} -> {body!r}"
            )
        headers = call.request.headers
        cd = headers.get("Content-Disposition", "") or ""
        assert "filename=" not in cd, (
            f"en-tête Content-Disposition avec filename= détecté : {cd!r} "
            f"sur {call.request.method} {call.request.url}"
        )
        for header_name, header_value in headers.items():
            assert "filename=" not in str(header_value), (
                f"en-tête {header_name}={header_value!r} contient filename= "
                f"sur {call.request.method} {call.request.url}"
            )
