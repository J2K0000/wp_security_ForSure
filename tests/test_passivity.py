"""Garde-fou « 100 % passif, lecture seule » : exécution complète du moteur,
dans les deux modes d'accès.

Le moteur (`ScanEngine`) tourne avec la configuration de `config.yaml`, une
fois par défaut (`authorized: false`) et une fois avec `authorized: true`
(option --authorized), contre une cible WordPress entièrement simulée. Un
attrape-tout `responses` enregistre CHAQUE requête qui atteint la couche HTTP,
quelle que soit sa méthode ou son hôte, puis on vérifie, dans les deux modes :

  1. que toutes les méthodes sont dans {GET, HEAD, OPTIONS} ;
  2. qu'aucune charge d'attaque n'apparaît dans l'URL, les en-têtes ou le corps ;
  3. qu'aucune requête ne part vers une adresse privée, de bouclage ou de lien
     local (la page d'accueil piégée référence 10.0.0.5, 169.254.169.254 et des
     noms qui résolvent vers ces plages, et une redirection pointe hors cible) ;
  4. qu'aucune requête ne vise wp-cron.php, un diagnostic Site Health ni un
     fichier .php deviné (non référencé) sous wp-content/, uploads/ ou
     mu-plugins/ : un GET l'exécuterait.

Par défaut, en plus : aucune requête de niveau 2 (chemin deviné et non lié,
voir scanner/access_tiers.py), et le check de niveau 2 est « skipped ». Avec
`authorized`, des requêtes de niveau 2 partent, mais toujours seulement en GET,
HEAD ou OPTIONS et sans charge d'attaque (points 1 et 2).

Tout reste hors ligne : HTTP simulé par `responses`, DNS par un faux
`socket.getaddrinfo`, binaires externes (openssl, curl) neutralisés, DNS TXT
d'email_auth substitué, cache de vulnérabilités dans un dossier temporaire.
"""
import ipaddress
import json
import re
import socket
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
import responses
import yaml

from wp_security_forsure.scanner import access_tiers as at
from wp_security_forsure.scanner import status as st
from wp_security_forsure.scanner.engine import CHECK_REGISTRY, ScanEngine

TARGET = "https://cible.test"
PUBLIC_IP = "93.184.216.34"

# Noms piégés : ils résolvent vers des plages que le scanner ne doit JAMAIS
# contacter (réseau interne de l'auditeur, métadonnées cloud, bouclage).
TRAP_DNS = {
    "interne.piege.test": "10.0.0.5",
    "meta.piege.test": "169.254.169.254",
    "boucle.piege.test": "127.0.0.1",
}

ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
ALL_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH",
               "TRACE", "CONNECT", "PROPFIND"]

# Charges d'attaque ou marqueurs de sonde active interdits dans une requête.
FORBIDDEN_NEEDLES = [
    "<script", "onerror=", "' or '", "../", "/etc/passwd",
    "169.254.169.254", "127.0.0.1", "localhost", "x-forwarded-host",
    "union select", "'--",
]
# Collaborateur OAST (interactsh : *.oast.pro, *.oast.fun...) ou clé
# oast_collaborator ; la limite de mot évite le faux positif « yoast ».
OAST_MARKER = re.compile(r"\boast")
# Une apostrophe dans la query string d'une URL de la cible = sonde SQL.
SQL_QUOTE_IN_QUERY = re.compile(r"\?[^#]*'")

HOME_HTML = """<!doctype html>
<html><head>
<title>Site de test</title>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="https://api.w.org/" href="https://cible.test/wp-json/" />
<link rel="EditURI" type="application/rsd+xml" href="https://cible.test/xmlrpc.php?rsd" />
<link rel="stylesheet" href="https://cible.test/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8" />
<link rel="stylesheet" href="https://interne.piege.test/style.css" />
<script src="https://cible.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<script src="https://cible.test/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.18.0"></script>
<script src="https://cdn.tiers.test/libs/jquery/1.12.4/jquery.min.js"></script>
<script src="http://10.0.0.5/interne.js"></script>
<script src="https://meta.piege.test/latest/meta-data/x.js"></script>
<script src="//boucle.piege.test/b.js"></script>
</head><body class="home blog">
<img src="http://169.254.169.254/latest/meta-data/iam.png" />
<form role="search" method="get" class="search-form" action="https://cible.test/">
  <input type="search" class="search-field" name="s" />
</form>
<div class="wpcf7"><form action="/contact/#wpcf7-f1-o1" method="post" class="wpcf7-form">
  <input type="hidden" name="_wpcf7" value="1" />
  <input type="file" name="piece-jointe" />
</form></div>
<form action="https://cible.test/wp-comments-post.php" method="post" id="commentform">
  <textarea name="comment"></textarea>
</form>
<a href="https://cible.test/wp-login.php">Connexion</a>
<a href="https://dangling.tiers.test/">Partenaire</a>
<iframe src="https://cdn.tiers.test/embed"></iframe>
</body></html>"""

REST_INDEX = {
    "name": "Site de test",
    "url": TARGET,
    "namespaces": ["oembed/1.0", "batch/v1", "wp/v2", "wp-site-health/v1",
                   "contact-form-7/v1", "custom/v1"],
    "routes": {
        "/": {"methods": ["GET"]},
        "/batch/v1": {"methods": ["POST"], "endpoints": [
            {"methods": ["POST"], "args": {"requests": {"type": "array"}}}]},
        "/oembed/1.0/embed": {"methods": ["GET"]},
        "/oembed/1.0/proxy": {"methods": ["GET"], "endpoints": [
            {"methods": ["GET"], "args": {"url": {"type": "string"}}}]},
        "/wp/v2/posts": {"methods": ["GET", "POST"]},
        "/wp/v2/users": {"methods": ["GET", "POST"]},
        "/wp/v2/media": {"methods": ["GET", "POST"]},
        "/wp/v2/settings": {"methods": ["GET", "POST", "PUT", "PATCH"]},
        "/contact-form-7/v1/contact-forms/(?P<id>\\d+)/feedback": {
            "methods": ["POST"]},
        "/custom/v1/fetch": {"methods": ["GET", "POST"], "endpoints": [
            {"methods": ["GET", "POST"],
             "args": {"url": {"type": "string"},
                      "callback": {"type": "string"}}}]},
    },
}

USERS = [{"id": 1, "name": "admin", "slug": "admin",
          "link": "https://cible.test/author/admin/"}]

LOGIN_HTML = ("<html><body class='login'><form name='loginform' id='loginform' "
              "action='https://cible.test/wp-login.php' method='post'>"
              "<input name='log'/><input name='pwd' type='password'/>"
              "</form></body></html>")


def _route_get(req):
    """Réponses simulées d'un WordPress plausible, pour les GET."""
    parts = urlsplit(req.url)
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if host not in ("cible.test", "www.cible.test"):
        if host == "cdn.tiers.test":
            return 200, {"Content-Type": "application/javascript"}, "/*! lib */"
        return 404, {}, "introuvable"
    html = {"Content-Type": "text/html; charset=UTF-8"}
    js = {"Content-Type": "application/json; charset=UTF-8"}
    if path == "/" and "rest_route" not in (parts.query or ""):
        return 200, dict(html, **{"Set-Cookie": "PHPSESSID=abc; path=/",
                                  "X-Powered-By": "PHP/8.1.2",
                                  "Server": "Apache"}), HOME_HTML
    if path in ("/wp-json", "/wp-json/") or "rest_route=/" == parts.query:
        return 200, dict(js, **{"Link": '<https://cible.test/wp-json/>; '
                                        'rel="https://api.w.org/"'}), json.dumps(REST_INDEX)
    if path.startswith("/wp-json/wp/v2/users"):
        return 200, js, json.dumps(USERS)
    if path.startswith("/wp-json/"):
        return 401, js, json.dumps({"code": "rest_forbidden", "message": "Non",
                                    "data": {"status": 401}})
    if path == "/xmlrpc.php":
        return 405, {"Content-Type": "text/plain", "Allow": "POST"}, \
            "XML-RPC server accepts POST requests only."
    if path == "/wp-login.php":
        return 200, html, LOGIN_HTML
    if path.startswith("/wp-admin/admin-ajax.php"):
        return 400, html, "0"
    # Redirections piégées : vers une IP de métadonnées et vers un tiers.
    if path.rstrip("/") == "/wp-admin":
        return 302, {"Location": "http://169.254.169.254/latest/meta-data/"}, ""
    if path.rstrip("/") == "/feed":
        return 301, {"Location": "https://evil.tiers.test/feed"}, ""
    if path == "/robots.txt":
        return 200, {"Content-Type": "text/plain"}, \
            "User-agent: *\nDisallow: /wp-admin/\nSitemap: https://cible.test/wp-sitemap.xml\n"
    return 404, html, "<html><body>Page introuvable</body></html>"


def _route_other(req):
    if req.method == "HEAD":
        status, headers, _ = _route_get(req)
        return status, headers, ""
    if req.method == "OPTIONS":
        return 200, {"Allow": "GET, HEAD, OPTIONS, POST"}, ""
    return 200, {"Content-Type": "application/json"}, "{}"


def _fake_getaddrinfo(host, port, *args, **kwargs):
    host = (host.decode() if isinstance(host, bytes) else str(host or "")).strip("[]")
    try:
        addr = str(ipaddress.ip_address(host))
    except ValueError:
        addr = TRAP_DNS.get(host.lower(), PUBLIC_IP)
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port or 0))]


def _no_binary(*args, **kwargs):
    raise FileNotFoundError("binaire externe neutralisé pour le test")


def _host_address(host: str) -> ipaddress._BaseAddress:
    return ipaddress.ip_address(_fake_getaddrinfo(host, 0)[0][4][0])


def _payload_hits(req):
    text = _request_text(req)
    hits = [n for n in FORBIDDEN_NEEDLES if n in text]
    if OAST_MARKER.search(text):
        hits.append("oast")
    if SQL_QUOTE_IN_QUERY.search(unquote(unquote(req.url or ""))):
        hits.append("apostrophe dans la query string")
    return hits


def _violations(recorded):
    """(check, description) de chaque requête non passive."""
    found = []
    for check, req in recorded:
        if req.method.upper() not in ALLOWED_METHODS:
            found.append((check, f"méthode {req.method} {req.url}"))
        hits = _payload_hits(req)
        if hits:
            found.append((check, f"charge {hits} {req.method} {req.url}"))
        addr = _host_address(urlsplit(req.url).hostname or "")
        if (not addr.is_global or addr.is_private or addr.is_loopback
                or addr.is_link_local):
            found.append((check, f"adresse privée {addr} {req.method} {req.url}"))
    return found


def _request_text(req) -> str:
    """URL (décodée deux fois), en-têtes (noms et valeurs) et corps, en minuscules."""
    url = unquote(unquote(req.url or ""))
    headers = "\n".join(f"{k}: {v}" for k, v in (req.headers or {}).items())
    body = req.body or b""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    return f"{url}\n{headers}\n{unquote(str(body))}".lower()


@pytest.fixture(scope="module")
def default_scan(tmp_path_factory):
    """Exécution complète par défaut (sans --authorized), une fois par module."""
    with pytest.MonkeyPatch.context() as mp:
        return _run_engine(mp, tmp_path_factory.mktemp("vulncache"), authorized=False)


@pytest.fixture(scope="module")
def authorized_scan(tmp_path_factory):
    """Exécution complète avec --authorized, une fois par module."""
    with pytest.MonkeyPatch.context() as mp:
        return _run_engine(mp, tmp_path_factory.mktemp("vulncache"), authorized=True)


@pytest.fixture(params=["default_scan", "authorized_scan"])
def scan(request):
    return request.getfixturevalue(request.param)


@pytest.fixture
def recorded_calls(scan):
    return scan["recorded"]


def _run_engine(monkeypatch, tmp_path, authorized=False):
    from wp_security_forsure.scanner.checks import email_auth, vulnerability_scan

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    monkeypatch.setattr(subprocess, "run", _no_binary)
    monkeypatch.setattr(email_auth, "_resolve_txt", lambda domain: [])
    # Cache de vulnérabilités isolé dans un dossier temporaire (jamais celui de
    # l'utilisateur), quelle que soit la façon dont le module le localise.
    monkeypatch.setattr(vulnerability_scan, "_DATA_DIR", str(tmp_path),
                        raising=False)
    try:
        from wp_security_forsure.scanner.vulndb import cache as vulncache
        env_name = getattr(vulncache, "CACHE_DIR_ENV", None)
        if env_name:
            monkeypatch.setenv(env_name, str(tmp_path))
    except ImportError:
        pass

    cfg_path = Path(__file__).resolve().parent.parent / "wp_security_forsure" / "config.yaml"
    config = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert config["authorized"] is False  # défaut livré : pas de niveau 2
    config["timeout"] = 5
    config["authorized"] = authorized

    # Attribution : chaque requête enregistrée porte le nom du check en cours.
    current = {"check": "moteur"}
    for cls in set(CHECK_REGISTRY.values()):
        if "run" in cls.__dict__:
            monkeypatch.setattr(cls, "run", _attributed(cls.__dict__["run"],
                                                        cls.name, current))
    recorded = []

    def recording(route):
        def callback(req):
            recorded.append((current["check"], req))
            return route(req)
        return callback

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for method in ALL_METHODS:
            route = _route_get if method == "GET" else _route_other
            rsps.add_callback(method, re.compile(r".*"), callback=recording(route))
        engine = ScanEngine(TARGET, config)
        results = engine.run_all()
        total = len(rsps.calls)
    assert results, "le moteur n'a produit aucun résultat"
    assert total == len(recorded), "requête non enregistrée par l'attrape-tout"
    assert len(recorded) > 50, "trop peu de requêtes : la cible simulée n'est pas explorée"
    return {"recorded": recorded, "results": results, "authorized": authorized,
            "references": dict(getattr(engine.session, "_wpsf_references", {}))}


def _attributed(run, name, current):
    def wrapper(self, *args, **kwargs):
        previous, current["check"] = current["check"], name
        try:
            return run(self, *args, **kwargs)
        finally:
            current["check"] = previous
    return wrapper


def _report(found):
    lines = sorted({f"[{check}] {desc}" for check, desc in found})
    return f"{len(lines)} requête(s) non passive(s) :\n" + "\n".join(lines[:40])


def test_run_uses_only_read_methods(recorded_calls):
    found = [(c, d) for c, d in _violations(recorded_calls)
             if d.startswith("méthode")]
    assert not found, _report(found)


def test_run_sends_no_attack_payload(recorded_calls):
    found = [(c, d) for c, d in _violations(recorded_calls)
             if d.startswith("charge")]
    assert not found, _report(found)


def test_run_never_contacts_private_addresses(recorded_calls):
    found = [(c, d) for c, d in _violations(recorded_calls)
             if d.startswith("adresse")]
    assert not found, _report(found)


def test_run_stays_within_request_budget(recorded_calls):
    assert len(recorded_calls) <= 2000


def test_every_request_is_attributed_to_a_known_check(recorded_calls):
    names = {c for c, _ in recorded_calls}
    assert names <= set(CHECK_REGISTRY) | {"moteur"}, names
    assert len(names) > 10


# ── Niveaux d'accès ─────────────────────────────────────────────────────

# Contrôle indépendant de l'implémentation : un .php sous wp-content/,
# uploads/ ou mu-plugins/ (extension finale, ou suivie d'un PATH_INFO).
_GUESSED_PHP = re.compile(r"/(?:wp-content|uploads|mu-plugins)/(?:[^?#]*/)?[^/?#]+\.php\d?(?:[/?#]|$)", re.I)


def _in_target(req):
    return (urlsplit(req.url).hostname or "").lower() in at.scope_hosts(TARGET)


def test_run_never_requests_wp_cron_site_health_or_guessed_php(scan):
    refs = scan["references"]
    found = []
    for check, req in scan["recorded"]:
        url = unquote(req.url or "")
        if "wp-cron" in url.lower() or "doing_wp_cron" in url.lower():
            found.append((check, f"wp-cron {req.method} {req.url}"))
        if "wp-site-health/v1/" in url.lower():
            found.append((check, f"Site Health {req.method} {req.url}"))
        if (_in_target(req) and _GUESSED_PHP.search(urlsplit(url).path + "?")
                and at.reference_key(req.url, TARGET) not in refs):
            found.append((check, f"PHP deviné {req.method} {req.url}"))
        if at.forbidden_reason(req.url, TARGET, refs):
            found.append((check, f"interdite {req.method} {req.url}"))
    assert not found, _report(found)


def _tier2(scan):
    refs = scan["references"]
    return [(check, f"niveau 2 {req.method} {req.url}")
            for check, req in scan["recorded"]
            if at.classify(req.method, req.url, TARGET, refs) == at.TIER_UNLINKED]


def test_default_run_sends_no_level_2_request(default_scan):
    found = _tier2(default_scan)
    assert not found, _report(found)


def test_default_run_skips_the_level_2_check(default_scan, authorized_scan):
    def status(scan):
        return {r.check_name: st.get_status(r) for r in scan["results"]}
    assert status(default_scan)["nulled_plugins"] == st.STATUS_SKIPPED
    assert status(authorized_scan)["nulled_plugins"] == st.STATUS_OK
    assert not any(c == "nulled_plugins" for c, _ in default_scan["recorded"])


def test_authorized_run_sends_level_2_requests_read_only(authorized_scan):
    found = _tier2(authorized_scan)
    assert len(found) > 100, len(found)
    urls = " ".join(desc for _, desc in found)
    for needle in ("/.env", "/.git/HEAD", "wp-config.php.bak", "/readme.txt"):
        assert needle in urls, needle
    # Mêmes garanties qu'en mode par défaut : lecture seule, sans charge.
    assert not [v for v in _violations(authorized_scan["recorded"])
                if not v[1].startswith("adresse")]
    assert len(authorized_scan["recorded"]) > len(_tier2(authorized_scan))


def test_default_run_sends_fewer_requests_than_authorized(default_scan, authorized_scan):
    assert len(default_scan["recorded"]) < len(authorized_scan["recorded"])


# Checks dont des requêtes se présentent comme un navigateur ou comme Googlebot
# (exceptions documentées dans le README : les injections se cachent des outils).
_DISGUISED_CHECKS = {"visit_profiles", "cloaking_seo_spam"}


def test_every_request_names_the_tool_except_documented_profiles(recorded_calls):
    """Toute requête porte l'agent identifiable de l'outil, y compris vers les
    services tiers (wpvulnerability.net, api.wordpress.org) ; seuls les profils
    de visite et le contrôle du cloaking se présentent autrement."""
    from wp_security_forsure import USER_AGENT
    found = []
    for check, req in recorded_calls:
        ua = req.headers.get("User-Agent", "")
        if ua == USER_AGENT:
            continue
        disguised = "Chrome/" in ua or "Googlebot" in ua
        if not (check in _DISGUISED_CHECKS and disguised):
            found.append(f"{check} {req.method} {req.url} UA={ua!r}")
    assert not found, chr(10).join(found[:20])

