"""Check for WordPress-specific features that are often attack vectors.

Contrainte non négociable du propriétaire du projet : ce check ne doit
JAMAIS soumettre d'identifiants ni déclencher de requête pingback sortante
réelle sur la cible. Il est 100 % PASSIF : GET et HEAD uniquement, aucun appel
XML-RPC (pas même system.listMethods), aucun POST admin-ajax.php.

Inherits from BaseCheck. Covers:
  1) XML-RPC availability : un GET sur xmlrpc.php qui répond « XML-RPC server
     accepts POST requests only. » prouve que le serveur XML-RPC est actif.
     La liste des méthodes exposées n'est pas évaluable passivement ; la
     surface d'amplification/SSRF XML-RPC est couverte par
     brute_force_login._check_xmlrpc_surface (propriétaire unique).
  2) WP-Cron : wp-cron.php n'est jamais demandé (un GET lance les tâches
     planifiées du site) ; constat INFO « non évaluable de l'extérieur »
  3) oEmbed endpoint : route présente dans l'index REST (jamais appelée avec
     une URL)
  4) Application Passwords (WP 5.6+) : wp-json/wp/v2/users/me/application-passwords
  5) Site Health endpoint : wp-json/wp-site-health/v1 (info disclosure) ;
     ses sous-endpoints de test ne sont jamais appelés (chacun exécute un
     diagnostic côté serveur) : constat INFO « non évaluable de l'extérieur »
  6) Block directory : wp-json/wp/v2/block-directory/search (SSRF)
  7) Trackback detection : RDF in HTML head
  8) Commentaires ouverts (SEC-20) : page d'accueil et un article réel, dont
     l'URL vient de l'API REST (wp-json/wp/v2/posts?per_page=1, niveau 1) ou
     d'un lien de la page d'accueil (niveau 0) ; formulaire (#commentform,
     action vers wp-comments-post.php) et flux comments/feed/ (niveau 1).
     Rien n'est jamais soumis : wp-comments-post.php n'est pas demandé.
  9) Link manager : wp-json/wp/v2/links endpoint
Retirés (exigeaient un POST) : l'introspection XML-RPC system.listMethods et
la sonde Heartbeat (admin-ajax.php), signalées par un constat INFO « non
évaluable passivement ».
"""

import re
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import requests

from .. import access_tiers
from .base import BaseCheck, CheckResult
from .signatures import xmlrpc_server_active


# ── Article réel de la cible (partagé avec forms_upload) ─────────────────

_UNSET = object()
_A_TAG = re.compile(r"<a\b[^>]*>", re.I)
_HREF = re.compile(r"""\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))""", re.I)
_REL_BOOKMARK = re.compile(r"""\brel\s*=\s*["'][^"']*\bbookmark\b""", re.I)
_TITLE_LINK = re.compile(
    r"""class\s*=\s*["'][^"']*\b(?:entry-title|post-title|wp-block-post-title)\b"""
    r"""[^"']*["'][^>]*>\s*(<a\b[^>]*>)""", re.I)
_POST_URL = re.compile(r"(?:[?&]p=\d+$|/\d{4}/\d{2}/(?:\d{2}/)?[^/?#]+/?$)")
_NOT_ARTICLE = re.compile(
    r"/(?:wp-admin|wp-login\.php|wp-content|wp-includes|wp-json|xmlrpc\.php|"
    r"feed|comments|author|category|tag|page|search)(?:/|$)", re.I)

COMMENT_FORM_ID = re.compile(r"""\bid\s*=\s*["']commentform["']""", re.I)
COMMENT_FORM_ACTION = re.compile(
    r"""<form\b[^>]*\baction\s*=\s*["'][^"']*wp-comments-post\.php""", re.I)
_COMMENTS_CLOSED = re.compile(
    r"comments?\s+(?:are\s+)?closed|commentaires?\s+(?:sont\s+)?ferm[ée]s", re.I)


def comment_form_markers(body: str) -> List[str]:
    """Marqueurs d'un formulaire de commentaire WordPress dans une page."""
    markers = []
    if COMMENT_FORM_ID.search(body or ""):
        markers.append("formulaire #commentform")
    if COMMENT_FORM_ACTION.search(body or ""):
        markers.append("formulaire dont l'action vise wp-comments-post.php")
    return markers


def _href(tag: str) -> str:
    m = _HREF.search(tag or "")
    return (m.group(1) or m.group(2) or m.group(3) or "") if m else ""


def _usable_article(check: BaseCheck, url: str) -> bool:
    """URL d'article sur la cible, distincte de l'accueil, demandable dans le
    mode courant (référencée, donc niveau 0 ou 1 sans --authorized)."""
    if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
        return False
    parts = urlsplit(url)
    if (parts.hostname or "").lower() not in access_tiers.scope_hosts(check.target):
        return False
    if url.split("#", 1)[0].rstrip("/") == check.target.rstrip("/"):
        return False
    if _NOT_ARTICLE.search(parts.path or ""):
        return False
    return check.may_request(url)


def _article_from_rest(check: BaseCheck) -> Optional[Tuple[str, str]]:
    data, resp = check.get_json("wp-json/wp/v2/posts?per_page=1")
    if resp is None or resp.status_code != 200 or not isinstance(data, list):
        return None
    for post in data:
        link = post.get("link") if isinstance(post, dict) else None
        if _usable_article(check, link):
            return link, "API REST wp-json/wp/v2/posts?per_page=1"
    return None


def _article_from_home(check: BaseCheck) -> Optional[Tuple[str, str]]:
    try:
        resp = check.http_get("")
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    body = resp.text or ""
    base = resp.url or check.target.rstrip("/") + "/"
    tags = _A_TAG.findall(body)
    candidates = [_href(t) for t in tags if _REL_BOOKMARK.search(t)]
    candidates += [_href(m.group(1)) for m in _TITLE_LINK.finditer(body)]
    candidates += [h for h in (_href(t) for t in tags)
                   if _POST_URL.search(urljoin(base, h).split("#", 1)[0])]
    for href in candidates:
        url = urljoin(base, href).split("#", 1)[0]
        if href and _usable_article(check, url):
            return url, "lien de la page d'accueil"
    return None


def find_article(check: BaseCheck) -> Optional[Tuple[str, str]]:
    """(URL, source) d'un article réel de la cible, ou None.

    Source : la liste REST des articles (niveau 1), sinon un lien d'article
    de la page d'accueil (niveau 0). Mémoïsé sur la session de l'audit : les
    checks qui l'utilisent testent le même article.
    """
    cached = getattr(check.session, "_wpsf_article", _UNSET)
    if cached is not _UNSET:
        return cached
    found = _article_from_rest(check) or _article_from_home(check)
    try:
        check.session._wpsf_article = found
    except AttributeError:
        pass
    return found


class WPFeaturesCheck(BaseCheck):
    """Check WordPress features that are commonly exploited attack vectors."""

    name = "wp_features"
    title = "WordPress Features Security Audit"
    description = (
        "Checks WordPress-specific features (XML-RPC, WP-Cron, oEmbed, "
        "Application Passwords, Site Health, Block Directory, "
        "Trackback, Comments, Link Manager) for security misconfigurations."
    )
    severity = "CRITICAL"
    access_tier = 1  # xmlrpc.php en GET, routes REST, accueil
    depends_on: List[str] = []

    def __init__(self, target: str, config: dict, session):
        super().__init__(target, config, session)

    # ── Public API ──────────────────────────────────────────────────────

    def run(self) -> CheckResult:
        """Execute all WordPress features security checks."""
        self._check_xmlrpc_availability()       # 1  : endpoint actif (GET)
        self._check_wp_cron()                    # 2  : WP-Cron
        self._check_oembed()                     # 3  : oEmbed (index REST)
        self._check_application_passwords()      # 5 , App Passwords (HIGH)
        self._check_site_health()                # 6 , Site Health (HIGH)
        self._check_block_directory()            # 7 , Block Directory
        self._check_trackback_html()             # 8 , Trackback RDF
        self._check_comments_open()              # 9 , Comments
        self._check_link_manager()               # 10, Link Manager
        self._report_not_assessable()            # sous-contrôles retirés (actifs)
        return self._result

    def _report_not_assessable(self) -> None:
        """Constat INFO : sous-contrôles retirés car ils exigeaient un POST."""
        self._result.add_finding(
            message=(
                "Sous-contrôles non évaluables passivement : introspection "
                "XML-RPC (system.listMethods), API Heartbeat (admin-ajax.php)"
            ),
            severity="INFO",
            evidence=(
                "Ces vérifications exigent un POST vers la cible, que le scanner "
                "n'envoie jamais (lecture seule : GET, HEAD, OPTIONS). À vérifier "
                "manuellement, dans un cadre autorisé."
            ),
            url=self.target.rstrip("/"),
            confidence="potential",
        )

    # ── 1) XML-RPC endpoint availability (GET seul) ───────────────────────

    def _check_xmlrpc_availability(self) -> None:
        """xmlrpc.php est-il servi par le serveur XML-RPC de WordPress ?

        Un GET suffit : le serveur répond « XML-RPC server accepts POST
        requests only. » quand il est actif. Aucun appel XML-RPC n'est envoyé.
        """
        resp = self._safe_get("xmlrpc.php", allow_redirects=False)
        if resp is None:
            return

        status = resp.status_code
        if status in (401, 403, 404, 410):
            return  # Blocked or not found

        body = resp.text or ""
        content_type = resp.headers.get("Content-Type", "")
        url = f"{self.target.rstrip('/')}/xmlrpc.php"

        if xmlrpc_server_active(body):
            self._result.add_finding(
                message="XML-RPC endpoint fully accessible (xmlrpc.php)",
                severity="HIGH",
                evidence=(
                    "XML-RPC endpoint accessible\n"
                    f"GET xmlrpc.php : HTTP {status}\n"
                    "Réponse « XML-RPC server accepts POST requests only. » : "
                    "le serveur XML-RPC de WordPress est actif (détection "
                    "passive, aucun appel XML-RPC envoyé)."
                ),
                url=url,
            )
        elif status in (200, 405) and not self._is_soft404(resp):
            self._result.add_finding(
                message="xmlrpc.php exists but may be disabled",
                severity="LOW",
                evidence=(
                    f"xmlrpc.php responds (GET HTTP {status}) sans la signature "
                    "du serveur XML-RPC\n"
                    f"Content-Type: {content_type}\n"
                    f"Response snippet: {body[:200]}"
                ),
                url=url,
            )

    # ── 2) WP-Cron detection ────────────────────────────────────────────

    def _check_wp_cron(self) -> None:
        """WP-Cron : sonde retirée. Demander wp-cron.php (HEAD ou GET) lance
        les tâches planifiées du site : interdit à tout niveau d'accès."""
        self.note_not_assessable(
            "WP-Cron (wp-cron.php)", server_work=True,
            evidence="Demander wp-cron.php lance les tâches planifiées du site")

    # ── 3) oEmbed endpoint ──────────────────────────────────────────────

    def _check_oembed(self) -> None:
        """oEmbed : route présente dans l'index REST (jamais appelée avec une
        URL, donc aucune récupération déclenchée côté cible)."""
        data, index_url = self.rest_index()
        routes = data.get("routes") if isinstance(data, dict) else None
        if not isinstance(routes, dict) or "/oembed/1.0/embed" not in routes:
            return

        self._result.add_finding(
            message="oEmbed endpoint actif (wp-json/oembed/1.0/embed, natif WordPress)",
            severity="INFO",
            evidence=(
                f"Route /oembed/1.0/embed publiée dans l'index REST ({index_url}).\n"
                "Note : /embed est actif par défaut et ne renvoie que les "
                "métadonnées des contenus DU site ; le vecteur SSRF serait "
                "/proxy, qui exige l'authentification. Aucune URL n'a été "
                "soumise (détection passive)."
            ),
            url=f"{self.target.rstrip('/')}/wp-json/oembed/1.0/embed",
            confidence="potential",
        )

    # ── 5) Application Passwords (WP 5.6+) ──────────────────────────────

    def _check_application_passwords(self) -> None:
        """Check if Application Passwords endpoint exists (WP 5.6+)."""
        resp = self._safe_get(
            "wp-json/wp/v2/users/me/application-passwords"
        )
        if resp is None:
            return

        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "")
        body = resp.text
        allow = resp.headers.get("Allow", "")

        # 401 = endpoint exists but requires auth (feature is active)
        # 404 = endpoint not found (WP < 5.6 or feature disabled)
        # 200 = exposed without auth (rare but severe)
        if status == 401:
            evidence_lines = [
                "Application Passwords endpoint exists (WP 5.6+ feature enabled)",
                f"HTTP {status} (Unauthorized, endpoint active, auth required)",
                f"Content-Type: {content_type}",
            ]
            if allow:
                evidence_lines.append(f"Allow: {allow}")

            # Check if the response indicates REST API is active
            try:
                data = resp.json()
                if isinstance(data, dict) and "code" in data:
                    evidence_lines.append(f"REST API code: {data.get('code', '')}")
            except Exception:
                pass

            evidence_lines.append(
                "Note : Application Passwords est activé PAR DÉFAUT depuis WP 5.6 "
                "et 401 = état sécurisé (auth requise). Feature normale."
            )

            evidence = "\n".join(evidence_lines)

            self._result.add_finding(
                message="Application Passwords endpoint present (401, auth requise, normal)",
                severity="INFO",
                evidence=evidence,
                confidence="potential",
                url=(
                    f"{self.target.rstrip('/')}"
                    "/wp-json/wp/v2/users/me/application-passwords"
                ),
            )

        elif status == 200:
            # Exposed without auth, critical
            evidence = (
                "Application Passwords endpoint EXPOSED without authentication!\n"
                f"HTTP {status}\n"
                f"Content-Type: {content_type}\n"
                f"Response: {body[:500]}"
            )
            self._result.add_finding(
                message="Application Passwords endpoint exposed without authentication",
                severity="CRITICAL",
                evidence=evidence,
                url=(
                    f"{self.target.rstrip('/')}"
                    "/wp-json/wp/v2/users/me/application-passwords"
                ),
            )

        elif status != 404:
            # Some other status, endpoint may be partially accessible
            evidence = (
                f"Application Passwords endpoint responds (HTTP {status})\n"
                f"Content-Type: {content_type}\n"
                f"Response: {body[:200]}"
            )
            self._result.add_finding(
                message=f"Application Passwords endpoint responds (HTTP {status})",
                severity="MEDIUM",
                evidence=evidence,
                url=(
                    f"{self.target.rstrip('/')}"
                    "/wp-json/wp/v2/users/me/application-passwords"
                ),
            )

    # ── 6) Site Health endpoint ─────────────────────────────────────────

    def _check_site_health(self) -> None:
        """Check if Site Health endpoint is accessible (info disclosure)."""
        resp = self._safe_get("wp-json/wp-site-health/v1")
        if resp is None:
            return

        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "")
        body = resp.text

        # 200 sur la racine du namespace = listing de routes, PUBLIC par
        # design en WordPress (cf. downgrade équivalent pour l'énumération
        # générique de namespaces dans rest_api.py). Les sous-endpoints de
        # test (ex: .../tests/background-updates) ne sont jamais appelés :
        # chacun exécute un diagnostic côté serveur (constat INFO dédié).
        # 401 = endpoint exists, feature active
        # 404 = WP < 5.2 or disabled
        if status == 200 and "json" in content_type.lower():
            try:
                data = resp.json()
                evidence_lines = [
                    "Namespace Site Health accessible (racine du namespace)",
                    f"HTTP {status}",
                ]
                # Extract info (listing de routes, pas de données sensibles)
                if isinstance(data, dict):
                    for key in data:
                        val = data[key]
                        if isinstance(val, (str, int, float, bool)):
                            evidence_lines.append(f"  {key}: {val}")
                        elif isinstance(val, dict):
                            for k2 in list(val.keys())[:5]:
                                v2 = val[k2]
                                if isinstance(v2, (str, int, float, bool)):
                                    evidence_lines.append(f"  {key}.{k2}: {v2}")
                evidence_lines.append(
                    "Note : le listing de routes d'un namespace REST est "
                    "public par design en WordPress. Les sous-endpoints de "
                    "test (ex: tests/background-updates) exigent "
                    "normalement manage_options et ne sont pas appelés."
                )
                evidence = "\n".join(evidence_lines)

                self._result.add_finding(
                    message=(
                        "Namespace Site Health accessible "
                        "(listing de routes public, normal en WordPress)"
                    ),
                    severity="INFO",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/wp-json/wp-site-health/v1",
                    confidence="potential",
                )
            except Exception:
                # Not valid JSON
                pass

        elif status == 401:
            evidence_lines = [
                "Site Health endpoint exists (wp-json/wp-site-health/v1)",
                f"HTTP {status} (Unauthorized, requires auth, but feature is active)",
                f"Content-Type: {content_type}",
            ]
            # Les sous-endpoints de test ne sont pas appelés : chacun
            # exécute un diagnostic côté serveur (constat INFO dédié).
            evidence_lines.append(
                "\nSous-endpoints de test non appelés : chacun exécute un "
                "diagnostic côté serveur (voir le constat « non évaluable »)."
            )
            self._result.add_finding(
                message="Site Health endpoint present (401, auth requise, normal)",
                severity="INFO",
                evidence="\n".join(evidence_lines),
                url=f"{self.target.rstrip('/')}/wp-json/wp-site-health/v1",
                confidence="potential",
            )

        elif status not in (404, 403):
            # Some other response, note it
            evidence = (
                f"Site Health endpoint responds (HTTP {status})\n"
                f"Content-Type: {content_type}\n"
                f"Response: {body[:200]}"
            )
            self._result.add_finding(
                message=f"Site Health endpoint accessible (HTTP {status})",
                severity="MEDIUM",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-json/wp-site-health/v1",
            )

        if status not in (404, 403, 410):
            self.note_not_assessable(
                "Points de test Site Health (tests/background-updates, "
                "tests/loopback-requests, tests/rest-availability)",
                server_work=True,
                evidence=("Chaque point de test exécute un diagnostic côté "
                          "serveur (requête en boucle locale, accès disque)"))

    # ── 7) Block directory ──────────────────────────────────────────────

    def _check_block_directory(self) -> None:
        """Check if Block Directory search endpoint exists (SSRF vector)."""
        resp = self._safe_get(
            "wp-json/wp/v2/block-directory/search?term=test"
        )
        if resp is None:
            return

        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "")
        body = resp.text

        # 401/403 = endpoint exists but auth required (WP 5.5+ feature active)
        # 200 = accessible without auth (rare)
        # 404 = disabled or WP < 5.5
        if status in (401, 403):
            evidence_lines = [
                "Block Directory endpoint exists (wp-json/wp/v2/block-directory/search)",
                f"HTTP {status} (requires authentication, feature is active)",
                f"Content-Type: {content_type}",
            ]

            try:
                data = resp.json()
                if isinstance(data, dict) and "code" in data:
                    evidence_lines.append(f"REST API code: {data.get('code', '')}")
            except Exception:
                pass

            evidence_lines.append(
                "Note : endpoint natif à destination FIXE (api.wordpress.org) et "
                "protégé par authentification, pas un SSRF exploitable (aucune URL "
                "contrôlable par l'attaquant, accès non anonyme)."
            )

            evidence = "\n".join(evidence_lines)

            # 401/403 + destination fixe = PAS un SSRF exploitable → INFO, pas MEDIUM.
            self._result.add_finding(
                message=(
                    "Block Directory présent (auth requise, destination fixe "
                    "api.wordpress.org, pas un SSRF exploitable)"
                ),
                severity="INFO",
                evidence=evidence,
                url=(
                    f"{self.target.rstrip('/')}"
                    "/wp-json/wp/v2/block-directory/search"
                ),
                confidence="potential",
            )

        elif status == 200:
            evidence_lines = [
                "Block Directory search endpoint accessible without authentication!",
                f"HTTP {status}",
                f"Content-Type: {content_type}",
            ]
            try:
                data = resp.json()
                if isinstance(data, list):
                    evidence_lines.append(
                        f"Response contains {len(data)} results"
                    )
            except Exception:
                evidence_lines.append(f"Response: {body[:200]}")

            evidence_lines.append(
                "Impact: SSRF to api.wordpress.org, confirms "
                "external HTTP requests are possible"
            )

            evidence = "\n".join(evidence_lines)

            self._result.add_finding(
                message="Block Directory search accessible without authentication",
                severity="HIGH",
                evidence=evidence,
                url=(
                    f"{self.target.rstrip('/')}"
                    "/wp-json/wp/v2/block-directory/search"
                ),
            )

    # ── 8) Trackback detection ──────────────────────────────────────────

    def _check_trackback_html(self) -> None:
        """Check for trackback RDF in the HTML head of the homepage."""
        resp = self._safe_get("")
        if resp is None:
            return

        body = resp.text
        content_type = resp.headers.get("Content-Type", "")

        if "html" not in content_type.lower():
            return  # Not HTML

        # Look for trackback RDF block in HTML head
        trackback_pattern = (
            r'<rdf:RDF[^>]*xmlns:trackback='
            r'["\']http://madskills\.com/public/xmlrpc/ext/trackback/["\']'
        )
        has_trackback_rdf = bool(re.search(trackback_pattern, body, re.IGNORECASE))

        if has_trackback_rdf:
            # Extract the trackback URLs
            tb_urls = re.findall(
                r'trackback:ping=["\']([^"\']+)["\']',
                body,
            )
            evidence_lines = [
                "Trackback RDF found in HTML head",
            ]
            if tb_urls:
                evidence_lines.append(f"Trackback ping URLs found ({len(tb_urls)}):")
                for url in tb_urls[:5]:
                    evidence_lines.append(f"  {url}")

            evidence_lines.append("Impact: Trackback/pingback feature enabled, SSRF and spam vector")

            evidence = "\n".join(evidence_lines)

            self._result.add_finding(
                message="Trackback RDF detected in homepage HTML",
                severity="LOW",
                evidence=evidence,
                url=self.target.rstrip("/"),
            )

    # ── 9) Comments open ────────────────────────────────────────────────

    _COMMENTS_ADVICE = (
        "Recommandation : les fermer s'ils ne servent pas (Réglages > "
        "Discussion, et sur les contenus déjà publiés), une porte d'entrée "
        "en moins.")

    def _home_comment_signals(self) -> Tuple[List[str], bool, bool]:
        """Indices de commentaires sur la page d'accueil : (lignes de preuve
        si ouverts, formulaire réel vu, fermeture explicite)."""
        resp = self._safe_get("")
        if resp is None or "html" not in resp.headers.get("Content-Type", "").lower():
            return [], False, False
        body = resp.text or ""
        markers = comment_form_markers(body)
        loose_form = bool(re.search(r"<form[^>]*comment[^>]*>", body, re.I))
        closed = bool(_COMMENTS_CLOSED.search(body))
        comment_count = len(re.findall(r'id=["\']comment[-_]', body))
        has_respond = bool(re.search(r'id=["\']respond["\']', body))
        if not (markers or loose_form or has_respond
                or (comment_count > 0 and not closed)):
            return [], False, closed
        lines = [f"Page d'accueil {self.target.rstrip('/')}/ :"]
        lines += [f"  - {m}" for m in markers]
        if loose_form and not markers:
            lines.append("  - formulaire lié aux commentaires")
        if has_respond:
            lines.append("  - section #respond")
        if comment_count > 0:
            lines.append(f"  - {comment_count} élément(s) de commentaire")
        return lines, bool(markers or loose_form), closed

    def _comments_feed_line(self) -> Optional[str]:
        """État du flux des commentaires (comments/feed/, niveau 1)."""
        resp = self._safe_get("comments/feed/")
        if resp is None or resp.status_code != 200:
            return None
        body = resp.text or ""
        head = body[:4096].lower()
        if ("<rss" not in head and "<feed" not in head) or self._is_soft404(resp):
            return None
        count = (len(re.findall(r"<item[\s>]", body, re.I))
                 or len(re.findall(r"<entry[\s>]", body, re.I)))
        return (f"Flux des commentaires comments/feed/ actif : {count} "
                "commentaire(s) publié(s) dans le flux.")

    def _check_comments_open(self) -> None:
        """Commentaires ouverts sur la page d'accueil ou sur un article réel.

        Lecture seule : le formulaire est seulement repéré, jamais soumis.
        """
        open_lines, real_form, home_closed = self._home_comment_signals()
        closed_lines = (["Page d'accueil : commentaires explicitement fermés."]
                        if home_closed and not open_lines else [])
        url = self.target.rstrip("/") + "/"

        article = find_article(self)
        if article:
            article_url, source = article
            resp = None
            try:
                resp = self.http_get_url(article_url)
            except Exception:
                resp = None
            if resp is not None and resp.status_code == 200:
                body = resp.text or ""
                markers = comment_form_markers(body)
                if markers:
                    open_lines += [f"Article {article_url} (source : {source}) :"]
                    open_lines += [f"  - {m}" for m in markers]
                    real_form, url = True, article_url
                else:
                    state = (" ; commentaires explicitement fermés"
                             if _COMMENTS_CLOSED.search(body) else "")
                    closed_lines.append(
                        f"Article {article_url} (source : {source}) : aucun "
                        f"formulaire de commentaire{state}.")

        if not open_lines and not closed_lines:
            return
        feed = self._comments_feed_line()
        if open_lines:
            self._result.add_finding(
                message="Commentaires ouverts (formulaire de commentaire visible)",
                severity="LOW",
                evidence="\n".join(
                    open_lines + ([feed] if feed else [])
                    + ["Lecture seule : aucun commentaire n'a été soumis.",
                       "Un formulaire ouvert reçoit spam, liens malveillants et "
                       "tentatives d'injection.", self._COMMENTS_ADVICE]),
                url=url,
                confidence="confirmed" if real_form else "potential",
            )
        else:
            self._result.add_finding(
                message="Commentaires fermés sur les pages testées",
                severity="INFO",
                evidence="\n".join(closed_lines + ([feed] if feed else [])),
                url=url,
            )

    # ── 10) Link Manager ────────────────────────────────────────────────

    def _check_link_manager(self) -> None:
        """Check if Link Manager REST API endpoint exists."""
        resp = self._safe_get("wp-json/wp/v2/links")
        if resp is None:
            return

        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "")
        body = resp.text

        # 401 = endpoint exists (Link Manager active)
        # 200 = accessible without auth (info leak)
        # 404 = disabled or WP 5.5+
        if status == 401:
            evidence_lines = [
                "Link Manager endpoint exists (wp-json/wp/v2/links)",
                f"HTTP {status} (requires authentication, Link Manager active)",
                f"Content-Type: {content_type}",
            ]

            # Also check link-categories
            cat_resp = self._safe_get("wp-json/wp/v2/link-categories")
            if cat_resp is not None and cat_resp.status_code != 404:
                evidence_lines.append(
                    f"Link Categories endpoint also active (HTTP {cat_resp.status_code})"
                )

            evidence_lines.append(
                "Impact: Legacy feature indicator (WP 3.5-5.5). "
                "Potential info disclosure of stored links/partners."
            )

            evidence = "\n".join(evidence_lines)

            self._result.add_finding(
                message="Link Manager endpoint active (wp-json/wp/v2/links)",
                severity="LOW",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-json/wp/v2/links",
            )

        elif status == 200:
            try:
                data = resp.json()
                link_count = len(data) if isinstance(data, list) else "N/A"
                evidence_lines = [
                    "Link Manager endpoint EXPOSED without authentication!",
                    f"HTTP {status}",
                    f"Links found: {link_count}",
                ]
                if isinstance(data, list) and data:
                    for link in data[:5]:
                        title = link.get("title", {}).get("rendered", "?")
                        url_val = link.get("link", "?") or link.get("url", "?")
                        evidence_lines.append(f"  - {title}: {url_val}")
                evidence = "\n".join(evidence_lines)

                self._result.add_finding(
                    message="Link Manager endpoint exposed without authentication",
                    severity="HIGH",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/wp-json/wp/v2/links",
                )
            except Exception:
                evidence = (
                    f"Link Manager endpoint responds (HTTP {status})\n"
                    f"Content-Type: {content_type}\n"
                    f"Response: {body[:200]}"
                )
                self._result.add_finding(
                    message=f"Link Manager endpoint accessible (HTTP {status})",
                    severity="MEDIUM",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/wp-json/wp/v2/links",
                )

    # ── HTTP helpers ────────────────────────────────────────────────────

    def _safe_get(self, path: str, **kwargs) -> Optional[requests.Response]:
        """Safe GET that returns None on connection errors."""
        try:
            return self.http_get(path, **kwargs)
        except Exception:
            return None

    def _safe_head(self, path: str, **kwargs) -> Optional[requests.Response]:
        """Safe HEAD that returns None on connection errors."""
        try:
            return self.http_head(path, **kwargs)
        except Exception:
            return None
