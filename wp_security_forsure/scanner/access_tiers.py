"""Niveaux d'accès des requêtes vers la cible : source unique.

Le scanner ne sonde par défaut que ce qu'un visiteur ou un client WordPress
standard demande. La recherche de chemins non liés est réservée à l'audit
d'un site dont le propriétaire a donné son autorisation écrite (option
``authorized`` / ``--authorized``). Lecture du droit pénal français qui fonde
ce choix : articles 323-1 (accès frauduleux) et 323-3-1 (outil conçu pour
une atteinte) du Code pénal.

  Niveau 0  la page d'accueil et les ressources qu'elle référence (scripts,
            feuilles de style, images, liens, hôtes tiers cités) ;
  Niveau 1  les points d'entrée publics standard de WordPress
            (PUBLIC_ENTRY_POINTS et requêtes de l'accueil ci-dessous), et les
            ressources référencées par une autre page déjà récupérée ;
  Niveau 2  tout le reste : chemin deviné et non lié (sauvegardes, .env, .git/,
            listings de répertoires, readme.txt de plugins devinés...).

Interdit à tout niveau (forbidden_reason) : toute requête qui déclenche un
travail côté serveur ou exécute un fichier deviné, quel que soit le mode.

Seules les requêtes vers la cible (son hôte et sa variante www.) sont classées ;
un hôte tiers (CDN cité par la page, base de vulnérabilités) ne l'est pas. Une
redirection n'est pas reclassée : sa destination est désignée par le serveur.
"""

import posixpath
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

TIER_HOME = 0
TIER_PUBLIC = 1
TIER_UNLINKED = 2

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# « GET seulement » : GET et HEAD, qui est le même GET sans corps (RFC 9110,
# 9.3.2). Jamais OPTIONS, ni a fortiori POST.
GET_METHODS = frozenset({"GET", "HEAD"})

# Témoin d'absence (voir PUBLIC_ENTRY_POINTS) : partagé avec BaseCheck.
SOFT404_PROBE_PATH = "wpsf-probe-4f9a2c7e-does-not-exist"

QueryPairs = List[Tuple[str, str]]


def _no_query(pairs: QueryPairs) -> bool:
    return not pairs


def _any_query(pairs: QueryPairs) -> bool:
    return True


# Actions de wp-login.php liées par le formulaire de connexion standard
# (liens « Inscription » et « Mot de passe oublié ? »). Les autres (rp,
# resetpass, confirmaction, logout...) ne se devinent pas : niveau 2.
_LOGIN_ACTIONS = frozenset({"login", "register", "lostpassword"})


def _login_query(pairs: QueryPairs) -> bool:
    if not pairs:
        return True
    return len(pairs) == 1 and pairs[0][0] == "action" and pairs[0][1] in _LOGIN_ACTIONS


def _root_query(pairs: QueryPairs) -> bool:
    """Requêtes de l'accueil qu'un client WordPress standard émet.

    ?rest_route= : API REST quand les permaliens sont désactivés (les autres
    paramètres sont ceux de la route) ; ?feed= : flux ; ?author=N : archive
    d'auteur (lien de tout thème) ; ?s= : formulaire de recherche du thème ;
    ?p=N : lien court publié par <link rel="shortlink">.
    """
    keys = [k for k, _ in pairs]
    if "rest_route" in keys:
        return True
    if len(pairs) != 1:
        return False
    key, value = pairs[0]
    if key == "feed":
        return bool(re.fullmatch(r"[a-z0-9_-]+", value or ""))
    if key in ("author", "p"):
        return value.isdigit()
    return key == "s"


def _index_query(pairs: QueryPairs) -> bool:
    return not pairs or _root_query(pairs)


@dataclass(frozen=True)
class EntryPoint:
    """Point d'entrée public : chemin relatif à la racine du site (casse
    ignorée), méthodes admises, règle de query string, préfixe ou exact."""
    path: str
    methods: frozenset = READ_METHODS
    query: Callable[[QueryPairs], bool] = _no_query
    prefix: bool = False

    def matches(self, rel: str, method: str, pairs: QueryPairs) -> bool:
        if method not in self.methods:
            return False
        bare = self.path.rstrip("/")
        if self.prefix:
            hit = rel == bare or rel.startswith(bare + "/")
        else:
            hit = rel in (self.path, bare)
        return hit and self.query(pairs)


# ── Liste fermée du niveau 1 ─────────────────────────────────────────────
PUBLIC_ENTRY_POINTS: Tuple[EntryPoint, ...] = (
    # Index de l'API REST et ses routes, en lecture (GET, HEAD, OPTIONS) :
    # c'est l'API que le cœur publie pour tout client. OPTIONS sur une route
    # renvoie sa description sans exécuter son traitement. Les diagnostics
    # Site Health restent interdits (voir forbidden_reason).
    EntryPoint("wp-json/", query=_any_query, prefix=True),
    # Flux RSS et Atom du site et des commentaires (lecteurs de flux).
    EntryPoint("feed/", prefix=True),
    EntryPoint("comments/feed/", prefix=True),
    # xmlrpc.php en GET seulement : répond « XML-RPC server accepts POST
    # requests only. » ; ?rsd est le document annoncé par <link rel="EditURI">.
    # Aucun appel de méthode XML-RPC (POST) n'est jamais émis.
    EntryPoint("xmlrpc.php", methods=GET_METHODS, query=_any_query),
    EntryPoint("wp-login.php", query=_login_query),
    EntryPoint("robots.txt"),
    EntryPoint("sitemap.xml"),
    EntryPoint("wp-sitemap.xml"),
    EntryPoint("sitemap_index.xml"),
    # readme.html et license.txt : fichiers statiques de l'archive officielle,
    # à la racine de toute installation. Leur emplacement est une propriété de
    # WordPress, pas une supposition sur le site ; ils ne s'exécutent pas.
    EntryPoint("readme.html"),
    EntryPoint("license.txt"),
    # wp-admin/ : renvoie un visiteur non connecté vers wp-login.php
    # (auth_redirect) ; aucune page d'administration n'est demandée.
    EntryPoint("wp-admin/"),
    # admin-ajax.php en GET sans paramètre : URL publiée dans les pages
    # (variable ajaxurl des thèmes et extensions), répond « 0 » sans action.
    # Avec ?action= elle lancerait un traitement : niveau 2.
    EntryPoint("wp-admin/admin-ajax.php", methods=GET_METHODS),
    # Emplacement normalisé du contact sécurité (RFC 9116).
    EntryPoint(".well-known/security.txt"),
    # Demandé d'office par tout navigateur.
    EntryPoint("favicon.ico"),
    # Contrôleur frontal de WordPress : la même page que l'accueil, mêmes
    # requêtes admises.
    EntryPoint("index.php", query=_index_query),
    # Page d'inscription publique d'un réseau multisite : wp-login.php
    # ?action=register y redirige ; hors multisite, elle renvoie vers l'accueil.
    EntryPoint("wp-signup.php"),
    # Témoin d'absence : chemin aléatoire qui ne désigne aucune ressource. Il
    # ne cherche rien ; il mesure la réponse « page introuvable » du site
    # (soft-404) pour ne pas prendre une page d'erreur pour une ressource, comme
    # un visiteur qui suit un lien cassé.
    EntryPoint(SOFT404_PROBE_PATH),
)


# ── Normalisation ────────────────────────────────────────────────────────

_SCRIPT_RE = re.compile(r"\.(?:php\d?|phtml|phar|pht|phps)(?:[.\s]*|;.*|::\$data)$", re.I)


def scope_hosts(target: str) -> Set[str]:
    """Hôte de la cible et sa variante avec ou sans « www. »."""
    host = (urlsplit(target or "").hostname or "").lower()
    if not host:
        return set()
    other = host[4:] if host.startswith("www.") else "www." + host
    return {host, other}


def normalize_path(path: str) -> str:
    """Chemin décodé (deux fois), segments « . » et « .. » résolus, barres
    obliques doublées fusionnées ; la barre finale est conservée."""
    raw = unquote(unquote(path or "/")).replace("\\", "/")
    trailing = raw.endswith("/")
    norm = posixpath.normpath("/" + raw.lstrip("/"))
    if trailing and norm != "/":
        norm += "/"
    return norm


def _query_pairs(query: str) -> QueryPairs:
    return [(k.lower(), v) for k, v in parse_qsl(query or "", keep_blank_values=True)]


def _is_script(path: str) -> bool:
    return any(_SCRIPT_RE.search(seg) for seg in path.split("/") if seg)


def reference_key(url: str, target: str) -> Tuple[str, str, str]:
    """Clé d'une ressource : (hôte, chemin, query). Hôte vide pour la cible.
    La query n'est retenue que pour un script (paramètres) ; pour une
    ressource statique, ?ver= n'est qu'un anti-cache."""
    parts = urlsplit(url or "")
    host = (parts.hostname or "").lower()
    scope = "" if host in scope_hosts(target) else host
    path = normalize_path(parts.path)
    query = ""
    if _is_script(path):
        query = "&".join(f"{k}={v}" for k, v in sorted(_query_pairs(parts.query)))
    return scope, path, query


def _relative(url_path: str, target: str) -> str:
    """Chemin (minuscules) relatif à la racine du site cible."""
    full = normalize_path(url_path).lower()
    base = normalize_path(urlsplit(target or "").path).lower().rstrip("/")
    if base and (full == base or full.startswith(base + "/")):
        return full[len(base):].lstrip("/")
    return full.lstrip("/")


# ── Classement ───────────────────────────────────────────────────────────

def classify(method: str, url: str, target: str,
             references: Optional[Dict] = None) -> Optional[int]:
    """Niveau d'une requête vers la cible (0, 1 ou 2), ou None pour un hôte
    tiers (non classé). Ne dit rien des requêtes interdites : voir
    forbidden_reason, à consulter d'abord."""
    method = (method or "GET").upper()
    parts = urlsplit(url or "")
    if (parts.hostname or "").lower() not in scope_hosts(target):
        return None
    if references:
        known = references.get(reference_key(url, target))
        if known is not None:
            return known
    rel = _relative(parts.path, target)
    pairs = _query_pairs(parts.query)
    if rel == "":
        if not pairs:
            return TIER_HOME
        return TIER_PUBLIC if _root_query(pairs) else TIER_UNLINKED
    for entry in PUBLIC_ENTRY_POINTS:
        if entry.matches(rel, method, pairs):
            return TIER_PUBLIC
    return TIER_UNLINKED


# ── Interdit à tout niveau ───────────────────────────────────────────────

# Dossiers où un fichier PHP deviné ne doit jamais être demandé : un GET
# l'exécute (extension, drop-in db.php, object-cache.php, advanced-cache.php,
# sunrise.php, fichier déposé dans uploads/ ou mu-plugins/).
_PHP_GUARDED_DIRS = frozenset({"wp-content", "uploads", "mu-plugins"})


def forbidden_reason(url: str, target: str,
                     references: Optional[Dict] = None) -> Optional[str]:
    """Raison du refus si la requête est interdite à tout niveau, sinon None.

    - wp-cron.php (ou ?doing_wp_cron) : lance les tâches planifiées du site ;
    - diagnostics Site Health (wp-site-health/v1/...) : chaque route exécute
      un test côté serveur (requête en boucle locale, accès disque...) ;
    - fichier PHP deviné (non référencé) sous wp-content/, uploads/ ou
      mu-plugins/ : un GET l'exécute.
    Les fichiers non PHP (.user.ini, .htaccess, sauvegardes) n'en relèvent pas.
    """
    parts = urlsplit(url or "")
    path = normalize_path(parts.path).lower()
    segments = [s for s in path.split("/") if s]
    pairs = _query_pairs(parts.query)
    keys = {k for k, _ in pairs}
    if any(seg.startswith("wp-cron.php") for seg in segments) or "doing_wp_cron" in keys:
        return "wp-cron.php déclenche les tâches planifiées du site"
    route = None
    if "wp-json" in segments:
        route = "/" + "/".join(segments[segments.index("wp-json") + 1:])
    for key, value in pairs:
        if key == "rest_route":
            route = normalize_path(value).lower()
    if route and route.startswith("/wp-site-health/v1/"):
        return "un diagnostic Site Health s'exécute côté serveur"
    for i, seg in enumerate(segments):
        if _SCRIPT_RE.search(seg) and _PHP_GUARDED_DIRS & set(segments[:i]):
            if references and reference_key(url, target) in references:
                return None  # référencé par une page : pas deviné
            return ("fichier PHP deviné sous wp-content/, uploads/ ou "
                    "mu-plugins/ : un GET l'exécuterait")
    return None


# ── Ressources référencées ───────────────────────────────────────────────

_ATTR_RE = re.compile(
    r"""\b(?:src|href|data-src|poster)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))""",
    re.I)
_SRCSET_RE = re.compile(r"""\b(?:data-)?srcset\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)
_CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^'")\s]+)['"]?\s*\)""", re.I)
_ABS_URL_RE = re.compile(r"""https?://[^\s"'<>()\\\[\]{}]+""", re.I)
_BINARY_TYPES = ("image/", "font/", "audio/", "video/")
_BINARY_MARKERS = ("octet-stream", "zip", "gzip", "pdf", "x-tar", "wasm")
_MAX_REFERENCES_PER_PAGE = 5000


def extract_references(text: str, content_type: str, base_url: str) -> Iterable[str]:
    """URL absolues référencées par un document récupéré : attributs src,
    href, srcset, poster (HTML), url() (CSS), URL absolues (tout texte, y
    compris JSON aux barres échappées, XML des plans de site, en-têtes)."""
    ctype = (content_type or "").lower()
    if ctype.startswith(_BINARY_TYPES) or any(m in ctype for m in _BINARY_MARKERS):
        return []
    body = (text or "").replace("\\/", "/")
    raw: List[str] = []
    if "html" in ctype or "<" in body[:2048]:
        for m in _ATTR_RE.finditer(body):
            raw.append(m.group(1) or m.group(2) or m.group(3) or "")
        for m in _SRCSET_RE.finditer(body):
            for item in (m.group(1) or m.group(2) or "").split(","):
                token = item.strip().split(" ")[0]
                if token:
                    raw.append(token)
    raw.extend(_CSS_URL_RE.findall(body))
    raw.extend(_ABS_URL_RE.findall(body))
    out: List[str] = []
    seen: Set[str] = set()
    for candidate in raw:
        candidate = candidate.strip().replace("&amp;", "&")
        if not candidate or candidate.startswith(("#", "data:", "javascript:",
                                                  "mailto:", "tel:")):
            continue
        absolute = urljoin(base_url or "", candidate).split("#", 1)[0]
        if not absolute.lower().startswith(("http://", "https://")):
            continue
        if absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
        if len(out) >= _MAX_REFERENCES_PER_PAGE:
            break
    return out


def add_references(store: Dict, urls: Iterable[str], target: str, tier: int,
                   base_url: Optional[str] = None) -> None:
    """Enregistre des URL référencées avec le niveau de la page qui les cite
    (0 pour l'accueil, au moins 1 sinon) ; le niveau le plus bas l'emporte."""
    level = TIER_HOME if tier == TIER_HOME else max(TIER_PUBLIC, tier or TIER_PUBLIC)
    for url in urls:
        absolute = urljoin(base_url or target.rstrip("/") + "/", url)
        key = reference_key(absolute, target)
        previous = store.get(key)
        if previous is None or level < previous:
            store[key] = level


# ── Libellés communs aux rapports ────────────────────────────────────────

SKIPPED_LABEL = ("Non réalisé : nécessite --authorized (recherche de chemins "
                 "non liés)")

AUTHORIZED_WARNING = (
    "Mode --authorized actif : réservé à l'audit d'un site dont le propriétaire "
    "a donné son autorisation écrite. La recherche de chemins non liés (niveau "
    "2) est activée ; le scanner reste en lecture seule.")

_LEVEL_LABELS = {
    False: ("Niveaux 0 et 1 : page d'accueil, ressources qu'elle référence et "
            "points d'entrée publics standard de WordPress. Recherche de "
            "chemins non liés non réalisée (niveau 2, option --authorized)."),
    True: ("Niveaux 0, 1 et 2 (--authorized) : en plus des points d'entrée "
           "publics, recherche de chemins non liés, en lecture seule, sur "
           "autorisation écrite du propriétaire du site."),
}


def is_authorized(config: Optional[dict]) -> bool:
    return bool((config or {}).get("authorized"))


def access_level(config: Optional[dict]) -> dict:
    """Niveau d'accès d'un audit, pour les rapports."""
    authorized = is_authorized(config)
    return {
        "authorized": authorized,
        "max_tier": TIER_UNLINKED if authorized else TIER_PUBLIC,
        "label": _LEVEL_LABELS[authorized],
    }
