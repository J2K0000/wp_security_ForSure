"""Lecture d'une page HTML pour la détection d'injections : scripts, iframes,
redirections, liens. Aucune requête réseau, aucune exécution.

Sert au check ``visit_profiles`` (comparaison de profils de visite), au check
``client_injection`` (signatures dans les scripts) et à la passe de rendu.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

# Suffixes publics à deux niveaux les plus courants. Approximation volontaire
# (pas de liste publique des suffixes embarquée) : sert seulement à ne pas
# traiter « m.exemple.fr » ou « cdn.exemple.co.uk » comme un autre site.
_TWO_LEVEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.mx",
    "co.za", "co.in", "com.tr", "com.ar", "co.kr", "com.sg", "com.hk",
    "gouv.fr", "asso.fr", "com.es", "com.pl", "co.il", "com.tw",
})


def registrable_domain(host: str) -> str:
    """Domaine enregistrable approché : deux derniers libellés, trois pour
    les suffixes à deux niveaux courants. Une IP est rendue telle quelle."""
    host = (host or "").lower().rstrip(".")
    if not host or re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_site(host_a: str, host_b: str) -> bool:
    return bool(host_a) and registrable_domain(host_a) == registrable_domain(host_b)


def host_of(url: str) -> str:
    return (urlsplit(url or "").hostname or "").lower()


@dataclass
class Script:
    src: str = ""          # URL absolue, ou URL data: telle quelle ; vide si en ligne
    inline: str = ""       # contenu du script en ligne
    type: str = ""


@dataclass
class PageFeatures:
    """Ce qu'une page charge ou déclenche, tel que le HTML le déclare."""
    scripts: List[Script] = field(default_factory=list)
    iframes: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    meta_refresh: str = ""
    js_redirects: List[str] = field(default_factory=list)
    text_length: int = 0

    @property
    def script_srcs(self) -> List[str]:
        return [s.src for s in self.scripts if s.src and not s.src.startswith("data:")]

    @property
    def inline_scripts(self) -> List[str]:
        return [s.inline for s in self.scripts if not s.src and s.inline]

    @property
    def data_scripts(self) -> List[str]:
        return [s.src for s in self.scripts if s.src.lower().startswith("data:")]


_JS_REDIRECT_RE = re.compile(
    r"""(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*['"](https?://[^'"\s]+)"""
    r"""|location\.(?:replace|assign)\s*\(\s*['"](https?://[^'"\s]+)""",
    re.I)
_META_REFRESH_URL_RE = re.compile(r"url\s*=\s*['\"]?([^'\";\s]+)", re.I)
# Types de script exécutables (un bloc JSON-LD ou un gabarit n'en est pas un).
_EXECUTABLE_TYPES = ("", "text/javascript", "application/javascript", "module",
                     "text/ecmascript", "application/ecmascript")


class _Parser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.features = PageFeatures()
        self._in_script: Optional[Script] = None
        self._chunks: List[str] = []
        self._text = 0

    def _abs(self, value: str) -> str:
        value = (value or "").strip()
        if not value or value.lower().startswith(("data:", "javascript:", "about:", "blob:")):
            return value
        try:
            return urljoin(self.base_url, value)
        except ValueError:
            return ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            stype = a.get("type", "").strip().lower()
            self._in_script = Script(src=self._abs(a.get("src", "")), type=stype)
            self._chunks = []
        elif tag in ("iframe", "frame"):
            src = self._abs(a.get("src", ""))
            if src:
                self.features.iframes.append(src)
        elif tag == "a":
            href = self._abs(a.get("href", ""))
            if href.lower().startswith(("http://", "https://")):
                self.features.links.append(href)
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = _META_REFRESH_URL_RE.search(a.get("content", ""))
            if m:
                self.features.meta_refresh = self._abs(m.group(1))

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script is not None:
            script = self._in_script
            script.inline = "".join(self._chunks) if not script.src else ""
            if script.type in _EXECUTABLE_TYPES or script.src:
                self.features.scripts.append(script)
                if script.inline:
                    for m in _JS_REDIRECT_RE.finditer(script.inline):
                        self.features.js_redirects.append(m.group(1) or m.group(2))
            self._in_script = None
            self._chunks = []

    def handle_data(self, data):
        if self._in_script is not None:
            self._chunks.append(data)
        else:
            self._text += len(data.strip())


def parse_page(html: str, base_url: str) -> PageFeatures:
    """Scripts, iframes, liens et redirections déclarés par une page."""
    parser = _Parser(base_url)
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass  # HTML cassé : on garde ce qui a été lu
    if parser._in_script is not None:  # script non fermé
        parser.handle_endtag("script")
    parser.features.text_length = parser._text
    return parser.features


# ── Chargeur en ligne ────────────────────────────────────────────────────

_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")
_RUN_RE = re.compile(r"\batob\s*\(|\beval\s*\(|\bnew\s+Function\s*\(|decodeURIComponent\s*\(", re.I)


def is_inline_loader(script: str) -> bool:
    """Script en ligne qui contient une longue chaîne base64 et la décode ou
    l'exécute : forme du chargeur en ligne décrit par Rapid7 (2026)."""
    return bool(script and _LONG_B64_RE.search(script) and _RUN_RE.search(script))


def normalized_hash(script: str) -> str:
    """Empreinte d'un script en ligne, nombres et jetons longs neutralisés
    (nonces, horodatages, ?ver=)."""
    text = re.sub(r"[A-Za-z0-9+/_-]{16,}={0,2}", "X", script or "")
    text = re.sub(r"\d+", "0", text)
    text = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


# ── Pages internes à comparer ────────────────────────────────────────────

_SKIP_PATH_RE = re.compile(
    r"/(?:wp-admin|wp-login\.php|wp-json|xmlrpc\.php|wp-content|wp-includes|feed|"
    r"comments|trackback|cart|panier|my-account|mon-compte|wp-signup\.php)(?:/|$)"
    r"|\.(?:php\d?|js|css|png|jpe?g|gif|webp|svg|ico|pdf|zip|xml|txt|mp4|mp3|woff2?)$",
    re.I)
_ARTICLE_HINT_RE = re.compile(r"/\d{4}/\d{2}/|/(?:blog|actualites?|news|article|post)s?/", re.I)


def internal_pages(links: List[str], target: str, limit: int = 2) -> List[str]:
    """Pages internes liées depuis l'accueil, sans paramètres de requête (un
    lien à paramètres peut déclencher une action, comme ?add-to-cart=),
    articles d'abord."""
    target_host = host_of(target)
    seen: Set[str] = set()
    articles, others = [], []
    for link in links:
        parts = urlsplit(link)
        host = (parts.hostname or "").lower()
        bare = target_host[4:] if target_host.startswith("www.") else target_host
        if host not in (bare, f"www.{bare}") or parts.query:
            continue
        path = parts.path or "/"
        if path in ("", "/") or _SKIP_PATH_RE.search(path):
            continue
        url = f"{parts.scheme}://{parts.netloc}{path}"
        if url in seen:
            continue
        seen.add(url)
        (articles if _ARTICLE_HINT_RE.search(path) else others).append(url)
    return (articles + others)[:max(0, limit)]


def checkout_page(links: List[str], target: str) -> Optional[str]:
    """Page de paiement WooCommerce liée depuis l'accueil, si elle existe."""
    target_host = host_of(target)
    bare = target_host[4:] if target_host.startswith("www.") else target_host
    for link in links:
        parts = urlsplit(link)
        if ((parts.hostname or "").lower() in (bare, f"www.{bare}") and not parts.query
                and re.search(r"/(?:checkout|commande|validation-de-la-commande)/?$",
                              parts.path or "", re.I)):
            return f"{parts.scheme}://{parts.netloc}{parts.path}"
    return None


def offsite_hosts(urls: List[str], target: str) -> Set[str]:
    """Hôtes des URL qui appartiennent à un autre site que la cible."""
    th = host_of(target)
    return {h for h in (host_of(u) for u in urls) if h and not same_site(h, th)}


def split_by_site(urls: List[str], target: str) -> Tuple[List[str], List[str]]:
    """(URL du site cible, URL d'autres sites)."""
    th = host_of(target)
    mine, other = [], []
    for u in urls:
        (mine if same_site(host_of(u), th) else other).append(u)
    return mine, other
