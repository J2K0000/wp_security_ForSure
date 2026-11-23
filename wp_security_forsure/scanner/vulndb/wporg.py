"""Client des API publiques de wordpress.org (répertoire et versions du cœur).

Source unique des appels à api.wordpress.org des checks (core_branch,
plugin_status, nulled_plugins). Le client ne touche jamais le réseau
lui-même : il reçoit la fonction GET du check (``BaseCheck.http_get_url``),
qui porte la garde de méthode, la garde SSRF, le budget de requêtes et la
lecture bornée. Seul hôte contacté : api.wordpress.org (tiers, jamais la
cible).

Réponses mises en cache dans le dossier de cache utilisateur
(vulndb.cache.wporg_cache_path) : 24 h pour le cœur, 7 jours pour les
extensions. Faute de réseau, une réponse en cache périmée est servie et
marquée ``stale`` ; sans cache, le résultat est « inconnu », jamais une
conclusion.

Répertoire des extensions (API 1.2, ``plugin_information``) :
  - 200 + fiche : extension publiée (``active``) ;
  - 404 (ou 200) + ``closed: true`` / ``error: closed`` : fermée (``closed``) ;
  - 404 (ou 200) + autre ``error`` : absente du répertoire (``absent`` :
    extension premium ou sur mesure, aucune conclusion) ;
  - autre statut, corps non JSON, erreur réseau : ``unknown``.
"""
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

import requests

from .matcher import compare_versions

API_HOST = "https://api.wordpress.org"
STABLE_CHECK_URL = f"{API_HOST}/core/stable-check/1.0/"
VERSION_CHECK_URL = f"{API_HOST}/core/version-check/1.7/"
CORE_TTL_DAYS = 1
PLUGIN_TTL_DAYS = 7

ACTIVE, CLOSED, ABSENT, UNKNOWN = "active", "closed", "absent", "unknown"

# Slug d'extension du répertoire : minuscules, chiffres, tirets et soulignés.
# Un slug d'une autre forme (namespace REST arbitraire de la cible) n'est
# jamais transmis à wordpress.org.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,199}$")

# Champs conservés d'une fiche d'extension (le reste n'est pas utilisé).
_PLUGIN_FIELDS = ("name", "slug", "version", "last_updated", "added",
                  "active_installs", "requires", "tested", "closed",
                  "closed_date", "reason", "reason_text", "error")

_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")

GetUrl = Callable[..., Any]


def plugin_info_url(slug: str) -> str:
    """URL de la fiche d'une extension (API 1.2, plugin_information)."""
    return (f"{API_HOST}/plugins/info/1.2/?action=plugin_information"
            f"&request[slug]={quote(slug, safe='')}")


def plugin_page_url(slug: str) -> str:
    return f"https://wordpress.org/plugins/{quote(slug, safe='')}/"


def valid_slug(slug) -> bool:
    return bool(SLUG_RE.match(str(slug or "")))


def parse_date(value) -> Optional[date]:
    """Date d'un champ wordpress.org (« 2026-11-20 4:29pm GMT », « 2026-11-09 »)."""
    m = _DATE_RE.match(str(value or "").strip())
    if not m:
        return None
    try:
        return date(*(int(g) for g in m.groups()))
    except ValueError:
        return None


def _text(value) -> Optional[str]:
    """Champ texte de l'API : `false`, vide ou absent -> None."""
    if value is None or value is False:
        return None
    text = str(value).strip()
    return text or None


# ── Extensions ───────────────────────────────────────────────────────────

def classify_plugin(raw: Optional[dict]) -> str:
    """État d'une réponse brute {status, data} (voir l'en-tête du module)."""
    if not isinstance(raw, dict):
        return UNKNOWN
    status, data = raw.get("status"), raw.get("data")
    if status not in (200, 404):
        return UNKNOWN
    if data is None:
        # API 1.0 : `null` en 200 pour un slug inexistant.
        return ABSENT if status == 200 else UNKNOWN
    if not isinstance(data, dict):
        return UNKNOWN
    if data.get("closed") is True or data.get("error") == "closed":
        return CLOSED
    if data.get("error"):
        return ABSENT
    if status == 200 and (data.get("slug") or data.get("name") or data.get("version")):
        return ACTIVE
    return UNKNOWN


@dataclass
class PluginRecord:
    slug: str
    state: str
    data: Dict[str, Any] = field(default_factory=dict)
    stale: bool = False
    fetched_at: Optional[int] = None

    @property
    def name(self) -> str:
        return _text(self.data.get("name")) or self.slug

    @property
    def version(self) -> Optional[str]:
        return _text(self.data.get("version"))

    @property
    def closed_date(self) -> Optional[str]:
        return _text(self.data.get("closed_date"))

    @property
    def reason_text(self) -> Optional[str]:
        return _text(self.data.get("reason_text"))

    @property
    def description(self) -> Optional[str]:
        return _text(self.data.get("description"))

    @property
    def last_updated(self) -> Optional[date]:
        return parse_date(self.data.get("last_updated"))


def _compact_plugin(data):
    if not isinstance(data, dict):
        return data
    out = {k: data[k] for k in _PLUGIN_FIELDS if k in data}
    if data.get("closed") is True or data.get("error") == "closed":
        # Texte de fermeture publié par wordpress.org (temporaire, définitive...).
        if data.get("description"):
            out["description"] = str(data["description"])[:500]
    return out


# ── Cœur ─────────────────────────────────────────────────────────────────

def _compact_stable(data):
    if not isinstance(data, dict):
        return None
    out = {str(k): str(v) for k, v in data.items() if isinstance(v, str)}
    return out or None


def _compact_offers(data):
    offers = data.get("offers") if isinstance(data, dict) else None
    if not isinstance(offers, list):
        return None
    out = [{"response": o.get("response"), "version": o.get("version"),
            "current": o.get("current")}
           for o in offers if isinstance(o, dict) and o.get("version")]
    return {"offers": out} if out else None


def normalize_core_version(version: str) -> str:
    """6.4.0 -> 6.4 (clé de stable-check pour une version majeure)."""
    v = str(version or "").strip()
    parts = v.split(".")
    if len(parts) == 3 and parts[2] == "0":
        return ".".join(parts[:2])
    return v


def branch_of(version: str) -> str:
    return ".".join(str(version or "").split(".")[:2])


def _in_branch(version: str, branch: str) -> bool:
    return version == branch or version.startswith(branch + ".")


def _max_version(versions: List[str]) -> Optional[str]:
    best = None
    for v in versions:
        if v and (best is None or compare_versions(v, best) > 0):
            best = v
    return best


# Verdicts de assess_core.
INSECURE = "insecure"            # marquée insecure par wordpress.org
BEHIND_BRANCH = "behind_branch"  # en retard sur sa branche, non marquée insecure
OLD_BRANCH = "old_branch"        # dernière de sa branche, branche ancienne
LATEST = "latest"                # dernière version publiée
UNKNOWN_VERSION = "unknown"      # inconnue de wordpress.org


@dataclass
class CoreAssessment:
    version: str
    status: Optional[str]          # valeur de stable-check, ou None
    branch: str
    branch_latest: Optional[str]
    latest: Optional[str]
    verdict: str


def assess_core(version: str, stable: Dict[str, str],
                offers: Optional[dict] = None) -> CoreAssessment:
    """Situe `version` par rapport aux données de wordpress.org.

    `stable` : réponse de stable-check (version -> latest/outdated/insecure).
    `offers` : réponse compactée de version-check ({"offers": [...]}), ou None.
    La dernière version d'une branche est la plus haute connue des deux
    sources (offre « autoupdate » de la branche, versions de stable-check).
    """
    key = normalize_core_version(version)
    status = stable.get(key) or stable.get(str(version))
    branch = branch_of(key)
    offer_versions = [str(o.get("version")) for o in (offers or {}).get("offers", [])
                      if o.get("version")]
    upgrade = [str(o.get("version")) for o in (offers or {}).get("offers", [])
               if o.get("response") == "upgrade" and o.get("version")]
    latest = (_max_version(upgrade) or _max_version(offer_versions)
              or _max_version([v for v, s in stable.items() if s == "latest"]))
    branch_latest = _max_version(
        [v for v in offer_versions + list(stable) if _in_branch(v, branch)])

    if status == "insecure":
        verdict = INSECURE
    elif branch_latest and compare_versions(key, branch_latest) < 0:
        verdict = BEHIND_BRANCH
    elif status == "outdated":
        verdict = OLD_BRANCH
    elif status == "latest":
        verdict = LATEST
    else:
        verdict = UNKNOWN_VERSION
    return CoreAssessment(version=str(version), status=status, branch=branch,
                          branch_latest=branch_latest, latest=latest,
                          verdict=verdict)


# ── Client ───────────────────────────────────────────────────────────────

@dataclass
class Cached:
    data: Any
    stale: bool = False
    fetched_at: Optional[int] = None


class WporgDirectory:
    """Accès aux API de wordpress.org avec cache disque optionnel.

    `get_url(url, timeout=...)` : GET du check (BaseCheck.http_get_url).
    `cache` : VulnCache (ou None : pas de cache disque, mémoïsation de la
    session seulement). `now` : horloge (epoch) pour les tests.
    """

    def __init__(self, get_url: GetUrl, cache=None, now: Optional[int] = None,
                 timeout: int = 15):
        self._get_url = get_url
        self._cache = cache
        self._now = now
        self._timeout = timeout

    def _request(self, url: str, accept_404: bool = False) -> Optional[dict]:
        """{status, data} ou None (réseau, statut ou corps inexploitables)."""
        try:
            resp = self._get_url(url, timeout=self._timeout)
        except (requests.RequestException, OSError):
            # Erreur réseau (y compris SSRFBlocked, budget épuisé) : inconnu.
            # Un refus de niveau d'accès (BaseException) remonte au moteur.
            return None
        status = getattr(resp, "status_code", None)
        if status != 200 and not (accept_404 and status == 404):
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        return {"status": status, "data": data}

    def _cached(self, type_: str, key: str, fetch) -> Optional[Cached]:
        if self._cache is None:
            raw = fetch()
            return Cached(raw, False, self._now) if raw is not None else None
        clock = {"now": self._now} if self._now is not None else {}
        ttl = CORE_TTL_DAYS if type_.startswith("core") else PLUGIN_TTL_DAYS
        payload, stale = self._cache.get_or_fetch(
            type_, key, lambda _t, _k: fetch(), ttl_days=ttl, **clock)
        if payload is None:
            return None
        return Cached(payload, stale, self._cache.fetched_at(type_, key))

    def stable_check(self) -> Optional[Cached]:
        """Statut de chaque version publiée du cœur, ou None."""
        def fetch():
            raw = self._request(STABLE_CHECK_URL)
            return _compact_stable(raw["data"]) if raw else None
        return self._cached("core_stable_check", "1.0", fetch)

    def version_check(self) -> Optional[Cached]:
        """Offres de mise à jour du cœur ({"offers": [...]}), ou None.

        Aucun paramètre n'est envoyé : ni la version du site audité, ni
        son adresse."""
        def fetch():
            raw = self._request(VERSION_CHECK_URL)
            return _compact_offers(raw["data"]) if raw else None
        return self._cached("core_version_check", "1.7", fetch)

    def plugin(self, slug: str) -> PluginRecord:
        """Fiche d'une extension du répertoire (voir l'en-tête du module)."""
        if not valid_slug(slug):
            return PluginRecord(slug=str(slug), state=UNKNOWN)

        def fetch():
            raw = self._request(plugin_info_url(slug), accept_404=True)
            if raw is None or classify_plugin(raw) == UNKNOWN:
                return None   # rien de concluant : jamais mis en cache
            return {"status": raw["status"], "data": _compact_plugin(raw["data"])}

        cached = self._cached("plugin_info", slug, fetch)
        if cached is None:
            return PluginRecord(slug=slug, state=UNKNOWN)
        raw = cached.data
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        return PluginRecord(slug=slug, state=classify_plugin(raw), data=data,
                            stale=cached.stale, fetched_at=cached.fetched_at)


def open_directory(get_url: GetUrl, now: Optional[int] = None,
                   timeout: int = 15) -> WporgDirectory:
    """Client avec le cache disque du dossier de cache utilisateur."""
    from .cache import VulnCache, wporg_cache_path
    return WporgDirectory(get_url, cache=VulnCache(str(wporg_cache_path())),
                          now=now, timeout=timeout)
