"""Cache local SQLite des réponses wpvulnerability (TTL + fallback stale).

Le cache CVE, le snapshot EPSS, l'instantané CISA KEV et le cache des
réponses api.wordpress.org vivent dans le dossier de cache de
l'utilisateur, jamais dans le dossier du paquet (lecture seule ou partagé
après une installation pip) :
  - Windows : %LOCALAPPDATA%\\wp_security_forsure
  - ailleurs : $XDG_CACHE_HOME/wp_security_forsure, sinon ~/.cache/wp_security_forsure
La variable d'environnement WP_SECURITY_FORSURE_CACHE_DIR prend le dessus
(utile pour les tests, qui ne doivent jamais écrire dans le dossier réel).
"""
import json
import os
import posixpath
import sqlite3
import sys
import time
from pathlib import Path
from typing import Callable, Mapping, Optional, Tuple

CACHE_DIR_ENV = "WP_SECURITY_FORSURE_CACHE_DIR"
APP_DIR_NAME = "wp_security_forsure"


def user_cache_dir(environ: Optional[Mapping[str, str]] = None,
                   platform: Optional[str] = None) -> Path:
    """Dossier de cache utilisateur du scanner (non créé ici)."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    override = env.get(CACHE_DIR_ENV)
    if override:
        return Path(override)
    if plat.startswith("win"):
        base = env.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
    else:
        xdg = env.get("XDG_CACHE_HOME")
        # La spécification XDG impose un chemin absolu (au sens POSIX) ;
        # sinon on l'ignore.
        root = Path(xdg) if xdg and posixpath.isabs(xdg) else Path.home() / ".cache"
    return root / APP_DIR_NAME


def vulncache_path() -> Path:
    return user_cache_dir() / "vulncache.sqlite"


def epss_path() -> Path:
    return user_cache_dir() / "epss.csv"


def kev_path() -> Path:
    """Instantané du catalogue CISA KEV (commande refresh-kev)."""
    return user_cache_dir() / "kev.json"


def wporg_cache_path() -> Path:
    """Cache des réponses api.wordpress.org (cœur 24 h, extensions 7 jours)."""
    return user_cache_dir() / "wporg.sqlite"


class VulnCache:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS entry ("
            "type TEXT, slug TEXT, payload TEXT, fetched_at INTEGER, "
            "PRIMARY KEY (type, slug))"
        )
        self._conn.commit()

    def _get_raw(self, type_: str, slug: str):
        cur = self._conn.execute(
            "SELECT payload, fetched_at FROM entry WHERE type=? AND slug=?",
            (type_, slug),
        )
        row = cur.fetchone()
        if not row:
            return None, None
        return json.loads(row[0]), row[1]

    def fetched_at(self, type_: str, slug: str) -> Optional[int]:
        """Horodatage (epoch) de mise en cache de la fiche, ou None."""
        _, ts = self._get_raw(type_, slug)
        return ts

    def put(self, type_: str, slug: str, payload: dict, now: Optional[int] = None):
        ts = int(now if now is not None else time.time())
        self._conn.execute(
            "INSERT OR REPLACE INTO entry (type, slug, payload, fetched_at) "
            "VALUES (?, ?, ?, ?)",
            (type_, slug, json.dumps(payload), ts),
        )
        self._conn.commit()

    def get_or_fetch(self, type_: str, slug: str,
                     client: Callable[[str, str], Optional[dict]],
                     ttl_days: int = 7,
                     now: Optional[int] = None) -> Tuple[Optional[dict], bool]:
        """Retourne (payload, stale). stale=True si servi d'un cache périmé
        faute de réseau. (None, False) si rien en cache et réseau KO."""
        now = int(now if now is not None else time.time())
        cached, fetched_at = self._get_raw(type_, slug)
        fresh = cached is not None and (now - fetched_at) <= ttl_days * 86400
        if fresh:
            return cached, False
        fetched = client(type_, slug)
        if fetched is not None:
            self.put(type_, slug, fetched, now=now)
            return fetched, False
        if cached is not None:
            return cached, True
        return None, False

    def info(self) -> dict:
        cur = self._conn.execute("SELECT COUNT(*), MIN(fetched_at) FROM entry")
        n, oldest = cur.fetchone()
        return {"entries": n or 0, "oldest": oldest}

    def clear(self):
        self._conn.execute("DELETE FROM entry")
        self._conn.commit()
