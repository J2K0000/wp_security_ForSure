"""Client HTTP wpvulnerability.net (requêtes par composant)."""
from typing import Optional
import requests

BASE = "https://www.wpvulnerability.net"
from wp_security_forsure import USER_AGENT as UA


class WpvulnClient:
    def __init__(self, timeout: int = 15, session: Optional[requests.Session] = None):
        self.timeout = timeout
        self.session = session or requests.Session()
        # Une Session neuve porte déjà « python-requests/x » : setdefault ne
        # poserait jamais l'agent de l'outil. On remplace l'agent par défaut,
        # sans écraser un agent choisi par l'appelant.
        current = self.session.headers.get("User-Agent", "")
        if not current or current.startswith("python-requests/"):
            self.session.headers["User-Agent"] = UA

    def _get(self, path: str) -> Optional[dict]:
        try:
            resp = self.session.get(f"{BASE}/{path}", timeout=self.timeout)
        except requests.RequestException:
            return None
        if resp.status_code != 200:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    def fetch(self, type_: str, slug: str) -> Optional[dict]:
        """type_ in {plugin, theme, core}. Pour core, normalise la version."""
        if type_ == "core":
            return self._fetch_core(slug)
        return self._get(f"{type_}/{slug}/")

    def _fetch_core(self, version: str) -> Optional[dict]:
        payload = self._get(f"core/{version}/")
        if payload and (payload.get("data") or {}).get("vulnerability"):
            return payload
        parts = str(version).split(".")
        if len(parts) >= 2:
            branch = f"{parts[0]}.{parts[1]}"
            if branch != version:
                alt = self._get(f"core/{branch}/")
                if alt is not None:
                    return alt
        return payload
