"""SSRF non authentifié via endpoints REST custom de plugins + condition cœur wontfix.

Classe de vulnérabilité couverte : un plugin enregistre une route REST publique
qui passe une URL fournie par l'utilisateur à `wp_remote_get()` / `wp_safe_remote_*`
sans allowlist ni contrôle de destination. Un anonyme peut alors forcer le serveur
à émettre des requêtes HTTP arbitraires (SSRF pré-auth) : scan interne, lecture de
métadonnées cloud (169.254.169.254), pivot vers des services internes.

Exemples confirmés :
  - Ditty  < 3.1.58 , CVE-2025-8085, route /dittyeditor/v1/displayItems,
    paramètre `source_url` passé à wp_remote_get sans validation ;
  - Webmention <= 5.6.2, CVE-2026-0686, Receiver::post, paramètre `source`.

L'angle mort : le matching de version classique échoue parce que l'endpoint custom
n'est visible qu'en sondant l'index REST, il n'apparaît dans aucune bannière. Et
la brique cœur `wp_http_validate_url()` reste vulnérable au DNS rebinding : elle
valide l'hôte une fois puis le résout de nouveau au moment de la requête, si bien
que `wp_safe_remote_get()` NE protège PAS contre un attaquant qui fait pointer un
domaine tour à tour vers une IP publique (validation) puis une IP interne (fetch).
Cette faiblesse est classée « wontfix » côté cœur (cf. Patchstack, « Exploring the
Unpatched WordPress SSRF ») : tout plugin passant une URL utilisateur est donc
potentiellement affecté, indépendamment de sa version.

DÉTECTION PASSIVE UNIQUEMENT (non intrusive) : établit l'EXPOSITION, sans SSRF.
   - énumère l'index REST (GET wp-json/, repli ?rest_route=/ si permaliens off) ;
   - repère la présence de NAMESPACES / ROUTES connus comme sinks SSRF
     (base bundlée SSRF_PRONE_ROUTES) ;
   - recoupe avec l'inventaire des plugins (fingerprint) quand disponible pour
     renforcer l'évidence ;
   - AUCUNE requête n'est envoyée aux routes à risque : aucune URL n'est jamais
     soumise à la cible. Une route à risque exposée donne un finding HIGH
     `potential` (exposition, pas exploitation prouvée).
   - Ajoute un rappel de contexte unique sur la condition cœur wontfix
     `wp_http_validate_url()` (DNS rebinding).
L'ancienne sonde active (URL de collaborateur externe soumise aux routes) a été
retirée : elle faisait émettre une requête sortante par la cible.
"""

from typing import List, Optional

from .base import BaseCheck, CheckResult

# ── Base de connaissance : routes/namespaces REST connus comme sinks SSRF ──
# Chaque entrée :
#   match     : fragment de namespace ou de route à repérer dans l'index REST
#   endpoint  : chemin de la route (sous wp-json/), cité dans le constat
#   param     : nom du paramètre d'URL passé au client HTTP côté cible
#   plugin    : slug du plugin (recoupement avec l'inventaire fingerprint)
#   cve       : référence publique
#   affected  : plage vulnérable connue (à titre indicatif ; non requise pour flag)
#   sink      : fonction cœur atteinte (wp_remote_get, wp_safe_remote_get…)
#   reco      : recommandation de remédiation
SSRF_PRONE_ROUTES = (
    {
        "match": "dittyeditor/v1",
        "endpoint": "wp-json/dittyeditor/v1/displayItems",
        "param": "source_url",
        "plugin": "ditty",
        "cve": "CVE-2025-8085",
        "affected": "< 3.1.58",
        "sink": "wp_remote_get",
        "reco": "Mettre à jour Ditty >= 3.1.58 ; restreindre l'accès à la route "
                "dittyeditor/v1 et valider/allowlister source_url côté serveur.",
    },
    {
        "match": "webmention/receiver",
        "endpoint": "wp-json/webmention/receiver",
        "param": "source",
        "plugin": "webmention",
        "cve": "CVE-2026-0686",
        "affected": "<= 5.6.2",
        "sink": "wp_safe_remote_get",
        "reco": "Mettre à jour Webmention > 5.6.2 ; valider la destination de "
                "`source` et refuser les IP internes/liens locaux.",
    },
)

_CORE_SSRF_REF = "https://patchstack.com/articles/exploring-the-unpatched-wordpress-ssrf/"


class SsrfEndpointsCheck(BaseCheck):
    """Détecte l'exposition SSRF pré-auth via routes REST custom + rappel cœur."""

    name = "ssrf_endpoints"
    title = "SSRF pré-auth via endpoints REST (routes plugins + cœur wontfix)"
    description = (
        "Repère dans l'index REST les namespaces/routes de plugins connus pour "
        "passer une URL utilisateur à wp_remote_get sans allowlist (SSRF pré-auth), "
        "et rappelle la condition cœur wontfix wp_http_validate_url() (DNS rebinding). "
        "Détection passive uniquement : aucune URL n'est soumise à la cible."
    )
    severity = "HIGH"
    access_tier = 1  # index REST
    depends_on: List[str] = ["fingerprint"]

    # Deux formes d'accès à l'index REST : permaliens actifs / désactivés.
    _INDEX_ENDPOINTS = ("wp-json/", "?rest_route=/")

    def run(self) -> CheckResult:
        namespaces, routes, index_url = self._fetch_rest_index()

        exposed = []
        if namespaces is not None or routes is not None:
            exposed = self._match_prone_routes(namespaces or [], routes or {})

        plugins = ((self.context or {}).get("inventory") or {}).get("plugins") or []

        # ── PASSIF : une route à risque exposée = exposition SSRF (potential) ──
        for entry in exposed:
            self._result.add_finding(
                message=(
                    f"Endpoint REST à risque SSRF exposé : {entry['match']} "
                    f"({entry['plugin'].capitalize()}, {entry['cve']}), param "
                    f"{entry['param']} passé à {entry['sink']}"
                ),
                severity="HIGH",
                evidence=self._passive_evidence(entry, index_url, plugins),
                url=f"{self.target.rstrip('/')}/{entry['endpoint']}",
                confidence="potential",
            )

        # ── Rappel de contexte unique : condition cœur wontfix (DNS rebinding) ──
        self._result.add_finding(
            message=(
                "Condition cœur wontfix : wp_http_validate_url() reste vulnérable au "
                "DNS rebinding, wp_safe_remote_* NE protège pas ; tout plugin passant "
                "une URL utilisateur est potentiellement affecté par une SSRF"
            ),
            severity="INFO",
            evidence=(
                "La validation d'URL du cœur résout l'hôte une première fois pour le "
                "valider, puis une seconde fois au moment du fetch : un attaquant peut "
                "faire pointer un domaine vers une IP publique (validation) puis une IP "
                "interne (requête). Faiblesse classée wontfix côté cœur.\n"
                f"Référence : {_CORE_SSRF_REF}"
            ),
            url=f"{self.target.rstrip('/')}/wp-json/",
            confidence="potential",
        )

        return self._result

    # ── Récupération et parsing défensif de l'index REST ────────────────────

    def _fetch_rest_index(self):
        """Renvoie (namespaces, routes, url) depuis l'index REST, ou (None, None, url).

        Essaie wp-json/ puis ?rest_route=/. Gère soft-404 (site qui sert la home
        pour toute URL) et corps non-JSON pour éviter les faux positifs.
        """
        last_url = f"{self.target.rstrip('/')}/wp-json/"
        for path in self._INDEX_ENDPOINTS:
            last_url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
            try:
                resp = self.http_get(path)
            except Exception:
                continue
            if resp is None:
                continue
            # Un soft-404 (home renvoyée pour tout) n'est pas un index REST.
            if self._is_soft404(resp):
                continue
            if resp.status_code >= 500:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            namespaces = data.get("namespaces")
            routes = data.get("routes")
            if not isinstance(namespaces, list):
                namespaces = []
            if not isinstance(routes, dict):
                routes = {}
            # Une réponse JSON dépourvue des deux clés n'est pas l'index REST.
            if namespaces or routes:
                return namespaces, routes, last_url
        return None, None, last_url

    @staticmethod
    def _match_prone_routes(namespaces: list, routes: dict) -> list:
        """Sélectionne les entrées SSRF_PRONE_ROUTES présentes dans l'index."""
        ns_blob = [str(n) for n in namespaces]
        route_keys = [str(k) for k in routes.keys()]
        matched = []
        for entry in SSRF_PRONE_ROUTES:
            frag = entry["match"]
            in_ns = any(frag in n for n in ns_blob)
            in_routes = any(frag in rk for rk in route_keys)
            if in_ns or in_routes:
                matched.append(entry)
        return matched

    def _passive_evidence(self, entry: dict, index_url: str, plugins: list) -> str:
        lines = [
            f"Route/namespace exposé : {entry['match']}",
            f"Plugin : {entry['plugin']} (plage vulnérable connue : {entry['affected']})",
            f"Paramètre d'URL non validé : {entry['param']} -> {entry['sink']}",
            f"Référence : {entry['cve']}",
            f"Index REST : {index_url}",
        ]
        # Recoupement avec l'inventaire des plugins pour renforcer l'évidence.
        match = self._plugin_from_inventory(entry["plugin"], plugins)
        if match:
            ver = match.get("version") or "version inconnue"
            src = match.get("source")
            lines.append(
                f"Recoupement inventaire : plugin {entry['plugin']} détecté "
                f"(version {ver}" + (f", source {src}" if src else "") + ")"
            )
        lines += [
            "",
            f"Remédiation : {entry['reco']}",
            "Exposition (route à risque joignable), l'exploitabilité SSRF n'est "
            "PAS prouvée en mode passif : confidence potential.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _plugin_from_inventory(slug: str, plugins: list) -> Optional[dict]:
        for p in plugins or []:
            if isinstance(p, dict) and p.get("slug") == slug:
                return p
        return None
