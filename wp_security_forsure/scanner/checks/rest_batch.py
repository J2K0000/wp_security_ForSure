"""wp2shell, RCE pré-authentification via l'API REST batch du cœur WordPress.

Couvre CVE-2026-63030 (confusion de routes dans le contrôleur batch/v1) et son
enchaînement wp2shell (CVSS 9.8, exploitation active constatée en juillet 2026,
configuration par défaut, aucun plugin requis).

Versions du cœur affectées : 6.9.0 à 6.9.4 et 7.0.0 à 7.0.1.
Corrigées dans : 6.9.5 et 7.0.2 (la branche 6.8.x n'a jamais été affectée).

L'endpoint batch est natif, actif par défaut et joignable sans authentification.
Il répond aussi bien sur /wp-json/batch/v1 que sur la forme /?rest_route=/batch/v1,
disponible même quand les permaliens sont désactivés.

DÉTECTION PASSIVE UNIQUEMENT
----------------------------
Le scanner n'émet jamais de POST : l'exposition est établie sans rien envoyer
au contrôleur batch.
   - présence de la route /batch/v1 dans l'index REST public (GET wp-json/,
     repli ?rest_route=/) ; à défaut d'index, OPTIONS sur la route (WordPress
     y décrit la route et ses méthodes sans rien dispatcher) ;
   - recoupement avec la version du cœur détectée par fingerprint.
La démonstration du désalignement d'index (ancien mode actif) a été retirée :
elle exigeait des POST vers la cible.
"""

from typing import List, Optional

from .base import BaseCheck, CheckResult
from ..vulndb.matcher import compare_versions

# Plages du cœur affectées par CVE-2026-63030 (bornes incluses).
_AFFECTED_RANGES = (("6.9.0", "6.9.4"), ("7.0.0", "7.0.1"))
_FIXED_VERSIONS = "6.9.5, 7.0.2"
_CVE = "CVE-2026-63030 (wp2shell), CVE-2026-60137"
_REF = "https://hadrian.io/blog/wp2shell-a-pre-authentication-rce-in-wordpress-cores-rest-batch-api"

# Narratif d'accès attaquant partagé par les constats wp2shell (prise de contrôle).
_CONTROLE_IMPACT = {
    "data": "Exécution de code arbitraire sur le serveur (pré-authentification).",
    "path": "Appel non authentifié de l'API REST batch vulnérable du cœur.",
    "enables": "Contrôle total : lecture de la base, backdoor, rebond interne.",
}


def _core_is_affected(version: Optional[str]) -> bool:
    """True si `version` tombe dans une plage du cœur vulnérable."""
    if not version:
        return False
    for low, high in _AFFECTED_RANGES:
        if compare_versions(version, low) >= 0 and compare_versions(version, high) <= 0:
            return True
    return False


class RestBatchCheck(BaseCheck):
    """Détecte l'exposition à wp2shell : contrôleur batch + version affectée."""

    name = "rest_batch"
    title = "API REST batch (wp2shell / CVE-2026-63030)"
    description = (
        "Détecte l'exposition à la RCE pré-authentification wp2shell : présence "
        "du contrôleur REST batch joignable sans authentification, recoupée avec "
        "la version du cœur WordPress détectée."
    )
    severity = "CRITICAL"
    access_tier = 1  # index REST et OPTIONS sur la route batch
    depends_on: List[str] = ["fingerprint"]

    # Le contrôleur répond sur les deux formes, y compris sans permaliens.
    _ENDPOINTS = ("wp-json/batch/v1", "?rest_route=/batch/v1")

    def run(self) -> CheckResult:
        core = ((self.context or {}).get("inventory") or {}).get("core") or {}
        version = core.get("version")
        version_src = core.get("source")

        exposure = self._probe_batch_controller()
        affected = _core_is_affected(version)

        if affected and exposure["reachable"]:
            self._result.add_finding(
                message=(
                    f"WordPress {version} vulnérable à wp2shell, contrôleur REST "
                    f"batch exposé sans authentification (RCE pré-auth)"
                ),
                severity="CRITICAL",
                evidence=self._evidence(version, version_src, exposure),
                url=exposure["url"],
                confidence="confirmed",
                access_class="controle",
                impact=_CONTROLE_IMPACT,
            )
        elif affected and not exposure["reachable"]:
            # Version vulnérable mais endpoint filtré (WAF / durcissement) :
            # surface réduite, correctif néanmoins impératif.
            self._result.add_finding(
                message=(
                    f"WordPress {version} dans la plage wp2shell, contrôleur "
                    f"batch non joignable, mais le cœur doit être mis à jour"
                ),
                severity="MEDIUM",
                evidence=self._evidence(version, version_src, exposure),
                url=self.target.rstrip("/"),
                confidence="confirmed",
            )
        elif exposure["reachable"] and version is None:
            # Endpoint exposé, version du cœur non confirmée : on ne peut ni
            # affirmer ni écarter la vulnérabilité → alerte à valider.
            self._result.add_finding(
                message=(
                    "Contrôleur REST batch exposé sans authentification, version "
                    "du cœur non confirmée, exposition wp2shell à vérifier"
                ),
                severity="HIGH",
                evidence=self._evidence(version, version_src, exposure),
                url=exposure["url"],
                confidence="potential",
                access_class="controle",
                impact=_CONTROLE_IMPACT,
            )
        elif exposure["reachable"]:
            # Endpoint présent mais version hors plage affectée : état sain,
            # tracé en INFO pour la complétude du rapport.
            self._result.add_finding(
                message=(
                    f"Contrôleur REST batch présent, cœur {version} hors de la "
                    f"plage wp2shell (non vulnérable)"
                ),
                severity="INFO",
                evidence=self._evidence(version, version_src, exposure),
                url=exposure["url"],
                confidence="confirmed",
            )
        return self._result

    def _probe_batch_controller(self) -> dict:
        """Le contrôleur batch est-il exposé ? Détection passive, sans POST.

        Renvoie {reachable, url, status, signal}. `reachable` est True quand la
        route /batch/v1 figure dans l'index REST public, ou, sans index, quand
        OPTIONS sur la route la décrit (200 + méthodes). Un 401/403 signale une
        route protégée ; un 404 « rest_no_route » une route absente.
        """
        default_url = f"{self.target.rstrip('/')}/wp-json/batch/v1"
        data, index_url = self.rest_index()
        routes = data.get("routes") if isinstance(data, dict) else None
        if isinstance(routes, dict) and routes:
            if "/batch/v1" in routes:
                return {"reachable": True, "url": default_url, "status": None,
                        "signal": "route_indexed", "index": index_url}
            return {"reachable": False, "url": default_url, "status": None,
                    "signal": "absent", "index": index_url}

        for path in self._ENDPOINTS:
            try:
                resp = self.http_options(path)
            except Exception:
                continue
            url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
            status = resp.status_code
            low = (resp.text or "")[:600].lower()
            if status == 404 and "rest_no_route" in low:
                continue
            if status in (401, 403):
                return {"reachable": False, "url": url, "status": status,
                        "signal": "auth_required", "index": None}
            # Réponse REST décrivant la route (JSON namespace/methods/endpoints),
            # pas un simple en-tête Allow générique du serveur web.
            described = '"endpoints"' in low or (
                '"methods"' in low and "batch" in low)
            if status == 200 and described and not self._is_soft404(resp):
                return {"reachable": True, "url": url, "status": status,
                        "signal": "options_route", "index": None}

        return {"reachable": False, "url": default_url, "status": None,
                "signal": "absent", "index": None}

    def _evidence(self, version, version_src, exposure) -> str:
        signal = {
            "route_indexed": "route /batch/v1 publiée dans l'index REST public",
            "options_route": "route /batch/v1 décrite par OPTIONS",
            "auth_required": "route protégée (authentification requise)",
        }.get(exposure.get("signal"), "route /batch/v1 absente ou filtrée")
        lines = [
            f"Version du cœur : {version or 'non confirmée'}"
            + (f" (source: {version_src})" if version_src else ""),
            f"Plages affectées : 6.9.0–6.9.4, 7.0.0–7.0.1, corrigé dans {_FIXED_VERSIONS}",
            f"Contrôleur batch exposé : "
            f"{'oui' if exposure['reachable'] else 'non'} ({signal}"
            + (f", HTTP {exposure['status']}" if exposure['status'] is not None else "")
            + ")",
            f"Endpoint : {exposure['url']}",
            f"Références : {_CVE}",
            f"Détail : {_REF}",
            "",
            "Détection passive : aucune requête n'est envoyée au contrôleur batch "
            "(aucun POST, aucune sous-requête dispatchée). L'exploitabilité n'est "
            "pas démontrée par le scanner.",
        ]
        return "\n".join(lines)
