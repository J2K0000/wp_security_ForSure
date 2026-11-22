"""auth_bypass_state, détection COMPORTEMENTALE des auth-bypass / élévations de
privilège dont l'exploitabilité réelle dépend d'un ÉTAT RUNTIME ou d'un SECRET
FAIBLE, en complément du flux CVE classique.

Objectif : détection comportementale vs CVE-match
-------------------------------------------------
Le matching de version pur (vulnerability_scan) traite une CVE de façon binaire :
« version dans la plage → vulnérable ». Pour certaines failles d'auth-bypass,
cette lecture SUR-signale (elle crie CRITICAL sur une install où la condition
d'exploitation n'est pas réunie) ou SOUS-évalue (elle ignore un secret faible
exploitable). Ce check produit un signal COMPORTEMENTAL : il sonde, en boîte
noire et sans rien détruire, l'état de la surface qui conditionne l'exploit, puis
module la sévérité en conséquence. C'est un enrichissement (priorité 2), volontai-
rement mesuré : en cas de doute (version inconnue, surface illisible) il préfère
NE RIEN affirmer plutôt qu'un faux positif.

Deux classes couvertes
-----------------------
A) Really Simple Security (slug « really-simple-ssl »), CVE-2024-10924 :
   bypass d'authentification non authentifié via les actions REST 2FA sur les
   versions 9.0.0 → 9.1.1.1. RÉELLEMENT critique uniquement si la fonctionnalité
   Two-Factor Authentication est ACTIVÉE (désactivée par défaut). Signal runtime :
   présence du namespace/routes REST « reallysimplessl » (2FA) dans l'index
   wp-json/. Présent → CRITICAL ; absent → MEDIUM (exploitabilité réduite). C'est
   la valeur ajoutée face au CVE-match, qui hurlerait CRITICAL dans les deux cas.

B) LiteSpeed Cache (slug « litespeed-cache »), CVE-2024-28000 :
   élévation de privilège via un hash faible (litespeed_hash dérivé de mt_rand,
   ~1 million de valeurs) autorisant la simulation de rôle jusqu'à administrateur,
   sur les versions <= 6.3.0.1. Détection boîte noire NON destructive : présence
   du plugin + empreinte de la surface de simulation de rôle (en-têtes
   x-litespeed-*, cookie/route litespeed_hash). AUCUN brute-force n'est effectué -
   signalement par empreinte et version uniquement.
"""

from typing import List, Optional, Tuple

import requests

from .base import BaseCheck, CheckResult
from ..vulndb.matcher import compare_versions

# ── Base bundlée : description figée des deux classes runtime/secret-faible ──
# Chaque entrée porte la plage affectée (bornes incluses ; None = pas de borne
# basse), la CVE, la condition RUNTIME qui gouverne l'exploitabilité réelle, et
# la recommandation. Sert de source unique pour les messages et l'evidence.
_KNOWN_CLASSES = {
    "really-simple-ssl": {
        "name": "Really Simple Security",
        "cve": "CVE-2024-10924",
        "cvss": 9.8,
        "range": ("9.0.0", "9.1.1.1"),   # bornes incluses
        "fixed_in": "9.1.2",
        "runtime_condition": (
            "Two-Factor Authentication ACTIVÉE (désactivée par défaut). La faille "
            "n'est exploitable que si le 2FA est en service : ses actions REST "
            "d'authentification ne sont enregistrées que dans ce cas."
        ),
        "runtime_signal": "namespace/routes REST « reallysimplessl » (2FA) dans wp-json/",
        "reco": (
            "Mettre à jour Really Simple Security >= 9.1.2. À défaut immédiat, "
            "désactiver le module 2FA retire la surface d'exploitation."
        ),
        "ref": "https://www.wordfence.com/blog/2024/11/really-simple-security-vulnerability/",
    },
    "litespeed-cache": {
        "name": "LiteSpeed Cache",
        "cve": "CVE-2024-28000",
        "cvss": 9.8,
        "range": (None, "6.3.0.1"),      # <= 6.3.0.1 ; pas de borne basse utile
        "fixed_in": "6.4",
        "runtime_condition": (
            "Secret « litespeed_hash » dérivé de mt_rand (~1 000 000 de valeurs "
            "possibles) donc brute-forçable hors ligne, autorisant la simulation "
            "de rôle jusqu'au compte administrateur."
        ),
        "runtime_signal": "en-têtes x-litespeed-* / cookie-route litespeed_hash",
        "reco": (
            "Mettre à jour LiteSpeed Cache >= 6.4 ET forcer la rotation du secret "
            "litespeed_hash (l'invalider ne suffit pas s'il a déjà pu fuiter)."
        ),
        "ref": "https://patchstack.com/articles/critical-account-takeover-vulnerability-patched-in-litespeed-cache-plugin/",
    },
}


class AuthBypassStateCheck(BaseCheck):
    """Affine les auth-bypass/élévations conditionnés par un état runtime ou un
    secret faible : signal comportemental en complément du CVE-match."""

    name = "auth_bypass_state"
    title = "Auth-bypass conditionnés (état runtime / secret faible)"
    description = (
        "Détection comportementale (boîte noire, non destructive) des auth-bypass "
        "et élévations de privilège dont l'exploitabilité dépend d'un état runtime "
        "ou d'un secret faible : Really Simple Security (CVE-2024-10924, 2FA REST) "
        "et LiteSpeed Cache (CVE-2024-28000, hash de simulation de rôle)."
    )
    severity = "HIGH"
    access_tier = 1  # index REST et accueil
    depends_on: List[str] = ["fingerprint"]

    def run(self) -> CheckResult:
        plugins = self._inventory_plugins()
        self._check_really_simple_security(plugins)
        self._check_litespeed_cache(plugins)
        return self._result

    # ── Classe A : Really Simple Security / CVE-2024-10924 ──────────────
    def _check_really_simple_security(self, plugins: list) -> None:
        meta = _KNOWN_CLASSES["really-simple-ssl"]
        entry = self._find_plugin(plugins, "really-simple-ssl")
        if not entry:
            return
        version = entry.get("version")
        source = entry.get("source") or "inventory"
        # Version inconnue : on ne conclut PAS la plage (évite un faux positif) -
        # on préfère se taire plutôt que d'alarmer sur une hypothèse.
        if not version:
            return
        low, high = meta["range"]
        if not self._in_range(version, low, high):
            return  # hors plage (patché ou trop ancien) : rien à signaler ici

        present, detail = self._probe_rss_2fa_surface()

        if present:
            # Version vulnérable + surface 2FA REST active = condition runtime
            # réunie → réellement exploitable.
            self._result.add_finding(
                message=(
                    "Really Simple Security : surface d'auth-bypass 2FA REST active "
                    f"({meta['cve']}), 2FA activée = exploitable"
                ),
                severity="CRITICAL",
                evidence=self._evidence(meta, version, source, present, detail),
                url=f"{self.target.rstrip('/')}/wp-json/",
                confidence="confirmed",
            )
        else:
            # Version vulnérable mais 2FA non détectée : le CVE-match crierait
            # CRITICAL ; ici on rétrograde en MEDIUM (exploitabilité réduite),
            # tout en exigeant le correctif, c'est la valeur ajoutée du check.
            self._result.add_finding(
                message=(
                    f"Really Simple Security : version vulnérable ({meta['cve']}) "
                    "mais 2FA REST non détectée, exploitabilité réduite, correctif requis"
                ),
                severity="MEDIUM",
                evidence=self._evidence(meta, version, source, present, detail),
                url=f"{self.target.rstrip('/')}/wp-json/",
                confidence="potential",
            )

    # ── Classe B : LiteSpeed Cache / CVE-2024-28000 ────────────────────
    def _check_litespeed_cache(self, plugins: list) -> None:
        meta = _KNOWN_CLASSES["litespeed-cache"]
        entry = self._find_plugin(plugins, "litespeed-cache")
        if not entry:
            return
        version = entry.get("version")
        source = entry.get("source") or "inventory"
        if not version:
            return
        _, high = meta["range"]
        # <= 6.3.0.1. Au-delà (>) : plugin corrigé, rien à signaler.
        if compare_versions(version, high) > 0:
            return

        detail = self._probe_litespeed_surface()
        self._result.add_finding(
            message=(
                "LiteSpeed Cache : classe weak-hash role-simulation "
                f"({meta['cve']}), secret litespeed_hash brute-forçable ; "
                "rotation du secret + MAJ >= 6.4 requis"
            ),
            severity="HIGH",
            evidence=self._evidence(meta, version, source, None, detail),
            url=f"{self.target.rstrip('/')}/wp-content/plugins/litespeed-cache/",
            confidence="potential",
        )

    # ── Sondes runtime (boîte noire, non destructives) ─────────────────
    def _probe_rss_2fa_surface(self) -> Tuple[bool, str]:
        """La surface REST 2FA de Really Simple Security est-elle enregistrée ?

        Parse l'index REST wp-json/ à la recherche du namespace « reallysimplessl »
        ou de routes 2FA (two_fa / two-fa). Sa présence trahit un 2FA activé -
        donc la condition runtime d'exploitation de CVE-2024-10924. Renvoie
        (present, detail). Défensif : réseau HS, soft-404 et JSON illisible →
        (False, raison) sans jamais lever.
        """
        resp = self._safe_get("wp-json/")
        if resp is None:
            return False, "index REST wp-json/ injoignable"
        # Anti soft-404 : un site qui sert la home pour toute URL ne prouve rien.
        if self._is_soft404(resp):
            return False, "wp-json/ répond en soft-404 (pas d'index REST exploitable)"
        data = self._safe_json(resp)
        if not isinstance(data, dict):
            return False, "index REST illisible (réponse non-JSON)"

        namespaces = data.get("namespaces") or []
        routes = data.get("routes") or {}
        ns_hit = any("reallysimplessl" in str(ns).lower() for ns in namespaces)
        route_hit = False
        if isinstance(routes, dict):
            for key in routes.keys():
                k = str(key).lower()
                if "reallysimplessl" in k or "two_fa" in k or "two-fa" in k:
                    route_hit = True
                    break

        if ns_hit or route_hit:
            return True, "namespace/routes reallysimplessl (2FA) exposés dans wp-json/"
        return False, "aucun namespace/route reallysimplessl (2FA) dans l'index wp-json/"

    def _probe_litespeed_surface(self) -> str:
        """Empreinte NON intrusive de la surface de simulation de rôle LiteSpeed.

        Cherche des en-têtes x-litespeed-* et un cookie litespeed_hash sur la home.
        AUCUN brute-force : simple observation. Best-effort, l'absence d'empreinte
        n'annule pas le signalement (fondé sur la version), elle le nuance.
        """
        signals = []
        resp = self._safe_get("")  # home
        if resp is not None:
            try:
                headers = resp.headers
                for hname in headers.keys():
                    if str(hname).lower().startswith("x-litespeed"):
                        signals.append(f"en-tête {hname}")
                cookie = headers.get("Set-Cookie", "") or ""
                if "litespeed_hash" in cookie.lower():
                    signals.append("cookie litespeed_hash")
            except Exception:
                pass
        if signals:
            return "empreinte role-simulation observée : " + ", ".join(signals)
        return ("empreinte role-simulation non observée en surface "
                "(signalement fondé sur la version ; brute-force volontairement non effectué)")

    # ── Evidence commune ───────────────────────────────────────────────
    def _evidence(self, meta: dict, version: Optional[str], source: Optional[str],
                  runtime_present: Optional[bool], detail: str) -> str:
        low, high = meta["range"]
        plage = (f"<= {high}" if low is None else f"{low} – {high}")
        if runtime_present is True:
            runtime_line = f"Condition runtime : RÉUNIE, {detail}"
        elif runtime_present is False:
            runtime_line = f"Condition runtime : NON réunie, {detail}"
        else:
            runtime_line = f"Empreinte runtime : {detail}"
        lines = [
            f"Plugin : {meta['name']}, version {version or 'non confirmée'}"
            + (f" (source: {source})" if source else ""),
            f"CVE : {meta['cve']} (CVSS {meta['cvss']}), plage affectée {plage}, "
            f"corrigé dans {meta['fixed_in']}",
            f"Exploitabilité réelle conditionnée par : {meta['runtime_condition']}",
            runtime_line,
            f"Recommandation : {meta['reco']}",
            f"Référence : {meta['ref']}",
        ]
        return "\n".join(lines)

    # ── Helpers ────────────────────────────────────────────────────────
    def _inventory_plugins(self) -> list:
        return ((self.context or {}).get("inventory") or {}).get("plugins") or []

    @staticmethod
    def _find_plugin(plugins: list, slug: str) -> Optional[dict]:
        for comp in plugins:
            if isinstance(comp, dict) and comp.get("slug") == slug:
                return comp
        return None

    @staticmethod
    def _in_range(version: Optional[str], low: Optional[str], high: Optional[str]) -> bool:
        """True si version ∈ [low, high] (bornes incluses ; None = borne ouverte).

        Version None → False : on ne conclut jamais une plage sans version (garde
        anti-faux-positif).
        """
        if not version:
            return False
        if low is not None and compare_versions(version, low) < 0:
            return False
        if high is not None and compare_versions(version, high) > 0:
            return False
        return True

    def _safe_get(self, path: str) -> Optional[requests.Response]:
        try:
            return self.http_get(path)
        except Exception:
            return None

    @staticmethod
    def _safe_json(resp):
        try:
            return resp.json()
        except Exception:
            return None
