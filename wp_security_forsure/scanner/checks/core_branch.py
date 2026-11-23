"""Version du cœur et branche, comparées aux données de wordpress.org (SEC-13).

La version du cœur détectée par ``fingerprint`` est située par rapport à deux
API publiques de wordpress.org, mises en cache 24 h (vulndb.wporg) :
  - ``core/stable-check/1.0/`` : statut de chaque version publiée
    (``latest``, ``outdated`` ou ``insecure``) ;
  - ``core/version-check/1.7/`` : offres de mise à jour, dont la dernière
    version (« upgrade ») et la dernière version de chaque branche.

Constats :
  - ``insecure`` : HIGH ;
  - en retard sur la dernière version de sa branche sans être ``insecure`` :
    MEDIUM ;
  - dernière version de sa branche, branche ancienne (``outdated``) : LOW ;
  - ``latest`` : aucun constat ;
  - version inconnue de wordpress.org, ou données injoignables : INFO.

Check à part de vulnerability_scan : autre source (wordpress.org, pas
wpvulnerability.net), autre question (la version reçoit-elle encore les
correctifs ?) et autre mode d'échec. Niveau d'accès 0 : aucune requête vers la
cible, seul api.wordpress.org est contacté, sans aucun paramètre (ni la version
ni l'adresse du site audité ne lui sont transmises).
"""
from datetime import datetime, timezone
from typing import List, Optional

from .base import BaseCheck, CheckResult
from .vulnerability_scan import CONFIRMED_SOURCES, SOURCE_LABEL
from ..vulndb import wporg

_DATA_LABEL = "api.wordpress.org (core/stable-check/1.0/, core/version-check/1.7/)"


def _day(ts: Optional[int]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), timezone.utc).date().isoformat()


class CoreBranchCheck(BaseCheck):
    name = "core_branch"
    title = "Version du cœur et branche (wordpress.org)"
    description = ("Compare la version du cœur détectée aux statuts publiés par "
                   "wordpress.org (insecure, outdated, latest) et à la dernière "
                   "version de sa branche.")
    severity = "HIGH"
    access_tier = 0  # aucune requête vers la cible : api.wordpress.org seulement
    priority = 1
    depends_on: List[str] = ["fingerprint"]

    def __init__(self, target, config, session):
        super().__init__(target, config, session)
        self._wporg = None   # injectable (tests)
        self._result.default_access_class = "recon"

    def _directory(self):
        if self._wporg is None:
            self._wporg = wporg.open_directory(
                self.http_get_url, now=getattr(self, "_now", None),
                timeout=self.config.get("timeout", 15))
        return self._wporg

    def run(self) -> CheckResult:
        core = ((self.context or {}).get("inventory") or {}).get("core") or {}
        version = core.get("version")
        if not version:
            self._info("Version du cœur non détectée : comparaison avec "
                       "wordpress.org non réalisée",
                       "Le check fingerprint n'a trouvé aucune version du cœur "
                       "(balise generator, ressources versionnées, flux, "
                       "readme.html). Aucune requête n'a été envoyée.")
            return self._result

        directory = self._directory()
        stable = directory.stable_check()
        if stable is None or not isinstance(stable.data, dict):
            self._info(f"WordPress {version} : statut non vérifié auprès de "
                       "wordpress.org (réseau indisponible, aucun cache)",
                       f"{_DATA_LABEL} injoignable et aucune réponse en cache. "
                       "L'absence de constat ne prouve pas que la version est à "
                       "jour.")
            return self._result
        offers = directory.version_check()
        assessment = wporg.assess_core(version, stable.data,
                                       offers.data if offers else None)
        stale = stable.stale or bool(offers and offers.stale)
        self._report(core, assessment, stable, offers, stale)
        return self._result

    # ── Constats ─────────────────────────────────────────────────────────

    def _confidence(self, core: dict, stale: bool) -> str:
        """La confiance suit celle de la version détectée."""
        if stale:
            return "potential"
        if (core.get("confidence", "confirmed") == "confirmed"
                and core.get("source") in CONFIRMED_SOURCES):
            return "confirmed"
        return "potential"

    def _evidence(self, core, a, stable, offers, stale, remediation) -> str:
        source = SOURCE_LABEL.get(core.get("source"), core.get("source") or "?")
        lines = [
            f"Version détectée : {a.version} (source : {source})",
            f"Statut wordpress.org (stable-check) : {a.status or 'version inconnue'}",
            f"Dernière version de la branche {a.branch} : {a.branch_latest or 'inconnue'}",
            f"Dernière version publiée : {a.latest or 'inconnue'}",
            f"Données : {_DATA_LABEL}, lues le {_day(stable.fetched_at) or '?'}"
            + ("" if offers else " (version-check indisponible : branche déduite "
               "de stable-check)"),
        ]
        if stale:
            lines.append("(cache périmé : réseau indisponible, données "
                         "wordpress.org à revérifier)")
        if core.get("confidence") == "potential":
            lines.append("(version du cœur incohérente entre sources : à vérifier)")
        lines.append(f"Remédiation : {remediation}")
        return "\n".join(lines)

    def _report(self, core, a, stable, offers, stale) -> None:
        confidence = self._confidence(core, stale)
        target = a.branch_latest or a.latest or "la dernière version"
        latest = a.latest or "inconnue"
        if a.verdict == wporg.INSECURE:
            severity = "HIGH"
            message = (f"WordPress {a.version} : version marquée insecure par "
                       f"wordpress.org (dernière version de la branche {a.branch} : "
                       f"{a.branch_latest or 'inconnue'} ; dernière version : {latest})")
            remediation = (f"mettre à jour vers {target} au minimum, idéalement "
                           f"{latest} ; vérifier ensuite dans Tableau de bord > "
                           "Mises à jour que la mise à jour automatique a abouti")
            enables = ("Failles corrigées publiquement dans les versions "
                       "suivantes : exploits connus applicables à ce site.")
        elif a.verdict == wporg.BEHIND_BRANCH:
            severity = "MEDIUM"
            message = (f"WordPress {a.version} : en retard sur la dernière version "
                       f"de sa branche ({a.branch_latest})")
            remediation = (f"mettre à jour vers {a.branch_latest} au minimum, "
                           f"idéalement {latest}")
            enables = ("Correctifs publiés pour la branche non appliqués : la "
                       "version installée peut porter des failles déjà connues.")
        elif a.verdict == wporg.OLD_BRANCH:
            severity = "LOW"
            message = (f"WordPress {a.version} : dernière version de la branche "
                       f"{a.branch}, mais branche ancienne (dernière version : {latest})")
            remediation = (f"passer à la branche courante ({latest}) : une branche "
                           "ancienne ne reçoit plus que des rétroportages de "
                           "sécurité, sans garantie de durée")
            enables = ("Branche ancienne : les correctifs de sécurité dépendent des "
                       "rétroportages, qui peuvent cesser.")
        elif a.verdict == wporg.LATEST:
            return  # dernière version publiée : rien à signaler
        else:
            self._result.add_finding(
                message=(f"WordPress {a.version} : version inconnue de wordpress.org "
                         "(version de développement, modifiée ou détection "
                         "erronée), statut non vérifié"),
                severity="INFO",
                evidence=self._evidence(core, a, stable, offers, stale,
                                        "vérifier la version réelle dans "
                                        "Tableau de bord > Mises à jour"),
                url=self.target, confidence="potential")
            return
        self._result.add_finding(
            message=message, severity=severity,
            evidence=self._evidence(core, a, stable, offers, stale, remediation),
            url=self.target, confidence=confidence, access_class="recon",
            impact={
                "data": f"WordPress {a.version}, statut wordpress.org : {a.status or 'inconnu'}",
                "path": ("Version identifiable de l'extérieur, comparée aux "
                         "statuts publiés par wordpress.org"),
                "enables": enables,
            })

    def _info(self, message: str, evidence: str) -> None:
        self._result.add_finding(message=message, severity="INFO",
                                 evidence=evidence, url=self.target,
                                 confidence="potential")
