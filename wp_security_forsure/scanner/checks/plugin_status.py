"""Extensions fermées, abandonnées ou d'outillage de maintenance (SEC-16).

Pour chaque extension de l'inventaire (check ``fingerprint``) :
  - outillage de maintenance en production (maintenance_tools.py), sans
    aucune requête ;
  - fiche du répertoire wordpress.org (API 1.2 ``plugin_information``,
    cache 7 jours, vulndb.wporg) :
      fermée                         -> HIGH ;
      dernière mise à jour > 2 ans   -> MEDIUM « probablement abandonnée »
                                        (seuil choisi par l'outil, déclaré
                                        dans le constat) ;
      absente du répertoire          -> aucune conclusion (premium ou sur
                                        mesure), un constat INFO les liste ;
      réponse inexploitable          -> INFO « non vérifié ».

Niveau d'accès 0 : aucune requête vers la cible ; seul api.wordpress.org est
contacté, avec le seul slug de l'extension.
"""
import time
from datetime import datetime, timezone
from typing import List, Optional

from .base import BaseCheck, CheckResult
from .maintenance_tools import CATEGORY_LABELS, MAINTENANCE_TOOLS
from ..vulndb import wporg

# Seuil « probablement abandonnée » : choix de wp_security_ForSure, pas une
# règle de wordpress.org.
ABANDONED_AFTER_DAYS = 730
ABANDONED_LABEL = "2 ans"

# Slug déduit d'un namespace REST, sans confirmation par readme.txt : le
# dossier de l'extension n'est pas prouvé, la conclusion reste à vérifier.
_GUESSED_SLUG_SOURCES = ("rest_namespace",)

REMEDIATION_CLOSED = ("supprimer l'extension (désactiver ne suffit pas, un plugin "
                      "désactivé reste exploitable) et la remplacer par une "
                      "extension maintenue")
REMEDIATION_ABANDONED = ("vérifier l'activité de l'auteur ; à défaut, remplacer "
                         "l'extension par une extension maintenue et supprimer "
                         "l'ancienne (désactiver ne suffit pas)")


def _day(ts: Optional[int]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), timezone.utc).date().isoformat()


class PluginStatusCheck(BaseCheck):
    name = "plugin_status"
    title = "Extensions fermées, abandonnées ou d'outillage (wordpress.org)"
    description = ("Signale les extensions détectées fermées sur wordpress.org, "
                   "sans mise à jour depuis plus de 2 ans, ou relevant de "
                   "l'outillage de maintenance à retirer de la production.")
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

    def _today(self):
        now = getattr(self, "_now", None)
        return datetime.fromtimestamp(now if now is not None else time.time(),
                                      timezone.utc).date()

    def run(self) -> CheckResult:
        plugins = ((self.context or {}).get("inventory") or {}).get("plugins") or []
        seen, absent, unknown = set(), [], []
        for comp in plugins:
            slug = str(comp.get("slug") or "").strip().lower()
            if not slug or slug in seen:
                continue
            seen.add(slug)
            self._check_tooling(slug, comp)
            if not wporg.valid_slug(slug):
                continue  # pas un slug du répertoire : jamais transmis
            record = self._directory().plugin(slug)
            if record.state == wporg.CLOSED:
                self._closed(slug, comp, record)
            elif record.state == wporg.ACTIVE:
                self._maybe_abandoned(slug, comp, record)
            elif record.state == wporg.ABSENT:
                absent.append(slug)
            else:
                unknown.append(slug)
        if absent:
            self._result.add_finding(
                message=("Extensions absentes du répertoire wordpress.org "
                         "(premium ou développées sur mesure) : fermeture et "
                         f"abandon non vérifiables ({', '.join(absent)})"),
                severity="INFO",
                evidence=("api.wordpress.org ne connaît pas ces slugs : aucune "
                          "conclusion. Leur suivi de sécurité dépend de leur "
                          "éditeur."),
                url=self.target, confidence="potential")
        if unknown:
            self._result.add_finding(
                message=("Statut wordpress.org non vérifié (réseau indisponible "
                         "ou réponse inexploitable) : " + ", ".join(unknown)),
                severity="INFO",
                evidence=("api.wordpress.org injoignable ou réponse non "
                          "concluante, et aucune fiche en cache : l'absence de "
                          "constat ne prouve rien pour ces extensions."),
                url=self.target, confidence="potential")
        return self._result

    # ── Confiance et preuves ─────────────────────────────────────────────

    @staticmethod
    def _presence_confidence(comp: dict, stale: bool = False) -> str:
        if stale or comp.get("source") in _GUESSED_SLUG_SOURCES:
            return "potential"
        return "confirmed"

    @staticmethod
    def _presence_note(comp: dict) -> str:
        if comp.get("source") in _GUESSED_SLUG_SOURCES:
            return ("\n(slug déduit d'un namespace REST, dossier de l'extension "
                    "non confirmé : à vérifier)")
        return ""

    @staticmethod
    def _data_note(record) -> str:
        note = (f"\nDonnées : api.wordpress.org (plugins/info/1.2), lues le "
                f"{_day(record.fetched_at) or '?'}")
        if record.stale:
            note += " (cache périmé : réseau indisponible)"
        return note

    # ── Constats ─────────────────────────────────────────────────────────

    def _check_tooling(self, slug: str, comp: dict) -> None:
        tool = MAINTENANCE_TOOLS.get(slug)
        if not tool:
            return
        kind = ("outil de débogage" if tool["category"] == "debug"
                else "outil de maintenance")
        self._result.add_finding(
            message=(f"Extension {tool['name']} ({slug}) : {kind} à retirer de "
                     "la production"),
            severity=tool["severity"],
            evidence=(f"Catégorie : {CATEGORY_LABELS.get(tool['category'], tool['category'])}\n"
                      f"Motif : {tool['reason']}\n"
                      f"Détectée via : {comp.get('source') or 'chemin dans la page'}"
                      + self._presence_note(comp)
                      + f"\nRemédiation : {tool['remediation']}"),
            url=f"{self.target.rstrip('/')}/wp-content/plugins/{slug}/",
            confidence=self._presence_confidence(comp),
            access_class="recon",
            impact={
                "data": f"Extension {tool['name']} installée",
                "path": "Session d'administration volée ou faille de l'extension",
                "enables": tool["reason"][0].upper() + tool["reason"][1:] + ".",
            })

    def _closed(self, slug: str, comp: dict, record) -> None:
        motif = record.reason_text or "non précisé"
        when = record.closed_date or "date inconnue"
        evidence = (f"Extension : {record.name} ({slug})\n"
                    f"Fermée le : {when}\nMotif : {motif}")
        if record.description:
            evidence += f"\nTexte de wordpress.org : {record.description}"
        evidence += (self._data_note(record) + self._presence_note(comp)
                     + f"\nRemédiation : {REMEDIATION_CLOSED}")
        self._result.add_finding(
            message=(f"Extension {slug} : fermée sur wordpress.org le {when} "
                     f"(motif : {motif}) : plus aucune mise à jour possible, la "
                     "supprimer (désactiver ne suffit pas, un plugin désactivé "
                     "reste exploitable)"),
            severity="HIGH",
            evidence=evidence,
            url=wporg.plugin_page_url(slug),
            confidence=self._presence_confidence(comp, record.stale),
            access_class="recon",
            impact={
                "data": f"Extension {slug} fermée sur wordpress.org",
                "path": "Extension installée qui ne recevra plus aucun correctif",
                "enables": ("Toute faille découverte reste exploitable sans "
                            "correctif possible."),
            })

    def _maybe_abandoned(self, slug: str, comp: dict, record) -> None:
        updated = record.last_updated
        if updated is None:
            return
        age = (self._today() - updated).days
        if age <= ABANDONED_AFTER_DAYS:
            return
        self._result.add_finding(
            message=(f"Extension {slug} : probablement abandonnée, dernière mise à "
                     f"jour sur wordpress.org le {updated.isoformat()} (plus de "
                     f"{ABANDONED_LABEL}, seuil choisi par l'outil)"),
            severity="MEDIUM",
            evidence=(f"Extension : {record.name} ({slug})\n"
                      f"Dernière mise à jour : {updated.isoformat()} "
                      f"(il y a {age} jours)\n"
                      f"Version publiée : {record.version or '?'}\n"
                      f"Seuil : {ABANDONED_LABEL} sans mise à jour "
                      f"({ABANDONED_AFTER_DAYS} jours), choix de "
                      "wp_security_ForSure et non règle de wordpress.org"
                      + self._data_note(record) + self._presence_note(comp)
                      + f"\nRemédiation : {REMEDIATION_ABANDONED}"),
            url=wporg.plugin_page_url(slug),
            confidence="potential",
            access_class="recon",
            impact={
                "data": f"Extension {slug} sans mise à jour depuis {age} jours",
                "path": "Extension installée dont l'auteur ne publie plus rien",
                "enables": ("Une faille découverte risque de ne jamais être "
                            "corrigée."),
            })
