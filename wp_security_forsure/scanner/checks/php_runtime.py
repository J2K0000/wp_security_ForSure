"""Check php_runtime : le socle PHP vu de l'extérieur.

1) Branche de PHP : quand l'en-tête X-Powered-By publie la version, elle est
   comparée au cycle de support de php.net (signatures/php_support.yaml). Une
   branche en fin de vie ne reçoit plus aucun correctif de sécurité, et les
   failles de l'interpréteur lui-même (défauts mémoire) n'y sont plus
   corrigées. Sans en-tête, la version ne se voit pas : le constat INFO dit
   où la lire (Outils > Santé du site, panneau de l'hébergeur).
2) Erreurs PHP affichées : un avertissement ou une erreur fatale imprimés dans
   une page ordinaire (« Warning: ... in /var/www/... on line 12 ») montrent
   que display_errors est actif et divulguent les chemins du serveur. Seules
   les pages déjà demandées par l'audit sont lues (accueil, pages internes
   comparées par visit_profiles) : provoquer une erreur avec une entrée forgée
   serait une sonde active.
"""

from __future__ import annotations

import datetime
import functools
import re
from pathlib import Path
from typing import List, Optional, Tuple

import requests
import yaml

from .base import BaseCheck, CheckResult

PHP_SUPPORT_PATH = (Path(__file__).resolve().parent.parent.parent
                    / "signatures" / "php_support.yaml")
_VERSION_RE = re.compile(r"\bPHP/(\d+)\.(\d+)(?:\.(\d+))?", re.I)
# Format HTML (html_errors actif) et format texte des erreurs PHP.
_PHP_ERROR_RE = re.compile(
    r"(?:<b>)?\b(Warning|Notice|Deprecated|Fatal error|Parse error|Strict Standards)"
    r"(?:</b>)?:\s+(?:(?!<br).){1,300}?\bin\s+(?:<b>)?"
    r"((?:/[\w.\-]+)+\.php|[A-Za-z]:\\[^<\s]+\.php)(?:</b>)?\s+on\s+line\s+(?:<b>)?(\d+)",
    re.I | re.S)
NEAR_END_DAYS = 90


@functools.lru_cache(maxsize=1)
def load_php_support() -> dict:
    with open(PHP_SUPPORT_PATH, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for key in ("as_of", "supported", "eol", "source"):
        if key not in data:
            raise ValueError(f"php_support.yaml : clé {key} absente")
    return data


def today() -> datetime.date:
    """Date du jour (remplacée dans les tests)."""
    return datetime.date.today()


def _date(value: str) -> datetime.date:
    return datetime.date.fromisoformat(str(value))


def branch_status(version: str, day: Optional[datetime.date] = None,
                  table: Optional[dict] = None) -> dict:
    """État d'une version de PHP (« 8.1.2 ») d'après la table de php.net :
    {branch, state (eol | security_only | active | unknown), until, last_release}."""
    table = table or load_php_support()
    day = day or today()
    m = re.match(r"(\d+)\.(\d+)", version or "")
    if not m:
        return {"branch": "", "state": "unknown"}
    branch = f"{m.group(1)}.{m.group(2)}"
    if branch in table["eol"]:
        row = table["eol"][branch]
        return {"branch": branch, "state": "eol", "until": _date(row["eol"]),
                "last_release": row.get("last_release", "")}
    if branch in table["supported"]:
        row = table["supported"][branch]
        active, security = _date(row["active_until"]), _date(row["security_until"])
        if day > security:
            return {"branch": branch, "state": "eol", "until": security}
        if day > active:
            return {"branch": branch, "state": "security_only", "until": security}
        return {"branch": branch, "state": "active", "until": security}
    return {"branch": branch, "state": "unknown"}


def php_errors(body: str) -> List[Tuple[str, str, str]]:
    """Erreurs PHP affichées dans une page : (type, fichier, ligne)."""
    out = []
    for m in _PHP_ERROR_RE.finditer(body or ""):
        out.append((m.group(1), m.group(2), m.group(3)))
        if len(out) >= 5:
            break
    return out


class PhpRuntimeCheck(BaseCheck):
    """Branche de PHP (fin de vie) et erreurs PHP affichées."""

    name = "php_runtime"
    title = "Socle PHP (branche supportée, erreurs affichées)"
    description = (
        "Compare la version de PHP publiée par l'en-tête X-Powered-By au cycle "
        "de support de php.net, et cherche des erreurs PHP affichées dans les "
        "pages déjà lues par l'audit (display_errors actif, chemins divulgués).")
    severity = "HIGH"
    access_tier = 0
    priority = 3
    depends_on = ["visit_profiles"]

    def run(self) -> CheckResult:
        try:
            home = self.http_get("/")
        except requests.exceptions.RequestException:
            return self._result
        self._check_branch(home)
        self._check_errors(home)
        return self._result

    # ── 1) Branche de PHP ────────────────────────────────────────────

    def _check_branch(self, resp) -> None:
        header = resp.headers.get("X-Powered-By", "") or ""
        table = load_php_support()
        sources = " ; ".join(table["source"])
        m = _VERSION_RE.search(header)
        if not m:
            self._result.add_finding(
                message="Version de PHP non publiée : sa branche n'est pas vérifiable "
                        "de l'extérieur",
                severity="INFO",
                evidence=("Aucune version dans X-Powered-By (c'est un bon réglage). "
                          "La lire dans Outils > Santé du site ou dans le panneau de "
                          "l'hébergeur, et la comparer à " + table["source"][0]),
                url=self.target, confidence="confirmed")
            return
        version = ".".join(g for g in m.groups() if g)
        day = today()
        status = branch_status(version, day, table=table)
        branch, state = status["branch"], status["state"]
        base = (f"X-Powered-By: {header[:80]}. Cycle de support relevé sur php.net "
                f"le {table['as_of']} ({sources}).")
        if state == "eol":
            last = (f" Dernière version de la branche : {status['last_release']}."
                    if status.get("last_release") else "")
            self._result.add_finding(
                message=(f"PHP {branch} en fin de vie depuis le "
                         f"{status['until'].isoformat()} : plus aucun correctif de "
                         "sécurité"),
                severity="HIGH",
                evidence=(f"{base}{last} Une branche en fin de vie peut garder des "
                          "failles connues et non corrigées de l'interpréteur. Passer "
                          "sur une branche supportée."),
                url=self.target, confidence="confirmed")
        elif state == "security_only":
            near = (status["until"] - day).days <= NEAR_END_DAYS
            self._result.add_finding(
                message=(f"PHP {branch} : correctifs de sécurité seulement, jusqu'au "
                         f"{status['until'].isoformat()}"
                         + (", fin proche" if near else "")),
                severity="MEDIUM" if near else "LOW",
                evidence=f"{base} Prévoir le passage sur une branche plus récente.",
                url=self.target, confidence="confirmed")
        elif state == "active":
            self._result.add_finding(
                message=(f"PHP {branch} supporté (correctifs de sécurité jusqu'au "
                         f"{status['until'].isoformat()})"),
                severity="INFO", evidence=base, url=self.target,
                confidence="confirmed")
        else:
            self._result.add_finding(
                message=f"PHP {branch or version} absent de la table de support",
                severity="INFO",
                evidence=(f"{base} Branche plus récente que la table, ou version "
                          "non standard : vérifier sur php.net."),
                url=self.target, confidence="potential")

    # ── 2) Erreurs PHP affichées ─────────────────────────────────────

    def _pages(self) -> List[str]:
        shared = (self.context or {}).get("visit_profiles") or {}
        home = self.target.rstrip("/") + "/"
        return [u for u in (shared.get("pages") or {}) if u != home][:2]

    def _check_errors(self, home) -> None:
        bodies = [(home.url or self.target, home.text or "")]
        for url in self._pages():
            if not self.may_request(url):
                continue
            try:
                resp = self.http_get_url(url)
            except requests.exceptions.RequestException:
                continue
            bodies.append((url, resp.text or ""))
        for url, body in bodies:
            errors = php_errors(body)
            if not errors:
                continue
            kinds = sorted({e[0] for e in errors})
            first = errors[0]
            fatal = any(k.lower() in ("fatal error", "parse error") for k in kinds)
            self._result.add_finding(
                message=("Erreur PHP affichée dans la page : display_errors actif, "
                         "chemin du serveur divulgué"),
                severity="MEDIUM" if fatal else "LOW",
                evidence=(f"Types : {', '.join(kinds)}. Premier exemple : "
                          f"{first[0]} dans {first[1][:120]}, ligne {first[2]}. "
                          "Désactiver display_errors en production (panneau, "
                          ".htaccess ou .user.ini) et garder WP_DEBUG_DISPLAY à false."),
                url=url, confidence="confirmed")
