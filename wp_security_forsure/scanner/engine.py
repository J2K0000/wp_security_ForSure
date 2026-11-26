"""Moteur d'audit, Ordonnance et exécute les checks."""

import importlib
import logging
import pkgutil
from typing import List, Optional
import requests
from urllib.parse import urljoin, urlparse

from wp_security_forsure import USER_AGENT

from .access_tiers import TIER_HOME, TIER_UNLINKED
from .checks.base import (AccessPolicyViolation, AccessTierRequired, BaseCheck,
                          CheckResult, install_passive_guard, record_references)
from .status import STATUS_ERROR, STATUS_OK, STATUS_SKIPPED, set_status

logger = logging.getLogger(__name__)

# Registre des checks disponibles : nom -> classe
CHECK_REGISTRY = {}

# Checks lancés avant la sonde de joignabilité (voir ScanEngine.run_all).
PRE_PROBE_CHECKS = ("visit_profiles",)

def _discover_checks():
    """Découvre automatiquement tous les modules de check dans scanner/checks/."""
    from . import checks as checks_package
    package_path = checks_package.__name__  # "wp_security_forsure.scanner.checks"
    for importer, modname, ispkg in pkgutil.iter_modules(checks_package.__path__):
        if ispkg or modname == "base":
            continue
        full_module = f"{package_path}.{modname}"
        module = importlib.import_module(full_module)
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BaseCheck) and attr is not BaseCheck:
                if attr.name:
                    CHECK_REGISTRY[attr.name] = attr

_discover_checks()


# Priorité d'affichage de la commande ``list`` : 1 = intrusion et prise de
# contrôle, 2 = informations utilisateurs et sensibles, 3 = configuration et
# durcissement. Un check peut déclarer son propre attribut ``priority`` ;
# cette table ne sert que de repli (même regroupement que config.yaml).
PRIORITY_LABELS = {
    1: "intrusion et prise de contrôle",
    2: "informations utilisateurs et sensibles",
    3: "configuration et durcissement",
}
_DEFAULT_PRIORITY = {
    **dict.fromkeys((
        "fingerprint", "vulnerability_scan", "rest_batch", "ssrf_endpoints",
        "auth_bypass_state", "nulled_plugins", "high_risk_plugins",
        "forms_upload", "malware_detection", "cloaking_seo_spam",
        "brute_force_login", "wp_features", "file_exposure",
        "database_exposure", "visit_profiles", "client_injection",
        "browser_render"), 1),
    **dict.fromkeys((
        "rest_api", "webhook_exposure", "cookies_sessions",
        "third_party_scripts", "ssl_tls", "email_auth"), 2),
    **dict.fromkeys((
        "security_headers", "server_security", "waf_cdn", "takeover",
        "cache_security", "multisite", "php_runtime"), 3),
}


def check_priority(name: str, check_class=None) -> Optional[int]:
    """Priorité d'un check : attribut ``priority`` de la classe, sinon repli."""
    cls = check_class or CHECK_REGISTRY.get(name)
    declared = getattr(cls, "priority", None) if cls is not None else None
    return declared or _DEFAULT_PRIORITY.get(name)


def check_catalog() -> List[dict]:
    """Catalogue des checks du registre (nom, titre, description, priorité),
    trié par priorité puis par nom. Source unique de la commande ``list``."""
    catalog = [
        {"name": name,
         "title": getattr(cls, "title", "") or name,
         "description": getattr(cls, "description", "") or "",
         "priority": check_priority(name, cls)}
        for name, cls in CHECK_REGISTRY.items()
    ]
    return sorted(catalog, key=lambda c: (c["priority"] or 99, c["name"]))


def unknown_checks(names) -> List[str]:
    """Noms absents du registre, dans l'ordre fourni."""
    return [n for n in names if n not in CHECK_REGISTRY]


class UnknownCheckError(ValueError):
    """Un ou plusieurs checks demandés explicitement n'existent pas."""

    def __init__(self, names: List[str]):
        self.names = list(names)
        super().__init__("check(s) inconnu(s) : " + ", ".join(self.names))


class ScanEngine:
    """Moteur orchestrant l'exécution des checks."""

    def __init__(self, target: str, config: dict,
                 checks_list: Optional[List[str]] = None):
        # Un check demandé explicitement (``--checks``) et inconnu est une
        # erreur d'usage, pas un nom ignoré en silence. Les noms inconnus de
        # config.yaml restent ignorés (liste par défaut, éditée à la main).
        if checks_list is not None:
            missing = unknown_checks(checks_list)
            if missing:
                raise UnknownCheckError(missing)
        self.target = target
        self.config = config
        self.checks_list = checks_list  # None = tous
        self.context = {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.get("user_agent") or USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        # Audit : ne pas bloquer sur un certificat invalide/auto-signé (cas fréquent).
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # Garde passive montée dès la création de la session : méthode,
        # destination (SSRF) et budget s'appliquent aussi à la sonde de
        # joignabilité, avant que le premier check ne s'exécute.
        install_passive_guard(self.session)

    def _requested_checks(self):
        """Liste des checks demandés, dans l'ordre voulu (avant tri depends_on).

        Priorité : ``--checks`` CLI > ordre du ``config.yaml`` > registre complet.
        """
        if self.checks_list:
            return list(self.checks_list)
        configured = self.config.get("checks")
        if configured:
            return list(configured)
        return list(CHECK_REGISTRY.keys())

    def _resolve_order(self, requested):
        """Tri topologique des checks en respectant depends_on."""
        order = []
        visiting = set()
        done = set()

        def visit(name):
            if name in done or name not in CHECK_REGISTRY:
                return
            if name in visiting:
                return  # cycle : on ignore la ré-entrée
            visiting.add(name)
            for dep in getattr(CHECK_REGISTRY[name], "depends_on", []) or []:
                visit(dep)
            visiting.discard(name)
            done.add(name)
            order.append(name)

        for n in requested:
            visit(n)
        return order

    def _get_within_scope(self, url: str, timeout: float, max_hops: int = 5):
        """GET qui ne suit les redirections que vers la cible ou sa variante
        ``www.`` (5 sauts au plus). Une redirection hors périmètre n'est pas
        suivie : la réponse 3xx est rendue telle quelle."""
        host = (urlparse(self.target).hostname or "").lower()
        bare = host[4:] if host.startswith("www.") else host
        allowed = {bare, f"www.{bare}"}
        resp = self.session.get(url, timeout=timeout, allow_redirects=False)
        for _ in range(max_hops):
            location = resp.headers.get("Location")
            if not (resp.is_redirect and location):
                break
            nxt = urljoin(url, location)
            if (urlparse(nxt).hostname or "").lower() not in allowed:
                break
            url = nxt
            resp = self.session.get(url, timeout=timeout, allow_redirects=False)
        return resp

    def _probe_reachability(self) -> Optional[CheckResult]:
        """Sonde la cible avant l'audit.

        Retourne ``None`` si la cible répond (et stocke la réponse dans le
        contexte pour éviter un GET home redondant), ou un ``CheckResult``
        décrivant l'échec si elle est injoignable (DNS, connexion, timeout).
        """
        timeout = min(self.config.get("timeout", 30) or 30, 15)
        try:
            resp = self._get_within_scope(self.target, timeout)
        except requests.exceptions.RequestException as e:
            # Statut « error » : une cible injoignable rend l'audit incomplet,
            # elle ne doit pas être lue comme une vulnérabilité HIGH.
            return set_status(CheckResult(
                check_name="reachability",
                title="Cible injoignable",
                description="Sonde de joignabilité effectuée avant l'audit.",
                severity="HIGH",
                passed=False,
                findings=[{
                    "message": f"Cible injoignable, audit interrompu ({type(e).__name__}).",
                    "severity": "HIGH",
                    "evidence": str(e)[:200],
                    "url": self.target,
                    "confidence": "confirmed",
                }],
            ), STATUS_ERROR)
        self.context["probe_response"] = resp
        # Ce que l'accueil référence est de niveau 0 pour tous les checks.
        record_references(self.session, resp, self.target, TIER_HOME)
        return None

    @staticmethod
    def _dedup_findings(results: List[CheckResult]) -> List[CheckResult]:
        """Supprime les findings en double entre checks (même message + URL).

        Plusieurs checks couvrent parfois le même point (ex. HSTS manquant via
        ssl_tls ET security_headers). On garde la première occurrence.
        """
        seen = set()
        for r in results:
            kept = []
            for f in r.findings:
                # URL normalisée (slash final ignoré) : ssl_tls émet
                # « …/com » et security_headers « …/com/ » pour le même HSTS.
                key = (f.get("message", "").strip().lower(),
                       f.get("url", "").strip().rstrip("/"))
                if key in seen:
                    continue
                seen.add(key)
                kept.append(f)
            r.findings = kept
        return results

    def run_all(self) -> List[CheckResult]:
        """Exécute tous les checks dans l'ordre, en respectant depends_on.

        Les checks de PRE_PROBE_CHECKS passent avant la sonde de joignabilité :
        la première visite de l'audit est celle d'un profil de navigateur,
        avant toute requête de l'outil (certaines injections ne se déclenchent
        qu'une fois par visiteur ou par adresse IP).
        """
        results = []
        check_names = self._resolve_order(self._requested_checks())
        early = [n for n in check_names if n in PRE_PROBE_CHECKS]
        for name in early:
            results.append(self._run_check(name))
        if not self.config.get("skip_reachability"):
            unreachable = self._probe_reachability()
            if unreachable is not None:
                return [unreachable]
        for name in check_names:
            if name in CHECK_REGISTRY and name not in early:
                results.append(self._run_check(name))
        return self._dedup_findings(results)

    def _skipped(self, name: str, check_class, reason: str = "") -> CheckResult:
        result = set_status(CheckResult(
            check_name=name,
            title=getattr(check_class, "title", name),
            description=getattr(check_class, "description", ""),
            severity="INFO",
            passed=False,
        ), STATUS_SKIPPED)
        if reason:
            result.skip_reason = reason
        return result

    def _run_check(self, name: str) -> CheckResult:
        """Exécute un check et pose son statut (ok, error ou skipped)."""
        check_class = CHECK_REGISTRY[name]
        if (getattr(check_class, "access_tier", TIER_HOME) >= TIER_UNLINKED
                and not self.config.get("authorized")):
            # Check entièrement fait de chemins devinés : non lancé.
            return self._skipped(name, check_class)
        opt_in = getattr(check_class, "opt_in", "")
        if opt_in and not self.config.get(opt_in):
            # Passe facultative non demandée (ex. --render).
            return self._skipped(name, check_class,
                                 getattr(check_class, "skip_reason", ""))
        try:
            check_instance = check_class(self.target, self.config, self.session)
            check_instance.context = self.context   # contexte partagé
            result = check_instance.run()
            if not isinstance(result, CheckResult):
                raise TypeError(
                    f"run() a renvoyé {type(result).__name__} au lieu "
                    "d'un CheckResult")
            return set_status(result, STATUS_OK)
        except AccessPolicyViolation as e:
            # Requête mal classée (niveau 2 sans --authorized) ou interdite
            # à tout niveau : statut « error », jamais un silence.
            logger.error("Check %r : %s", name, e)
            message = ("requête de niveau 2 sans --authorized"
                       if isinstance(e, AccessTierRequired)
                       else "requête interdite à tout niveau d'accès")
            return set_status(CheckResult(
                check_name=name,
                title=getattr(check_class, "title", name),
                description=getattr(check_class, "description", ""),
                severity="INFO",
                passed=False,
                findings=[{
                    "message": message,
                    "severity": "INFO", "evidence": str(e)[:300],
                    "url": getattr(e, "url", ""), "confidence": "confirmed",
                }],
            ), STATUS_ERROR)
        except Exception as e:
            # Statut « error » : jamais présenté comme contrôle conforme.
            logger.exception("Échec du check %r pendant l'exécution", name)
            return set_status(CheckResult(
                check_name=name,
                title=getattr(check_class, "title", name),
                description=getattr(check_class, "description", ""),
                severity="INFO",
                passed=False,
                findings=[{
                    "message": f"Erreur lors de l'exécution : {e}",
                    "severity": "INFO", "evidence": str(e)[:200],
                    "url": "", "confidence": "confirmed",
                }],
            ), STATUS_ERROR)
