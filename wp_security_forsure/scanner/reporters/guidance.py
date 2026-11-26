"""Textes de conduite communs aux trois rapports (terminal, JSON, HTML).

Source unique, pour que les trois formats disent la même chose :
  - réponse à incident (SEC-17) : mise en avant quand le rapport contient un
    indice de compromission, sinon en annexe « En cas de compromission » ;
  - « Ce que cet audit ne peut pas voir » (SEC-15), toujours présent ;
  - recommandations permanentes, dont la double authentification.

Indice de compromission : constat d'un contrôle réalisé (statut ok), hors
INFO, soit issu de malware_detection, cloaking_seo_spam ou nulled_plugins et
confirmé ou de sévérité HIGH ou CRITICAL, soit dont le message signale un
contenu injecté (quel que soit le contrôle). Une classe de vulnérabilité
(« SQL Injection » d'une CVE, « tag injection » d'un en-tête CSP) n'est pas
un contenu injecté. Une simple exposition relevée par malware_detection
(« information disclosure ») n'en est pas un non plus.
"""

import re
from typing import Iterable, List

from ..status import ok_results

# ── Réponse à incident ───────────────────────────────────────────────────

INCIDENT_TITLE = "Réponse à incident"
INCIDENT_ANNEX_TITLE = "En cas de compromission"
INCIDENT_LEAD = ("Le rapport contient au moins un indice de compromission. "
                 "Suivre ces étapes dans l'ordre, sans attendre.")
INCIDENT_ANNEX_LEAD = ("Aucun indice de compromission dans ce rapport. Si le "
                       "site venait à l'être, suivre ces étapes dans l'ordre.")

INCIDENT_STEPS = (
    "Mettre le site hors ligne ou en maintenance.",
    "Changer tous les accès : hébergement, SFTP ou FTP, base de données, tous "
    "les comptes administrateurs, clés et sels de wp-config.php, clés d'API.",
    "Restaurer une sauvegarde antérieure à l'infection.",
    "Mettre à jour le cœur, les plugins et les thèmes, et supprimer ceux qui "
    "ne servent pas.",
    "Vérifier l'intégrité côté serveur : wp core verify-checksums, wp plugin "
    "verify-checksums, le dossier wp-content/mu-plugins/, les drop-ins, les "
    "fichiers .user.ini, la liste des administrateurs et les options.",
    "Remettre le site en ligne.",
    "Demander un réexamen dans Google Search Console.",
)

INCIDENT_WARNING = (
    "Ne pas se contenter de supprimer le fichier suspect : ces infections se "
    "réinstallent depuis plusieurs emplacements.")

COMPROMISE_CHECKS = frozenset({"malware_detection", "cloaking_seo_spam",
                               "nulled_plugins", "visit_profiles",
                               "client_injection", "browser_render"})
_SEVERE = frozenset({"HIGH", "CRITICAL"})
# Contenu injecté (participe), pas une classe de vulnérabilité (« injection »).
_INJECTED = re.compile(r"\binject(?:é|ée|és|ées|e|ee|es|ees|ed|ing)\b", re.I)
_NOT_COMPROMISE = re.compile(r"information disclosure|divulgation d'information",
                             re.I)

# ── Ce que cet audit ne peut pas voir ────────────────────────────────────

AUDIT_LIMITS_TITLE = "Ce que cet audit ne peut pas voir"
AUDIT_LIMITS_LEAD = ("Audit externe en lecture seule : ces points échappent à "
                     "toute observation de l'extérieur. L'absence de constat "
                     "ne les couvre pas.")
AUDIT_LIMITS = (
    "Les attaques actives ne sont pas rejouées : force brute sur la "
    "connexion, réutilisation de mots de passe divulgués, exploitation d'une "
    "faille, téléversement de fichier, injection de code. L'audit montre ce "
    "qui les rend possibles (connexion et XML-RPC exposés, comptes "
    "énumérables, versions vulnérables) ; la résistance du site se vérifie par "
    "un test d'intrusion sous contrat.",
    "Un site déjà compromis : code logé dans le functions.php du thème, les "
    "mu-plugins, les drop-ins, la base de données ou les tâches planifiées.",
    "Les injections servies seulement à certains visiteurs ne sont vues "
    "qu'en partie. L'audit compare plusieurs profils de visite (Referer, "
    "mobile, langue, cookie de connexion, seconde visite) et n'exécute le "
    "JavaScript qu'avec l'option --render. Il ne voit pas le cloaking qui "
    "vérifie l'adresse IP de Googlebot, ni le ciblage par pays ou par adresse "
    "IP : toutes les visites partent de la même adresse.",
    "Les versions masquées : un composant dont la version n'est pas publiée "
    "échappe à la comparaison avec les vulnérabilités connues.",
    "Ce qui se trouve derrière une authentification.",
    "Les sauvegardes hors serveur et leur restauration.",
    "Les rubriques Sécurité et Actions manuelles de Google Search Console : "
    "sans API, elles se consultent dans la propriété du site. Le Transparency "
    "Report de Google (navigation sécurisée) les complète.",
)

# ── Recommandations permanentes ──────────────────────────────────────────

RECOMMENDATIONS_TITLE = "Recommandation permanente"
RECOMMENDATIONS_SUBTITLE = "À vérifier par le propriétaire"
RECOMMENDATIONS = (
    {
        "id": "2fa_admins",
        "title": "Double authentification sur chaque compte administrateur",
        "text": (
            "Son activation, compte par compte, ne se voit pas de "
            "l'extérieur : une extension 2FA détectée ne prouve pas que chaque "
            "administrateur l'utilise. À vérifier dans l'administration."),
    },
    {
        "id": "login_limits",
        "title": "Limiter les tentatives de connexion",
        "text": (
            "La force brute vise wp-login.php et xmlrpc.php. L'audit ne "
            "l'essaie pas : vérifier qu'une limitation des tentatives, un pare-"
            "feu applicatif ou la désactivation de XML-RPC (s'il ne sert pas) "
            "est en place."),
    },
    {
        "id": "remove_unused",
        "title": "Supprimer ce qui ne sert pas",
        "text": (
            "Une extension ou un thème désactivé reste exploitable tant que "
            "ses fichiers sont sur le serveur : supprimer ce qui ne sert pas, "
            "mettre à jour le reste, et ne garder ni compte « admin » ni compte "
            "de test."),
    },
    {
        "id": "server_side",
        "title": "Durcir côté serveur",
        "text": (
            "Invisible de l'extérieur : interdire l'éditeur de fichiers de "
            "l'administration (DISALLOW_FILE_EDIT), interdire l'exécution de "
            "PHP dans wp-content/uploads/, tenir PHP sur une version encore "
            "supportée, garder une sauvegarde hors du serveur et l'avoir "
            "restaurée une fois."),
    },
)


def is_compromise_indicator(check_name: str, finding: dict) -> bool:
    """True si le constat est un indice de compromission (voir le module)."""
    severity = finding.get("severity", "INFO")
    if severity == "INFO":
        return False
    message = str(finding.get("message", ""))
    confirmed = finding.get("confidence", "confirmed") == "confirmed"
    if check_name in COMPROMISE_CHECKS and (confirmed or severity in _SEVERE):
        return not _NOT_COMPROMISE.search(message)
    return bool(_INJECTED.search(message)) and (confirmed or severity in _SEVERE)


def compromise_indicators(results: Iterable) -> List[dict]:
    """Indices de compromission des contrôles réalisés."""
    return [
        {"check": r.check_name, "message": f.get("message", ""),
         "severity": f.get("severity", "INFO"),
         "confidence": f.get("confidence", "confirmed")}
        for r in ok_results(list(results or []))
        for f in (r.findings or [])
        if is_compromise_indicator(r.check_name, f)
    ]


def incident_block(results: Iterable) -> dict:
    """Bloc de réponse à incident (clé JSON « incident_response »)."""
    indicators = compromise_indicators(results)
    highlighted = bool(indicators)
    return {
        "highlighted": highlighted,
        "placement": "en_tete" if highlighted else "annexe",
        "title": INCIDENT_TITLE if highlighted else INCIDENT_ANNEX_TITLE,
        "lead": INCIDENT_LEAD if highlighted else INCIDENT_ANNEX_LEAD,
        "indicators": indicators,
        "steps": list(INCIDENT_STEPS),
        "warning": INCIDENT_WARNING,
    }


def audit_limits_block() -> dict:
    """Bloc « Ce que cet audit ne peut pas voir » (clé JSON « audit_limits »)."""
    return {"title": AUDIT_LIMITS_TITLE, "lead": AUDIT_LIMITS_LEAD,
            "items": list(AUDIT_LIMITS)}


def recommendations_block() -> List[dict]:
    """Recommandations permanentes (clé JSON « recommendations »)."""
    return [dict(r) for r in RECOMMENDATIONS]
