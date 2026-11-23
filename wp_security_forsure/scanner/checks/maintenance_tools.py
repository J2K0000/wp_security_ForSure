"""Outillage de maintenance à retirer d'un site en production (SEC-16).

Données seules, lues par le check plugin_status. Chaque entrée dit pourquoi
l'extension n'a rien à faire sur un site en production : elle donne, à
quiconque obtient une session d'administration ou exploite une faille de
contrôle d'accès de l'extension, une action que WordPress n'offre pas de
lui-même (vider la base, écrire des fichiers PHP, lancer du SQL ou du PHP).

Retenu seulement ce qui se justifie par la fonction même de l'extension, et
par un précédent quand il est vérifié. Écarté :
  - health-check (Health Check & Troubleshooting) : maintenu par l'équipe de
    wordpress.org, son mode de dépannage n'agit que sur la session de
    l'administrateur qui l'active, sans action destructrice ni donnée
    exposée au-delà de l'écran Santé du site du cœur.

Sévérité : HIGH pour une action destructrice ou équivalente à l'exécution de
code ; LOW pour un outil de débogage qui n'expose que de l'information, et
seulement aux comptes administrateurs.

Ces slugs sont aussi sondés par readme.txt sous --authorized
(common_components.COMMON_PLUGINS) : la plupart ne chargent rien sur les
pages publiques.
"""

CATEGORY_LABELS = {
    "reset": "remise à zéro de la base",
    "files": "gestionnaire de fichiers du serveur",
    "database": "administration de la base de données",
    "console": "console d'exécution de code",
    "debug": "outil de débogage",
}

_REMOVE = ("supprimer l'extension (désactiver ne suffit pas : ses fichiers "
           "restent sur le serveur et appelables) ; la réinstaller seulement le "
           "temps d'une intervention")
_DEBUG = ("supprimer l'extension du site en production et réserver le "
          "débogage à une copie de préproduction")

# slug -> {name, category, severity, reason, remediation}
MAINTENANCE_TOOLS = {
    # ── Remise à zéro de la base ──
    "reset-database": {
        "name": "Reset Database", "category": "reset", "severity": "HIGH",
        "reason": ("supprime les tables de la base et réinstalle WordPress ; "
                   "fermée sur wordpress.org le 2026-11-09, élévation de "
                   "privilèges sans correctif dans la version 1.1.3 et "
                   "antérieures (CVE-2026-119615, un compte abonné suffit)"),
        "remediation": _REMOVE,
    },
    "wp-reset": {
        "name": "WP Reset", "category": "reset", "severity": "HIGH",
        "reason": ("remet la base (et, en option, les fichiers) à zéro en un "
                   "clic depuis l'administration : une session volée ou une "
                   "faille de contrôle d'accès efface le site"),
        "remediation": _REMOVE,
    },
    "wp-database-reset": {
        "name": "WP Database Reset", "category": "reset", "severity": "HIGH",
        "reason": ("remet à zéro les tables choisies de la base ; précédent : "
                   "remise à zéro des tables sans authentification "
                   "(CVE-2020-7048)"),
        "remediation": _REMOVE,
    },
    "advanced-wp-reset": {
        "name": "Advanced WP Reset", "category": "reset", "severity": "HIGH",
        "reason": ("remet la base à zéro depuis l'administration : même risque "
                   "que WP Reset"),
        "remediation": _REMOVE,
    },
    # ── Gestionnaires de fichiers ──
    "wp-file-manager": {
        "name": "WP File Manager", "category": "files", "severity": "HIGH",
        "reason": ("lit, modifie et envoie des fichiers du serveur, PHP "
                   "compris ; précédent : exécution de code sans "
                   "authentification, exploitée en masse (CVE-2020-25213)"),
        "remediation": _REMOVE,
    },
    "file-manager-advanced": {
        "name": "Advanced File Manager", "category": "files", "severity": "HIGH",
        "reason": ("lit, modifie et envoie des fichiers du serveur depuis "
                   "l'administration : un compte compromis suffit à déposer "
                   "un webshell"),
        "remediation": _REMOVE,
    },
    "filester": {
        "name": "File Manager Pro (Filester)", "category": "files",
        "severity": "HIGH",
        "reason": ("lit, modifie et envoie des fichiers du serveur depuis "
                   "l'administration : un compte compromis suffit à déposer "
                   "un webshell"),
        "remediation": _REMOVE,
    },
    # ── Administration de la base dans WordPress ──
    "wp-dbmanager": {
        "name": "WP-DBManager", "category": "database", "severity": "HIGH",
        "reason": ("lance des requêtes SQL arbitraires, sauvegarde, restaure et "
                   "vide les tables depuis l'administration"),
        "remediation": _REMOVE,
    },
    "ari-adminer": {
        "name": "ARI Adminer", "category": "database", "severity": "HIGH",
        "reason": ("intègre Adminer : console SQL complète sur la base depuis "
                   "WordPress"),
        "remediation": _REMOVE,
    },
    "wp-phpmyadmin-extension": {
        "name": "WP phpMyAdmin", "category": "database", "severity": "HIGH",
        "reason": ("intègre phpMyAdmin : console SQL complète sur la base "
                   "depuis WordPress"),
        "remediation": _REMOVE,
    },
    # ── Débogage ──
    "debug-bar-console": {
        "name": "Debug Bar Console", "category": "console", "severity": "HIGH",
        "reason": ("ajoute à la barre de débogage une console qui exécute du "
                   "PHP et du SQL arbitraires : exécution de code pour tout "
                   "compte administrateur"),
        "remediation": _REMOVE,
    },
    "query-monitor": {
        "name": "Query Monitor", "category": "debug", "severity": "LOW",
        "reason": ("affiche aux administrateurs les requêtes SQL, les chemins "
                   "du serveur, les constantes et la configuration PHP : "
                   "surface et information inutiles en production"),
        "remediation": _DEBUG,
    },
    "debug-bar": {
        "name": "Debug Bar", "category": "debug", "severity": "LOW",
        "reason": ("affiche aux administrateurs les requêtes, le cache et les "
                   "avertissements PHP : surface inutile en production, socle "
                   "des modules comme Debug Bar Console"),
        "remediation": _DEBUG,
    },
}
