# Carte de couverture : failles WordPress et PHP

[English version](COVERAGE.md)

Cette page passe en revue les classes de failles et de mauvaises configurations d'un site WordPress et de son
socle PHP, et dit pour chacune ce que wp_security_ForSure en voit. L'outil est fait pour qu'un propriétaire
audite son propre site, en lecture seule. Il ne rejoue aucune attaque : voir « À qui il sert, ce qu'il n'est
pas » dans le [README](../README.fr.md).

Relevé du 24 novembre 2026, sur les sources listées en bas de page. 50 classes au total :

- **testées** (15) : l'outil émet un constat quand la faille se voit de l'extérieur ;
- **testées en partie** (11) : une partie seulement se voit, le contrôle demande `--authorized`, l'outil ne
  relève que des indices, ou il s'abstient par choix (C11) ;
- **invisibles de l'extérieur** (10) : il faut un accès au serveur ou à l'administration. Un mode serveur
  en lecture seule est prévu ;
- **actives seulement** (14) : les tester, c'est attaquer. L'outil ne le fait pas ; il signale ce qui les rend
  possibles et dit quoi vérifier.

`--authorized` marque un contrôle qui devine des chemins non liés : à réserver à un site dont vous avez
l'autorisation écrite.

## Testées

| # | Classe | Ce que fait l'outil | Ce que vous vérifiez | Sources |
|---|---|---|---|---|
| C01 | Cœur WordPress non à jour | Version relevée (balise generator, flux, fichiers du cœur), statut publié par wordpress.org, CVE connues et exploitation active (CISA KEV) : `fingerprint`, `core_branch`, `vulnerability_scan` | Mises à jour automatiques actives | WP-H, OWASP A03, PS-2026 |
| C02 | Extensions et thèmes de version vulnérable | Slugs et versions visibles, comparés aux CVE publiées : `fingerprint`, `vulnerability_scan` ; `readme.txt` d'extensions non liées avec `--authorized` | Mettre à jour, supprimer ce qui ne sert pas | PS-2026, PS-2025, WF-2024, OWASP A03 |
| C03 | Extensions abandonnées ou fermées | Statut au dépôt wordpress.org (fermée, sans mise à jour depuis 2 ans), outils de maintenance laissés en production : `plugin_status` | Remplacer l'extension | PS-2026, PS-2025, WF-2024, OWASP A03 |
| C04 | Branche PHP en fin de vie | Version de `X-Powered-By` comparée au cycle de support de php.net : `php_runtime` | Passer sur une branche supportée | PHP-SV, PHP-EOL, OWASP A03 |
| C07 | Erreurs PHP affichées, chemins divulgués | Erreurs PHP et erreurs de base de données imprimées dans les pages lues : `php_runtime`, `database_exposure` | `display_errors` désactivé, `WP_DEBUG_DISPLAY` à false | WP-ERR, OWASP A02, A10 |
| C08 | Fichiers sensibles servis | Copies de `wp-config.php`, `debug.log`, `.env`, `.git/`, dumps SQL, `.user.ini` : `file_exposure`, `database_exposure` (`--authorized`) | Retirer ces fichiers de la racine web | OWASP A01, A09, WF-2024, WP-H |
| C10 | Installation ou configuration restée ouverte | `wp-admin/install.php` et `wp-admin/setup-config.php` : `database_exposure` (`--authorized`) | Aucun reste d'installation | WF-2024 |
| C12 | Fichiers d'exemple laissés en ligne | `readme.html`, `license.txt` : `file_exposure` | Retirer ce qui ne sert pas | OWASP A02, WF-2024 |
| C13 | En-têtes de sécurité absents | CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`... : `security_headers` | Les envoyer depuis le serveur ou le CDN | OWASP A02, A06 |
| C15 | Cookies sans Secure, HttpOnly ou SameSite | Attributs des cookies des pages publiques : `cookies_sessions` | HTTPS et `FORCE_SSL_ADMIN` | OWASP A02, A01, WP-CONN |
| C16 | HTTPS absent ou incomplet | Certificat, protocoles, redirection, HSTS : `ssl_tls` | Certificat valide, redirection, HSTS | OWASP A04, WP-HTTPS |
| C17 | Divulgation d'informations techniques | En-têtes `Server` et `X-Powered-By`, versions publiées : `server_security`, `fingerprint` | Masquer, en appoint seulement | OWASP A01, WF-2024, CWE |
| C19 | Énumération des comptes, identifiant « admin » | Archives d'auteur, API REST des utilisateurs, oEmbed, sitemap des auteurs ; noms à risque (`admin`, `test`, nom du site) : `rest_api`, `wp_features`, `brute_force_login` | Pas d'identifiant `admin` ni de compte de test | OWASP A07, WP-H, WP-BF |
| C20 | Mots de passe d'application ouverts sans besoin | Annonce dans l'index de l'API REST : `rest_api`, `wp_features` | Les désactiver s'ils ne servent pas | WP-AP |
| C50 | Site déjà compromis (spam, redirections, scripts injectés) | Code injecté, spam SEO, cloaking, faux CAPTCHA ClickFix, chargeurs EtherHiding, profils de visite comparés, passe Chromium avec `--render`, `auto_prepend_file` inconnu dans `.user.ini` (`--authorized`) : `malware_detection`, `cloaking_seo_spam`, `visit_profiles`, `client_injection`, `browser_render`, `file_exposure` | Contrôle d'intégrité côté serveur, sauvegardes | PS-2025, PS-2026, WP-H, WF-2024 |

## Testées en partie

| # | Classe | Ce que l'outil voit, et ce qui lui échappe | Ce que vous vérifiez | Sources |
|---|---|---|---|---|
| C05 | Logiciel serveur obsolète | La version de l'en-tête `Server` est signalée comme divulguée, mais son ancienneté n'est pas jugée : `server_security` | Hébergeur qui maintient ses versions | WP-H, OWASP A03 |
| C06 | Composants de source non fiable | Scripts tiers sans `integrity`, scripts de domaines suspects, extensions nullées (`--authorized`) : `third_party_scripts`, `nulled_plugins`. Une porte dérobée dans une extension reste invisible | Composants de wordpress.org ou d'éditeurs connus | OWASP A03, A08, WP-H, PS-2026 |
| C09 | Listage de répertoires | Pages d'index de `wp-content/`, `uploads/` et voisins, seulement avec `--authorized` : `file_exposure`, `server_security` | Listage désactivé sur le serveur | OWASP A01, A02 |
| C14 | Politique CORS permissive | En-têtes `Access-Control-Allow-*` de l'API REST : `rest_api` | Limiter les origines autorisées | OWASP A01, A02 |
| C18 | XML-RPC actif sans besoin | Réponse de `xmlrpc.php` à un GET. Vérifier `system.multicall` demanderait un POST, hors périmètre : `wp_features`, `brute_force_login` | Désactiver s'il ne sert pas | WP-BF |
| C23 | Administration sans protection supplémentaire | Exposition de `wp-login.php` et de la redirection de `/wp-admin` : `brute_force_login`. Une authentification serveur (401) n'est pas qualifiée à part | Protection ciblée sur `wp-login.php` et `xmlrpc.php` | WP-H, WP-BF |
| C35 | Données exposées par une extension | Données servies par des routes REST publiques en GET : `rest_api` | Mettre à jour | PS-2025, WF-2024, CWE |
| C40 | Défauts mémoire de l'interpréteur PHP | Seulement à travers la branche de PHP (C04) | Branche supportée | CWE, PHP-SV |
| C46 | Pare-feu applicatif absent | Présence d'un WAF ou d'un CDN d'après ses en-têtes et cookies ; son efficacité ne se mesure qu'en attaquant : `waf_cdn` | Pare-feu en périphérie ou propre à WordPress | WP-H, WP-BF, PS-2026, WF-2024 |
| C11 | Fichiers d'inclusion appelables directement | Non testé, par choix : demander un fichier PHP l'exécute côté serveur | Règles du serveur qui les bloquent | WP-H |
| C21 | Connexion sans limitation | Indices seulement : extensions de protection, CAPTCHA ou 2FA visibles, XML-RPC exposé : `brute_force_login`. La limitation réelle ne se vérifie qu'en enchaînant des tentatives | Limitation des tentatives, double authentification, pare-feu | WP-BF, OWASP A07, WF-2024 |

## Invisibles de l'extérieur

Elles relèvent d'un accès au serveur ou d'un compte administrateur. Le rapport les rappelle dans ses
recommandations permanentes ; un mode serveur en lecture seule est prévu pour plusieurs d'entre elles.

| # | Classe | Ce que vous vérifiez | Sources |
|---|---|---|---|
| C22 | Mots de passe faibles, double authentification absente | Mots de passe forts et uniques, 2FA sur chaque administrateur | WP-H, WP-BF, WP-2FA, OWASP A07 |
| C24 | Gestion de session défaillante | Cœur et extensions d'authentification à jour | OWASP A07 |
| C41 | Éditeur de fichiers du tableau de bord actif | `DISALLOW_FILE_EDIT` dans `wp-config.php` | WP-H |
| C42 | Permissions de fichiers trop larges | 755 pour les répertoires, 644 pour les fichiers, 400 ou 440 pour `wp-config.php` | WP-H |
| C43 | Base de données : droits excessifs, préfixe par défaut | Une base et un utilisateur par site, préfixe autre que `wp_` | WP-H |
| C44 | Sauvegardes absentes ou jamais restaurées | Copies hors du serveur, restauration testée | WP-H, WP-SAUV, WP-BF |
| C45 | Journalisation et surveillance insuffisantes | Journaux, suivi des fichiers modifiés, surveillance externe | OWASP A09, WP-H, WP-SURV |
| C47 | Poste de l'administrateur, FTP en clair | Poste à jour, SFTP au lieu de FTP | WP-H, OWASP A04 |
| C48 | Hébergement mutualisé mal isolé | Demander à l'hébergeur ses mesures d'isolement | WP-H |
| C49 | Conception non sécurisée | Composants maintenus, revue de code | OWASP A06, A10 |

## Actives seulement

Les tester, c'est attaquer : l'outil ne le fait pas, même en option. Pour chacune, il signale l'indice passif
qui la rend probable, presque toujours une version vulnérable connue (`vulnerability_scan`, avec le
catalogue CISA KEV des failles activement exploitées). La résistance réelle se mesure par un test
d'intrusion sous contrat.

| # | Classe | Indice relevé par l'outil | Ce que vous faites | Sources |
|---|---|---|---|---|
| C25 | Script intersite (XSS) | Version vulnérable connue | Mettre à jour, limiter les comptes à privilèges, pare-feu | PS-2025, PS-MI25, PS-2026, WF-2024, CWE, OWASP A05 |
| C26 | Contrôle d'accès cassé, autorisation manquante | Version vulnérable connue | Mettre à jour vite, correctif virtuel | PS-2026, PS-2025, WF-2024, CWE, OWASP A01 |
| C27 | Falsification de requête intersite (CSRF) | Version vulnérable connue | Mettre à jour, pare-feu | PS-2025, PS-MI25, WF-2024, CWE, OWASP A01 |
| C28 | Injection SQL | Version vulnérable connue ; erreurs SQL affichées (C07) | Mettre à jour, utilisateur de base aux droits limités | PS-2025, PS-2026, WF-2024, CWE, OWASP A05 |
| C29 | Téléversement de fichier arbitraire | Version vulnérable connue ; formulaires d'envoi exposés (`forms_upload`) | Mettre à jour, PHP interdit dans `uploads/` | PS-2025, PS-2026, WF-2024, CWE, OWASP A06 |
| C30 | Inclusion de fichier, traversée de chemin | Version vulnérable connue | Mettre à jour, pare-feu | PS-2025, PS-MI25, PS-2026, WF-2024, CWE, OWASP A05 |
| C31 | Injection d'objet PHP | Version vulnérable connue | Mettre à jour, pare-feu | PS-2025, PS-2026, WF-2024, CWE, OWASP A08 |
| C32 | Falsification de requête côté serveur (SSRF) | Routes REST connues pour accepter une URL (`ssrf_endpoints`) ; version vulnérable | Mettre à jour | PS-2025, CWE, OWASP A01 |
| C33 | Élévation de privilèges, authentification cassée | Version vulnérable connue ; contournements conditionnels repérés sans exploitation (`auth_bypass_state`) | Mettre à jour vite | PS-2025, PS-2026, WF-2024, CWE, OWASP A07 |
| C34 | Exécution de code, injection de commande | Version vulnérable connue ; exposition de l'API REST batch (`rest_batch`) | Mettre à jour, `DISALLOW_FILE_EDIT` | PS-2025, PS-2026, CWE, OWASP A05 |
| C36 | Redirection ouverte | Version vulnérable connue | Mettre à jour | PS-2025, OWASP A01 |
| C37 | Suppression ou téléchargement arbitraire de fichiers | Version vulnérable connue ; assistant d'installation rouvert (C10) | Mettre à jour, sauvegardes testées | PS-2025, WF-2024 |
| C38 | Déni de service | Aucun : un test de charge est une attaque | Limitation de débit et pare-feu en périphérie | PS-2025, CWE, OWASP A10 |
| C39 | Entité externe XML (XXE) | Version vulnérable connue | Mettre à jour | PS-2025, OWASP A02 |

## Sources

| Code | Document | Date |
|---|---|---|
| OWASP | [OWASP Top 10:2025](https://top10.owasp.org/2025/) | édition 2025, date de publication non affichée |
| WP-H | [Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/) | modifiée le 14 octobre 2026 |
| WP-ERR | [Display Errors](https://developer.wordpress.org/advanced-administration/security/hardening/display-errors/) | modifiée le 14 octobre 2026 |
| WP-BF | [Brute Force Attacks](https://developer.wordpress.org/advanced-administration/security/brute-force/) | modifiée le 14 octobre 2026 |
| WP-HTTPS | [HTTPS](https://developer.wordpress.org/advanced-administration/security/https/) | modifiée le 14 octobre 2026 |
| WP-SAUV | [Backups](https://developer.wordpress.org/advanced-administration/security/backup/) | modifiée le 28 octobre 2026 |
| WP-2FA | [Two Step Authentication](https://developer.wordpress.org/advanced-administration/security/mfa/) | modifiée le 14 octobre 2026 |
| WP-SURV | [Monitoring](https://developer.wordpress.org/advanced-administration/security/monitoring/) | modifiée le 14 octobre 2026 |
| WP-CONN | [Logging In](https://developer.wordpress.org/advanced-administration/security/logging-in/) | modifiée le 14 octobre 2026 |
| WP-AP | [Application Passwords](https://developer.wordpress.org/advanced-administration/security/application-passwords/) | modifiée le 14 octobre 2026 |
| PHP-SV | [PHP Supported Versions](https://www.php.net/supported-versions.php) | lue le 24 novembre 2026 |
| PHP-EOL | [PHP Unsupported Branches](https://www.php.net/eol.php) | lue le 24 novembre 2026 |
| PS-2026 | [Patchstack, State of WordPress Security in 2026](https://patchstack.com/whitepaper/state-of-wordpress-security-in-2026/) | 25 février 2026 |
| PS-2025 | [Patchstack, State of WordPress Security in 2025](https://patchstack.com/whitepaper/state-of-wordpress-security-in-2025/) | 14 mars 2025 |
| PS-MI25 | [Patchstack, 2025 mid-year vulnerability report](https://patchstack.com/whitepaper/2025-mid-year-vulnerability-report/) | 22 juillet 2025 |
| WF-2024 | [Wordfence, 2024 Annual WordPress Security Report](https://www.wordfence.com/wp-content/uploads/2025/04/2024-Annual-WordPress-Security-Report-by-Wordfence.pdf) | 8 avril 2025 |
| CWE | [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) | 15 décembre 2025 |

Une classe vous paraît manquer ou mal classée ? Ouvrez une issue avec sa source : voir
[CONTRIBUTING.md](../CONTRIBUTING.md).
