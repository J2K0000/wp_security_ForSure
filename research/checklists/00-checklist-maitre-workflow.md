# WordPress Security Audit, Checklists Systématiques

> **Usage :** Suivre dans l'ordre. Chaque checklist = phase d'audit.
> Chaque phase est autonome : commandes, attentes, interprétation.
> **Durée estimée audit complet :** 30-60 min (après familiarisation)

---

## Index des CheckLists

| # | Checklist | Priorité | Durée | Dépend |
|---|---|---|---|---|
| 00 | [Checklist Maître, Workflow d'Audit](#checklist-maitre) | n/a | 30-60 min | Toutes |
| 01 | Security Headers | 🔴 Critique | 5 min | Aucune |
| 02 | SSL/TLS Configuration | 🔴 Critique | 5 min | Aucune |
| 03 | Détection de Malware | 🔴 Critique | 10 min | 01, 02 |
| 04 | Permissions Fichiers & Exposition | 🔴 Critique | 5 min | Aucune |
| 05 | Brute Force & Login Protection | 🔴 Critique | 5 min | Aucune |
| 06 | Nulled & Plugins à Risque | 🔴 Critique | 10 min | 04 |
| 07 | Plugins à Risque Élevé (fiches) | 🟡 Important | 15 min | 06 |
| 08 | REST API Audit | 🟡 Important | 5 min | Aucune |
| 09 | Cookies & Sessions | 🟡 Important | 3 min | 01 |
| 10 | Base de Données & Exposition | 🟡 Important | 5 min | 04 |
| 11 | Formulaires & Upload | 🟡 Important | 5 min | Aucune |
| 12 | Scripts Tiers & Intégrations | 🟡 Important | 5 min | 01 |
| 13 | Sécurité Serveur | 🟡 Important | 5 min | Aucune |
| 14 | WP Features (Cron, Heartbeat, Pingback…) | 🟡 Important | 3 min | Aucune |
| 15 | Détection WAF / CDN | 🟡 Important | 2 min | Aucune |
| 16 | Multisite (si applicable) | 🟠 Secondaire | 5 min | 00 |
| 17 | Cache & Performance | 🟠 Secondaire | 3 min | Aucune |
| 18 | Modèle de Priorisation | 🟠 Secondaire | n/a | 00 |
| 19 | Mentions Légales & Consentement | 🟠 Secondaire | n/a | Aucune |

---

## Checklist Maître, Workflow d'Audit Complet

### Phase 0 : Préparation (2 min)
- [ ] Obtenir le consentement écrit du client
- [ ] Noter l'URL cible, le CMS, la date/heure
- [ ] Vérifier que la cible est accessible (ping, HTTP/HTTPS)
- [ ] Noter l'IP réelle (dig + nslookup)
- [ ] Ouvrir un terminal avec TARGET en variable

### Phase 1 : Reconnaissance Rapide (5 min)
- [ ] Confirmer WordPress (meta generator, wp-admin redirect)
- [ ] Identifier version WordPress (readme.html, generator tag, ?ver=)
- [ ] Identifier version PHP (X-Powered-By, Server header)
- [ ] Identifier serveur web (Apache/Nginx)
- [ ] Détecter WAF/CDN (cf-ray, server headers, challenge page)
- [ ] Lister plugins visibles (assets chargés)

### Phase 2 : Security Posture (10 min)
- [ ] Vérifier Security Headers (checklist 01)
- [ ] Vérifier SSL/TLS (checklist 02)
- [ ] Vérifier les fichiers exposés (checklist 04)
- [ ] Vérifier le debug mode (debug.log, PHP errors)
- [ ] Vérifier le directory listing
- [ ] Vérifier robots.txt pour chemins cachés

### Phase 3 : Vulnérabilités Critiques (15 min)
- [ ] Scanner avec WPScan (plugins/thèmes vulnérables)
- [ ] Tester XML-RPC (system.listMethods, pingback)
- [ ] Tester l'énumération d'utilisateurs
- [ ] Vérifier la protection login (checklist 05)
- [ ] Détecter les nulled/piratés (checklist 06)
- [ ] Détecter les scripts tiers risqués (checklist 12)

### Phase 4 : Détection Approfondie (15 min)
- [ ] Vérifier les plugins à haut risque (checklist 07)
- [ ] Tester les endpoints REST API sensibles (checklist 08)
- [ ] Détecter malware / injections (checklist 03)
- [ ] Vérifier les cookies de session (checklist 09)
- [ ] Vérifier les formulaires et uploads (checklist 11)

### Phase 5 : Configuration & Features (10 min)
- [ ] Vérifier la sécurité serveur (checklist 13)
- [ ] Vérifier WP-Cron, Heartbeat, Pingback (checklist 14)
- [ ] Vérifier SSL/TLS approfondi (checklist 02)
- [ ] Si multisite : checklist 16
- [ ] Vérifier cache plugins (checklist 17)

### Phase 6 : Rapport & Priorisation (10 min)
- [ ] Croiser les findings (Wordfence API + Patchstack)
- [ ] Prioriser par sévérité (checklist 18)
- [ ] Rédiger le rapport client (template)
- [ ] Proposer les correctifs avec devis estimatif
- [ ] Obtenir l'accord avant d'exécuter les correctifs

---

## Raccourcis Utiles

```bash
# Variables
TARGET="https://example.com"
TOKEN_WPSCAN="votre_token"

# 1. Confirmer WordPress
curl -sI "$TARGET/wp-admin/" | grep -i "location"

# 2. Version WP
curl -s "$TARGET/" | grep -oP 'WordPress \K[0-9.]+'
curl -s "$TARGET/readme.html" | grep -oP 'Version \K[0-9.]+'

# 3. Version PHP
curl -sI "$TARGET" | grep -iE 'x-powered-by|server.*php'

# 4. Users
curl -sI "$TARGET/?author=1" | grep -i "location"
curl -s "$TARGET/wp-json/wp/v2/users/" | grep -oP '"slug":"[^"]+'

# 5. XML-RPC
curl -s -o /dev/null -w "%{http_code}" "$TARGET/xmlrpc.php"
curl -s -X POST "$TARGET/xmlrpc.php" -H "Content-Type: text/xml" -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# 6. Fichiers exposés
for f in readme.html license.txt wp-config.php.bak wp-content/debug.log .git/config .env phpinfo.php wp-content/uploads/; do echo -n "$f: "; curl -s -o /dev/null -w "%{http_code}" "$TARGET/$f"; echo; done

# 7. Headers sécurité
curl -sI "$TARGET" | grep -iE 'strict-transport-security|x-content-type|x-frame-options|content-security-policy|referrer-policy|permissions-policy'

# 8. Directory listing
curl -s -o /dev/null -w "%{http_code}" "$TARGET/wp-content/uploads/"
curl -s -o /dev/null -w "%{http_code}" "$TARGET/wp-content/plugins/"
```
