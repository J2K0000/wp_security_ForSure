# WordPress Cache & Performance Plugin Security Audit

> **Audit Type:** Remote, No Authentication Required  
> **Scope:** Cache plugin fingerprinting, exposed files, cached sensitive pages, cache poisoning  
> **Severity Scale:** 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ⚪ Informational  
> **Estimated Time:** 10-15 min  
> **Target Audience:** Professional WordPress security auditors

---

## Table of Contents

1. [Plugin Detection & Fingerprinting](#1-plugin-detection--fingerprinting)
2. [W3 Total Cache, Database & Config Exposure](#2-w3-total-cache--database--config-exposure)
3. [WP Super Cache, Config & Cache File Exposure](#3-wp-super-cache--config--cache-file-exposure)
4. [LiteSpeed Cache, Logged-In Cache & ESI](#4-litespeed-cache--logged-in-cache--esi)
5. [WP Rocket, Config File & .htaccess Exposure](#5-wp-rocket--config-file--htaccess-exposure)
6. [Flying Press / Flying Pages / Swift Performance, AJAX Exposure](#6-flying-press--flying-pages--swift-performance--ajax-exposure)
7. [REST API Cache Poisoning](#7-rest-api-cache-poisoning)
8. [HTTP Method Caching Abuse](#8-http-method-caching-abuse)
9. [Cache Headers Inspection](#9-cache-headers-inspection)
10. [Sensitive Page Caching](#10-sensitive-page-caching)
11. [CDN Cache Configuration (Cloudflare)](#11-cdn-cache-configuration-cloudflare)
12. [Remediation Recommendations](#12-remediation-recommendations)

---

## 1. Plugin Detection & Fingerprinting

Before running targeted tests, identify which cache plugin (if any) is active. Multiple methods can be used independently; cross-reference results.

### 1.1 Generator Meta Tags

Many cache plugins inject a `<meta name="generator">` tag into the page `<head>`.

#### Curl Command

```bash
# Generic, capture all meta generator tags
curl -s "https://target.tld/" | grep -i '<meta name="generator"'

# Specific plugins
curl -s "https://target.tld/" | grep -iE 'w3-total-cache|wp-super-cache|litespeed|wp-rocket|flying-press|swift-performance'
```

#### Expected Signatures

| Plugin | Generator Tag String |
|---|---|
| W3 Total Cache | `W3 Total Cache vX.X.X` |
| WP Super Cache | `WP Super Cache` (via comment in HTML, not always meta) |
| LiteSpeed Cache | `LiteSpeed Cache vX.X.X` *(or `Powered by LiteSpeed` in headers)* |
| WP Rocket | *No default generator meta tag* (checks headers/cookies/files instead) |
| Flying Press | `Flying Press` (may appear in HTML comment) |
| Swift Performance | `Swift Performance` (may appear in HTML comment) |

### 1.2 Performance / Server Headers

Cache plugins often add response headers that reveal their presence.

#### Curl Command

```bash
curl -sI "https://target.tld/" | grep -iE 'x-cache|x-powered-by|x-litespeed|x-nananana|x-wp-super-cache|x-httpd|x-nginx'
```

#### Header Signatures

| Header | Likely Plugin |
|---|---|
| `X-Cache: HIT/MISS` | Generic (LiteSpeed, WP Rocket, NGINX, CDN) |
| `X-LiteSpeed-Cache: hit/miss` | LiteSpeed Cache |
| `X-Nananana: Batcache` | Batcache (WordPress VIP common) |
| `X-WP-Super-Cache: hit` | WP Super Cache |
| `X-Cache-Group: ...` | WP Rocket |
| `CF-Cache-Status: HIT/MISS` | Cloudflare (CDN layer, not plugin) |

### 1.3 Cookie Detection

Cache plugins set distinct cookies in responses for authenticated/logged-in users.

#### Curl Command

```bash
curl -sI -c /dev/null "https://target.tld/" | grep -i 'set-cookie'
```

#### Cookie Signatures

| Cookie | Plugin |
|---|---|
| `w3tc_logged_out` | W3 Total Cache |
| `wpSGCacheBypass` | WP Super Cache |
| `litespeed_vary` | LiteSpeed Cache |
| `wfwaf-authcookie-*` | Wordfence (not cache but important context) |
| `flying_press_*` | Flying Press |
| `swiftspeed*`/`swift_performance_*` | Swift Performance |

### 1.4 File Path Probing

Check for known file paths that indicate a cache plugin's installation.

#### Curl Command

```bash
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/w3-total-cache/"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/wp-super-cache/"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/litespeed-cache/"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/wp-rocket/"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/flying-press/"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/swift-performance/"
```

> **Note:** 403 = plugin directory exists but directory listing is blocked. 200/301 redirect with content = exposed. 404 = likely not installed.

### 1.5 Performance Header Extraction Script

```bash
# Full fingerprint: headers + cookies + meta tags
TARGET="https://target.tld"
echo "=== HEADERS ==="
curl -sI "$TARGET/" | head -30
echo ""
echo "=== COOKIES ==="
curl -sI "$TARGET/" | grep -i 'set-cookie'
echo ""
echo "=== META GENERATOR ==="
curl -s "$TARGET/" | grep -i '<meta name="generator"' | head -5
echo ""
echo "=== HTML COMMENTS (cache hints) ==="
curl -s "$TARGET/" | grep -iE '<!--.*cache|<!--.*perform|<!--.*rocket|<!--.*litespeed' | head -10
```

**Severity:** ⚪ Informational, This is reconnaissance. No vulnerability, but enables all subsequent tests.

---

## 2. W3 Total Cache, Database & Config Exposure

### 2.1 Database Cache File Exposure

W3 Total Cache stores database query result cache files in a dedicated directory. If directory listing is enabled or files are guessable, an attacker can read cached database content including excerpts of private data.

#### Paths to Probe

```
/wp-content/w3tc/dbcache/
/wp-content/cache/db/
/wp-content/w3tc-cache/db/
```

#### Curl Commands

```bash
# Check if directory listing is enabled
curl -s "https://target.tld/wp-content/w3tc/dbcache/" | head -20

# Try common cache file patterns (may have .php/.txt/.bin extension)
curl -s "https://target.tld/wp-content/w3tc/dbcache/index.html"
curl -s "https://target.tld/wp-content/w3tc/dbcache/index.php"

# If directory listing works, grab a sample
curl -s "https://target.tld/wp-content/w3tc/dbcache/" | grep -oE 'href="[^"]+\.(php|txt|bin|html)"'
```

#### Detection Method

- **HTTP 200** with directory listing → 🔴 Critical, database cache files may be downloadable
- **HTTP 403** → Plugin installed but protected
- **HTTP 404** → Likely not exposed or different path

**Severity:** 🟠 High (if listing = 🔴 Critical)

### 2.2 Config File Exposure

W3 Total Cache writes a configuration file that may contain database connection details, cache keys, and security settings.

#### Paths to Probe

```bash
# Primary config file
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/w3tc-config/master.php"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/w3tc-config/master-admin.php"

# Legacy / fallback paths
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/w3tc/config/master.php"
curl -s "https://target.tld/wp-content/cache/config/master.php"

# Attempt to read and check if PHP is served as plaintext
curl -s "https://target.tld/wp-content/w3tc-config/master.php" | head -30
```

> **Note:** `.php` files should execute (return blank/empty page). If they return PHP source code as plaintext, the server has a PHP misconfiguration, this is 🔴 Critical.

#### Alternative Check, Config as JSON/INI

```bash
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/w3tc-config/master.json"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/w3tc-config/master.txt"
```

**Severity:** 🟠 High (if PHP source exposed → 🔴 Critical)

### 2.3 Minify Directory Exposure

W3 Total Cache stores minified CSS/JS in predictable paths. These files may contain original source paths and sometimes sensitive comments.

#### Paths to Probe

```bash
curl -s "https://target.tld/wp-content/w3tc/minify/" | head -20
curl -s "https://target.tld/wp-content/cache/minify/" | head -20

# If directory listing enabled, list contents
curl -s "https://target.tld/wp-content/w3tc/minify/" | grep -oE 'href="[^"]+"' | head -30
```

**Severity:** 🟡 Medium, Low direct impact, but reveals site structure and plugin versions.

### 2.4 Object Cache Exposure

```bash
# Disk-based object cache
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/cache/object/"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/w3tc/objectcache/"
```

**Severity:** 🟡 Medium

---

## 3. WP Super Cache, Config & Cache File Exposure

### 3.1 wp-cache-config.php Exposure

WP Super Cache stores its configuration in `wp-cache-config.php`. If exposed, it reveals cache settings, secret keys, and sometimes WordPress table prefix.

#### Paths to Probe

```bash
# Primary config path
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/wp-super-cache/wp-cache-config.php"

# If reachable with non-zero content, check content
curl -s "https://target.tld/wp-content/plugins/wp-super-cache/wp-cache-config.php" | head -30

# Legacy paths
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/wp-cache-config.php"
```

> **Note:** `.php` files should execute and return empty. If PHP source is visible, this is 🔴 Critical, the config file contains `$wp_cache_key`, cache paths, and potentially sensitive settings.

**Severity:** 🟠 High (PHP source → 🔴 Critical)

### 3.2 Cache File Exposure

WP Super Cache stores static HTML cache files. If the cache directory is exposed, an attacker can read cached versions of pages including drafts or password-protected content.

#### Paths to Probe

```bash
# Default cache file paths
curl -s "https://target.tld/wp-content/cache/supercache/" | head -20

# Check for cached page variants
curl -s "https://target.tld/wp-content/cache/supercache/target.tld/" | head -20

# Cached homepage
curl -s "https://target.tld/wp-content/cache/supercache/target.tld/index.html" | head -20

# Cached page with query args (permalink-based)
curl -s "https://target.tld/wp-content/cache/supercache/target.tld/sample-page/index.html" | head -20

# Check for cached admin pages
curl -s "https://target.tld/wp-content/cache/supercache/target.tld/wp-login.php" | head -10
curl -s "https://target.tld/wp-content/cache/supercache/target.tld/wp-admin/" | head -10
```

#### Cache File Naming Patterns

```bash
# WP Super Cache uses directory structure mirroring the URL
# /wp-content/cache/supercache/domain.tld/path/to/page/index.html
# With compression: index.html.gz (check both)
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/cache/supercache/target.tld/index.html"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/cache/supercache/target.tld/index.html.gz"
```

**Severity:** 🟠 High (if cache files readable with sensitive content → 🔴 Critical)

### 3.3 advanced-cache.php Exposure

WP Super Cache's `advanced-cache.php` is copied to `wp-content/` during activation. It's a PHP file that should execute, but misconfigured servers may expose it as text.

#### Curl Command

```bash
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/advanced-cache.php"
curl -s "https://target.tld/wp-content/advanced-cache.php" | head -20
```

**Severity:** 🟡 Medium (PHP source → 🟠 High)

---

## 4. LiteSpeed Cache, Logged-In Cache & ESI

### 4.1 Logged-In User Cache Detection

LiteSpeed Cache can serve cached pages to logged-in users if configured incorrectly. This means private user-specific content (draft previews, dashboard snippets in admin bar) may be served from cache to other visitors.

#### Detection Method

The plugin sets a `litespeed_vary` cookie. Check if the cached response varies by cookie or is served identically regardless.

#### Curl Commands

```bash
# Base request (no cookies), collect headers
curl -sI "https://target.tld/" | grep -iE 'x-litespeed-cache|set-cookie|vary'

# Request with simulated logged-in user cookie
curl -sI -H "Cookie: litespeed_vary=logged-in-user" "https://target.tld/" | grep -iE 'x-litespeed-cache|vary'

# Check if the vary header accounts for logged-in status properly
curl -sI "https://target.tld/" | grep -i 'vary'
```

#### What to Look For

- `X-Litespeed-Cache: HIT` when sending a logged-in user cookie → 🟠 High (logged-in pages served from public cache)
- Missing `Vary: litespeed_vary` header → 🟡 Medium (vary header not set, cache may serve wrong content)
- `X-Litespeed-Cache: MISS` for authenticated cookies = proper isolation

**Severity:** 🟠 High

### 4.2 ESI (Edge Side Includes) Security

LiteSpeed Cache uses ESI to dynamically include logged-in user content (admin bar, private widgets) within cached pages. Misconfigured ESI can leak private content to non-authenticated users.

#### Detection

Check for `esi` references in page source or in cache headers.

#### Curl Commands

```bash
# Check for ESI blocks in HTML source
curl -s "https://target.tld/" | grep -iE '<esi:|<!--esi' | head -10

# Check headers for ESI-related values
curl -sI "https://target.tld/" | grep -iE 'x-litespeed-esi|x-esi|esi'
```

#### Risk Scenarios

| Finding | Implication | Severity |
|---|---|---|
| ESI blocks visible to unauthenticated requests | ESI may be disabled or misconfigured | 🟠 High |
| ESI private blocks in cached HTML | Private content (admin bar, user menus) leaked | 🔴 Critical |
| ESI URLs in page source are accessible | Direct ESI endpoint access may bypass auth | 🟠 High |
| `X-Litespeed-ESI: on` header present | ESI is active and being used | ⚪ Informational |

**Severity:** 🟠 High (private content in ESI → 🔴 Critical)

### 4.3 Private Cache Bypass

LiteSpeed Cache has a "private cache" feature for authenticated pages. Test if wp-admin pages are publicly cached.

#### Curl Commands

```bash
# Test wp-admin while pretending to be logged out
curl -sI "https://target.tld/wp-admin/" | grep -iE 'x-litespeed-cache|cache-control'

# Force cache accept header
curl -sI -H "Cache-Control: no-cache" "https://target.tld/wp-login.php" | grep -iE 'x-litespeed-cache|cache-control|set-cookie'
```

**Severity:** 🟠 High

---

## 5. WP Rocket, Config File & .htaccess Exposure

### 5.1 advanced-cache.php Detection

WP Rocket copies `advanced-cache.php` to `wp-content/` for its caching engine.

#### Curl Command

```bash
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/advanced-cache.php"

# If 200 and non-empty, check content (may reveal rocket paths)
curl -s "https://target.tld/wp-content/advanced-cache.php" | head -20
```

**Severity:** 🟡 Medium

### 5.2 Config File Discovery

WP Rocket stores its configuration in the database, but some versions create a backup config file.

#### Paths to Probe

```bash
# WP Rocket cache directory
curl -s "https://target.tld/wp-content/cache/wp-rocket/" | head -20

# Check for config backup (rare, but worth checking)
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/wp-rocket/inc/config.php"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/wp-rocket/views/settings/page.php"
```

**Severity:** 🟡 Medium

### 5.3 .htaccess Modifications

WP Rocket heavily modifies `.htaccess` for browser caching, gzip, and rewrite rules. A publicly readable `.htaccess` reveals server configuration, caching rules, and sometimes security-sensitive paths.

#### Curl Command

```bash
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/.htaccess"

# Try to read content (normally blocked by Apache)
curl -s "https://target.tld/.htaccess" | head -30
```

> **Note:** Apache normally blocks `.htaccess` access (returns 403 or empty). If you get a 200 with content → 🔴 Critical, entire Apache config is exposed.

#### WP Rocket-Specific Marks in .htaccess

```bash
# Check if WP Rocket rules are in response
curl -s "https://target.tld/.htaccess" 2>/dev/null | grep -i 'wp-rocket\|WP_Rocket\|Rocket-'
```

**Severity:** 🟠 High (file readable → 🔴 Critical)

### 5.4 Cache File Exposure

WP Rocket stores HTML cache files in `/wp-content/cache/wp-rocket/`.

#### Curl Commands

```bash
# Check for directory listing
curl -s "https://target.tld/wp-content/cache/wp-rocket/" | head -20

# Try cached page files (structured by domain)
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/cache/wp-rocket/target.tld/index.html"
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/cache/wp-rocket/target.tld/index.html_gzip"

# Check for logged-in cache variants
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/cache/wp-rocket/target.tld-wp-login-php/"
```

**Severity:** 🟠 High (cache files reachable → 🔴 Critical if sensitive pages)

### 5.5 WP Rocket Cookie Check

```bash
# WP Rocket doesn't usually set cookies by default, but check anyway
curl -sI "https://target.tld/" | grep -i 'set-cookie'
```

---

## 6. Flying Press / Flying Pages / Swift Performance, AJAX Exposure

### 6.1 Flying Press

Flying Press preloads pages in the background and uses AJAX to serve cached content. Its AJAX handler may be exposed to unauthenticated requests.

#### Detection

Check for Flying Press-specific query parameters or AJAX endpoints.

#### Curl Commands

```bash
# Check for Flying Press JS and endpoints
curl -s "https://target.tld/" | grep -i 'flying[-_]press' | head -10

# Common Flying Press AJAX endpoint
curl -s "https://target.tld/?flying_press_action=serve_cache" | head -20

# Direct file probe
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/flying-press/"
curl -s "https://target.tld/wp-content/plugins/flying-press/readme.txt" | head -20

# Cache directory exposure
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/cache/flying-press/"
curl -s "https://target.tld/wp-content/cache/flying-press/" | head -20
```

**Severity:** 🟡 Medium

### 6.2 Flying Pages

Flying Pages preloads links on hover. Its admin AJAX endpoint may be exposed.

#### Curl Commands

```bash
# Check for Flying Pages in page source
curl -s "https://target.tld/" | grep -i 'flying[-_]pages' | head -10

# Plugin directory detection
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/flying-pages/"
curl -s "https://target.tld/wp-content/plugins/flying-pages/readme.txt" | head -10

# AJAX endpoint exposure (common pattern)
curl -s -X POST -d "action=flying_pages_preload" "https://target.tld/wp-admin/admin-ajax.php" | head -20
```

**Severity:** 🟡 Medium

### 6.3 Swift Performance

Swift Performance has a more complex caching system with AJAX-based cache purging and preloading that may be exposed.

#### Curl Commands

```bash
# Plugin detection
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/plugins/swift-performance/"

# Cache directory exposure
curl -s "https://target.tld/wp-content/cache/performance/" | head -20
curl -s "https://target.tld/wp-content/cache/swift-performance/" | head -20

# AJAX endpoint, check for unauthenticated access
curl -s -X POST -d "action=swift_performance_clear_cache" \
  "https://target.tld/wp-admin/admin-ajax.php" | head -20

# Try reading Swift config (often stored in PHP file)
curl -s -o /dev/null -w "%{http_code}" "https://target.tld/wp-content/cache/performance/config.php"
curl -s "https://target.tld/wp-content/cache/performance/config.php" | head -20

# Check for admin AJAX handler (may allow cache manipulation)
curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=swift_performance_preload&url=https://target.tld/" \
  "https://target.tld/wp-admin/admin-ajax.php" | head -20
```

**Severity:** 🟠 High (writable AJAX endpoints → 🔴 Critical)

---

## 7. REST API Cache Poisoning

Cache poisoning via the WordPress REST API occurs when a cache layer stores a response that includes attacker-controlled data and serves it to subsequent visitors.

### 7.1 How It Works

1. Attacker sends a request with manipulated headers (e.g., `X-Forwarded-Host`, `X-Originating-URL`)
2. The cache layer sees a response, but includes the manipulated data in the cached response
3. Next visitor receives the poisoned cached response

### 7.2 Host Header Injection Through Cache

#### Curl Commands

```bash
# Test with X-Forwarded-Host manipulation
curl -sI -H "X-Forwarded-Host: attacker.com" "https://target.tld/wp-json/wp/v2/posts" \
  | grep -iE 'location|link|content-location'

# Test with X-Originating-URL
curl -sI -H "X-Originating-URL: https://attacker.com/evil" "https://target.tld/wp-json/" \
  | grep -iE 'location|link'

# Test with X-Rewrite-URL
curl -sI -H "X-Rewrite-URL: /wp-json/evil" "https://target.tld/" \
  | grep -iE 'location|link|content-location'

# Check if the Link header reflects the Host header
curl -sI -H "Host: attacker.com" "https://target.tld/wp-json/" \
  | grep -i 'link'
```

### 7.3 Unkeyed Query Parameter Poisoning

Cache systems may not key on certain query parameters, allowing cache poisoning.

#### Curl Commands

```bash
# Send a request with a cache-busting + poisoning parameter
curl -s -o /dev/null -w "Cache: %{http_code}\n" \
  "https://target.tld/wp-json/wp/v2/posts?cachebuster=12345"

# Then access without parameter, if it's a HIT, unkeyed params are in play
# Compare X-Cache or performance headers between two requests
curl -sI "https://target.tld/wp-json/wp/v2/posts" \
  | grep -iE 'x-cache|x-litespeed|age|cache-control'

curl -sI "https://target.tld/wp-json/wp/v2/posts?evilparam=1" \
  | grep -iE 'x-cache|x-litespeed|age|cache-control'
```

### 7.4 REST API ETag Cache Poisoning

If the REST API returns ETags based on response content, and the cache layer keys on ETag, an attacker can potentially poison the cache by forcing an ETag collision.

#### Curl Command

```bash
# Check if REST API responses include ETag
curl -sI "https://target.tld/wp-json/wp/v2/posts/1" \
  | grep -iE 'etag|last-modified|cache-control'
```

### 7.5 Automated Cache Poisoning Test

```bash
TARGET="https://target.tld"
# Step 1: Baseline, request the endpoint normally
echo "=== BASELINE ==="
curl -sI "$TARGET/wp-json/" | grep -iE 'x-cache|age|content-type|link'
sleep 1

# Step 2: Send poisoned request
echo "=== POISONED REQUEST ==="
curl -sI -H "X-Forwarded-Host: evil-target.com" "$TARGET/wp-json/" \
  | grep -iE 'x-cache|age|location|content-location|link'
sleep 1

# Step 3: Verify if the poison held (access without poison headers)
echo "=== VERIFICATION (should be clean) ==="
curl -sI "$TARGET/wp-json/" | grep -iE 'x-cache|age|link|location'

# Check if any redirect or link header reflects the poisoned host
echo "=== FULL HEADERS AFTER POISON TEST ==="
curl -sI "$TARGET/wp-json/"
```

**Severity:** 🟠 High (successful poisoning → 🔴 Critical, can serve malicious JS to all users)

---

## 8. HTTP Method Caching Abuse

Some cache implementations incorrectly cache POST requests, or serve a cached POST response to GET requests from other users.

### 8.1 POST-to-GET Cache Collision

#### Curl Commands

```bash
# Step 1: Send a POST request (simulating a form submission or search)
curl -s -X POST -d "s=test" "https://target.tld/" \
  | grep -iE 'x-cache|age|set-cookie' > /dev/null
curl -sI -X POST -d "s=test" "https://target.tld/" \
  | grep -iE 'x-cache|age|set-cookie'
sleep 1

# Step 2: Request the same URL with GET (simulating next visitor)
curl -sI "https://target.tld/?s=test" \
  | grep -iE 'x-cache|age|set-cookie'

# Step 3: Compare response bodies
POST_BODY=$(curl -s -X POST -d "s=test" "https://target.tld/" | md5sum)
GET_BODY=$(curl -s "https://target.tld/?s=test" | md5sum)
echo "POST body hash: $POST_BODY"
echo "GET body hash: $GET_BODY"
if [ "$POST_BODY" = "$GET_BODY" ]; then
  echo "⚠️  POST and GET return same content, cache collision likely!"
fi
```

### 8.2 REST API Method Caching

```bash
# Test POST on REST API (should not be cached)
curl -sI -X POST "https://target.tld/wp-json/wp/v2/posts" \
  | grep -iE 'x-cache|age|cache-control'

# Test if a POST response is served for subsequent GET
curl -s -X POST "https://target.tld/wp-json/wp/v2/posts" -o /dev/null
sleep 1
curl -sI "https://target.tld/wp-json/wp/v2/posts" \
  | grep -iE 'x-cache|age|cache-control'
```

### 8.3 Custom POST Endpoint Check

```bash
# Check common search/query endpoints
for endpoint in "/?s=test" "/wp-json/wp/v2/posts?search=test" "/search/test"; do
  echo "=== POST on $endpoint ==="
  curl -sI -X POST "$TARGET$endpoint" | grep -iE 'x-cache|age|cf-cache-status|cache-control'
  sleep 0.5
done
```

**Severity:** 🟠 High, POST data may contain search queries or form data that leak to other users.

---

## 9. Cache Headers Inspection

Analyzing HTTP cache headers reveals how the site's caching infrastructure is configured and whether security boundaries exist.

### 9.1 Core Cache Headers

#### Full Header Dump

```bash
TARGET="https://target.tld"
echo "=== FULL CACHE HEADERS ==="
curl -sI "$TARGET/" | grep -iE 'cache-control|pragma|expires|x-cache|age|vary|cf-cache-status|x-sucuri-cache|x-litespeed|x-nananana|x-httpd|surrogate-control|x-robots-tag'

echo ""
echo "=== COOKIE HEADERS (cache interaction) ==="
curl -sI "$TARGET/" | grep -iE 'set-cookie|cookie'
```

### 9.2 Cache-Control Analysis

| Directive | Meaning | Security Implication |
|---|---|---|
| `public` | Cacheable by anyone | Sensitive pages must NOT have this |
| `private` | Only cache for the specific user (browser cache) | ✅ Correct for authenticated pages |
| `no-store` | Never cache | ✅ Correct for sensitive data |
| `no-cache` | Revalidate with origin before serving | ✅ Safe |
| `max-age=0` | Expire immediately | ✅ Safe |
| `s-maxage=3600` | Shared cache (CDN/proxy) can cache for 1 hour | ⚠️ Must verify what's being cached |

#### Curl Commands

```bash
# Check cache-control on key pages
for page in "/" "/wp-admin/" "/wp-login.php" "/wp-json/" "/wp-json/wp/v2/users"; do
  echo "=== $page ==="
  curl -sI "$TARGET$page" | grep -iE 'cache-control|pragma|expires|x-cache|cache-status'
  echo ""
  sleep 0.3
done
```

### 9.3 Age Header Analysis

The `Age` header tells you how many seconds the cached response has been stored in the cache. A high `Age` value indicates long cache TTLs.

```bash
curl -sI "https://target.tld/" | grep -i 'age'

# If Age increments on subsequent requests, the page is served from cache
curl -sI "https://target.tld/" | grep -i 'age'
sleep 2
curl -sI "https://target.tld/" | grep -i 'age'
```

### 9.4 X-Cache Analysis

```bash
# Detect if response was a HIT or MISS
curl -sI "https://target.tld/" | grep -iE 'x-cache|x-super-cache|cf-cache-status'

# Two requests to see if second is cached
echo "=== REQUEST 1 ==="
curl -sI "https://target.tld/" | grep -iE 'x-cache|cf-cache-status|age'
echo "=== REQUEST 2 (1 second later) ==="
sleep 1
curl -sI "https://target.tld/" | grep -iE 'x-cache|cf-cache-status|age'
```

### 9.5 Vary Header Inspection

The `Vary` header tells caches which request headers to consider when determining if two requests are identical.

```bash
# Check which headers the cache varies on
curl -sI "https://target.tld/" | grep -i 'vary'

# Missing Vary: Cookie or Vary: Authorization = cache may not isolate authenticated users
curl -sI "https://target.tld/wp-admin/" | grep -i 'vary'
curl -sI "https://target.tld/wp-login.php" | grep -i 'vary'
```

| Vary Header | Implication |
|---|---|
| `Vary: Accept-Encoding` | Only varies by compression, ⚠️ No user variation |
| `Vary: Cookie, Accept-Encoding` | ✅ Varies by cookie, logged-in/out isolation |
| `Vary: Authorization` | ✅ Varies by auth |
| `Vary: User-Agent` | Varies by browser (rare) |
| **Missing Vary entirely** | ⚠️ Cache may serve same content to all users |

### 9.6 Automated Cache Header Analyzer

```bash
TARGET="https://target.tld"
echo "════════════════════════════════════════"
echo "  CACHE HEADER ANALYSIS"
echo "  Target: $TARGET"
echo "════════════════════════════════════════"

for page in "/" "/wp-admin/" "/wp-login.php" "/wp-json/" "/.htaccess" "/wp-content/advanced-cache.php"; do
  echo ""
  echo "── $page ──"
  RESP=$(curl -sI "$TARGET$page")
  echo "$RESP" | grep -iE 'http/|cache-control|pragma|expires|x-cache|age|vary|cf-cache-status|set-cookie|x-litespeed|x-nananana|x-sucuri-cache|surrogate-control|x-robots-tag|x-frame-options|content-type' || echo "(no cache headers found)"
  echo "───"
  sleep 0.5
done
```

**Severity:** ⚪ Informational (but findings within can lead to 🔴 Critical identifications)

---

## 10. Sensitive Page Caching

The most dangerous cache misconfiguration: sensitive WordPress pages (wp-admin, wp-login, REST API user endpoints) cached and served to unauthenticated visitors.

### 10.1 wp-admin Caching Test

#### Curl Commands

```bash
TARGET="https://target.tld"

# Request 1: without any auth, check if cached
echo "=== REQUEST 1 (unauthenticated) ==="
curl -sI "$TARGET/wp-admin/" | grep -iE 'x-cache|age|cache-control|set-cookie|location'
sleep 1

# Request 2: same request, check if Age increments (cache hit)
echo "=== REQUEST 2 (unauthenticated, 1s later) ==="
curl -sI "$TARGET/wp-admin/" | grep -iE 'x-cache|age|cache-control|set-cookie|location'
sleep 1

# Request 3: with admin cookie (simulating logged-in user)
echo "=== REQUEST 3 (with admin cookie) ==="
curl -sI -H "Cookie: wordpress_logged_in_abcdef123=admin|1234567890|abcdef..." \
  "$TARGET/wp-admin/" | grep -iE 'x-cache|age|cache-control|set-cookie|location'
```

#### What to Check

| Finding | Severity |
|---|---|
| wp-admin returns 200 OK (not 302 redirect) without auth | 🟡 Medium, admin exposed, may be login page |
| wp-admin returns cached version (Age increments) | 🟠 High, admin page is being cached |
| wp-login.php content served from cache to unauthenticated users | 🟠 High |
| Redirect page (302) is being cached | 🟡 Medium, could cause redirect loops |
| Response body contains visible admin bar or dashboard elements | 🔴 Critical |

### 10.2 wp-login.php Caching Test

```bash
echo "=== WP-LOGIN CACHE TEST ==="
# Request login page without any auth cookies
curl -sI "$TARGET/wp-login.php" | grep -iE 'x-cache|age|cache-control|set-cookie|location'

# Check response body
curl -s "$TARGET/wp-login.php" | head -5
sleep 1

# Second request to confirm cache
curl -sI "$TARGET/wp-login.php" | grep -iE 'x-cache|age'
```

### 10.3 REST API User Endpoint Cache Test

```bash
echo "=== REST API USERS CACHE TEST ==="
# This endpoint should return 401 or redirect if unauthenticated
curl -sI "$TARGET/wp-json/wp/v2/users" | grep -iE 'x-cache|age|content-type|location'
sleep 1

# Second request
curl -sI "$TARGET/wp-json/wp/v2/users" | grep -iE 'x-cache|age'

# Check the actual response (if it returns user data, it's exposed)
curl -s "$TARGET/wp-json/wp/v2/users" | head -50
```

### 10.4 Private Post/Draft Caching

```bash
# Check if a non-existent or private post returns cached 404 or cached content
curl -sI "$TARGET/?p=123456789" | grep -iE 'x-cache|age|http'
sleep 1
curl -sI "$TARGET/?p=123456789" | grep -iE 'x-cache|age|http'

# If the 404 page is cached, that's normal but reveals aggressive caching
# If a private post returns content... that's 🔴 Critical
```

### 10.5 Sensitive Page Caching Matrix

```bash
TARGET="https://target.tld"
echo "════════════════════════════════════════"
echo "  SENSITIVE PAGE CACHE TEST"
echo "════════════════════════════════════════"

declare -a pages=(
  "/"
  "/wp-admin/"
  "/wp-login.php"
  "/wp-json/"
  "/wp-json/wp/v2/users"
  "/wp-json/wp/v2/posts?per_page=100"
  "/wp-content/advanced-cache.php"
  "/.htaccess"
)

for page in "${pages[@]}"; do
  echo ""
  echo "── $page ──"
  STATUS=$(curl -s -o /dev/null -w "HTTP %{http_code}" "$TARGET$page")
  CACHE=$(curl -sI "$TARGET$page" | grep -iE 'x-cache|age|cf-cache-status' | tr '\n' '; ')
  echo "  $STATUS | $CACHE"
  sleep 0.5
done
```

**Severity:** 🟠 High (cached admin/login → 🔴 Critical)

---

## 11. CDN Cache Configuration (Cloudflare)

When WordPress is behind a CDN like Cloudflare, the CDN's cache configuration can override or complement the plugin's settings, creating additional security boundaries (or gaps).

### 11.1 Cloudflare Detection

```bash
# Check headers for Cloudflare presence
curl -sI "https://target.tld/" | grep -iE 'cf-ray|cf-cache-status|server|cf-request-id'

# CF-Ray header = behind Cloudflare
# CF-Cache-Status = Cloudflare's cache status
```

### 11.2 Full Page Caching of Authenticated Pages

Cloudflare can cache HTML pages even when a WordPress plugin does not. If using Cloudflare's "Cache Everything" page rule, authenticated pages may be cached.

#### Curl Commands

```bash
TARGET="https://target.tld"

# Check Cloudflare cache status on wp-admin
echo "=== WP-ADMIN CLOUDFLARE CACHE ==="
curl -sI "$TARGET/wp-admin/" | grep -iE 'cf-cache-status|age|cache-control'

# Check wp-login
echo "=== WP-LOGIN CLOUDFLARE CACHE ==="
curl -sI "$TARGET/wp-login.php" | grep -iE 'cf-cache-status|age|cache-control'

# Check if a page is served from CF cache vs origin
curl -sI "$TARGET/" | grep -iE 'cf-cache-status|age'

# With Cloudflare bypass (direct to origin, only works if origin IP is known)
# curl -sI -H "Host: target.tld" "http://<ORIGIN_IP>/" | grep -iE 'cache-control|set-cookie'
```

#### Cloudflare Cache Status Values

| CF-Cache-Status | Meaning |
|---|---|
| `HIT` | Served from Cloudflare cache |
| `MISS` | Not in cache, fetched from origin |
| `DYNAMIC` | Cloudflare bypassed caching (default for HTML) |
| `EXPIRED` | Was cached but TTL expired |
| `BYPASS` | Deliberately bypassed (cookie or rule) |
| `REVALIDATED` | Served stale but revalidated |

> **🟠 High:** If wp-admin or wp-login returns `CF-Cache-Status: HIT`, Cloudflare is caching sensitive pages.
> **🟡 Medium:** If `Cache-Control: public, max-age=XXX` on admin pages, origin is telling CDN to cache.

### 11.3 Cookie-Based Cache Bypass Check

Cloudflare can bypass cache for requests containing certain cookies (typically `wordpress_logged_in_*`).

```bash
# Request without cookies
echo "=== WITHOUT COOKIE ==="
curl -sI "$TARGET/" | grep -iE 'cf-cache-status|cache-control|set-cookie'
sleep 1

# Request with logged-in cookie pattern
echo "=== WITH LOGGED-IN COOKIE ==="
curl -sI -H "Cookie: wordpress_logged_in_abc=test" "$TARGET/" | grep -iE 'cf-cache-status|cache-control|set-cookie'
sleep 1

# Request with any WordPress cookie
echo "=== WITH WP COOKIE ==="
curl -sI -H "Cookie: wordpress_abc=test; wordpress_logged_in_abc=test; wp-settings-1=test" "$TARGET/" | grep -iE 'cf-cache-status|cache-control|set-cookie'
```

#### What to Look For

- Both requests return `CF-Cache-Status: HIT` → Cloudflare does NOT vary by cookie (🔴 Critical if sensitive pages)
- Request with cookie returns `CF-Cache-Status: BYPASS` or `DYNAMIC` → ✅ Proper isolation
- Request without cookie returns `HIT` while with cookie returns `DYNAMIC` → ✅ Working as expected

### 11.4 Page Rule Analysis (Indirect)

While you cannot see Cloudflare page rules remotely, you can infer them:

```bash
# If these URLs all cache, there may be a "Cache Everything" rule
for page in "/" "/about/" "/contact/" "/wp-admin/" "/wp-login.php"; do
  STATUS=$(curl -sI "$TARGET$page" | grep -i 'cf-cache-status' | head -1)
  echo "$page → $STATUS"
  sleep 0.3
done
```

### 11.5 Bypassing Cloudflare Cache for Testing

```bash
# Use cache-busting headers
curl -sI -H "Cache-Control: no-cache, no-store, must-revalidate" \
  -H "Pragma: no-cache" \
  "https://target.tld/wp-admin/" \
  | grep -iE 'cf-cache-status|cache-control|set-cookie'

# Use a unique query parameter (may not bypass CF)
curl -sI "https://target.tld/wp-admin/?nocache=$(date +%s)" \
  | grep -iE 'cf-cache-status|cache-control'
```

**Severity:** 🟠 High (HIT on wp-admin → 🔴 Critical)

---

## 12. Remediation Recommendations

### 12.1 General Cache Security

| # | Recommendation | Priority |
|---|---|---|
| 1 | Disable directory listing in web server config for all `wp-content/` directories | 🔴 Critical |
| 2 | Add `deny from all` or equivalent rules for cache directories in `.htaccess`/`nginx.conf` | 🔴 Critical |
| 3 | Ensure PHP files execute instead of being served as plaintext | 🔴 Critical |
| 4 | Add `Cache-Control: no-store, private` to wp-admin and wp-login via server rules | 🟠 High |
| 5 | Ensure `Vary: Cookie` header is set on all WordPress responses | 🟠 High |
| 6 | Do not use Cloudflare "Cache Everything" page rules without bypass cookies | 🟠 High |
| 7 | Disable REST API cache for authenticated endpoints | 🟠 High |
| 8 | Never cache POST requests at the CDN/reverse proxy level | 🟠 High |
| 9 | Use the WordPress `NO_CACHE` constant or plugin filters for logged-in users | 🟡 Medium |
| 10 | Regularly audit `.htaccess` modifications made by cache plugins | 🟡 Medium |

### 12.2 Plugin-Specific

| Plugin | Recommendation |
|---|---|
| W3 Total Cache | Move `w3tc-config/` outside web root, disable DB cache disk storage, obfuscate cache keys |
| WP Super Cache | Set proper file permissions on cache directory (750/640), use mod_rewrite to block direct access |
| LiteSpeed Cache | Verify ESI is properly configured, check private cache settings, test logged-in user isolation |
| WP Rocket | Ensure `.htaccess` isn't world-readable, use `WP_ROCKET_CACHE_ROOT_PATH` to move cache directory |
| Flying Press/P/Swift | Disable AJAX endpoints for unauthenticated users, limit admin-ajax.php access |
| Cloudflare | Use "Bypass Cache on Cookie" with `wordpress_logged_in_*` pattern, avoid "Cache Everything" |

### 12.3 Server-Level .htaccess Block Example

```apache
# Block access to cache directories
<IfModule mod_rewrite.c>
  RewriteRule ^wp-content/cache/ - [F,L]
  RewriteRule ^wp-content/w3tc/ - [F,L]
  RewriteRule ^wp-content/w3tc-config/ - [F,L]
</IfModule>

# Set proper cache headers for admin pages
<IfModule mod_headers.c>
  <FilesMatch "wp-admin|wp-login">
    Header set Cache-Control "no-store, private, must-revalidate"
    Header set Pragma "no-cache"
  </FilesMatch>
</IfModule>
```

### 12.4 NGINX Equivalent

```nginx
# Block cache directory access
location ~* ^/wp-content/(cache|w3tc|w3tc-config)/ {
    deny all;
    return 403;
}

# Proper cache headers for admin
location ~* (wp-admin|wp-login) {
    add_header Cache-Control "no-store, private, must-revalidate";
    add_header Pragma "no-cache";
}

# Prevent logged-in user caching
if ($http_cookie ~* "wordpress_logged_in_") {
    set $no_cache 1;
}
proxy_no_cache $no_cache;
proxy_cache_bypass $no_cache;
```

---

## Scoring Summary

| Section | Test | Max Severity |
|---|---|---|
| 1 | Plugin Detection | ⚪ Informational |
| 2 | W3 Total Cache, DB cache/config/minify | 🔴 Critical |
| 3 | WP Super Cache, Config/cache files | 🔴 Critical |
| 4 | LiteSpeed Cache, Logged-in/ESI | 🔴 Critical |
| 5 | WP Rocket, Config/.htaccess/cache | 🔴 Critical |
| 6 | Flying Press/P/Swift, AJAX exposure | 🟠 High |
| 7 | REST API Cache Poisoning | 🔴 Critical |
| 8 | HTTP Method Caching | 🟠 High |
| 9 | Cache Headers Inspection | ⚪ Informational |
| 10 | Sensitive Page Caching | 🔴 Critical |
| 11 | CDN Cache Configuration | 🔴 Critical |

> **Overall Risk:** 🟠 High, Cache misconfigurations are common in WordPress and range from information disclosure to full account takeover via session leakage.

---

*Generated for professional WordPress security audits. Always obtain written authorization before testing.*
*Last updated: 2026-07-16*
