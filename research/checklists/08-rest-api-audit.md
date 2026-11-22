# WordPress REST API Security Audit

> **Audit Type:** Remote, No Authentication Required  
> **Scope:** Public-facing REST API exposure  
> **Severity Scale:** 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ⚪ Informational  
> **Target Audience:** Professional WordPress security auditors

---

## Table of Contents

1. [Introduction & Background](#1-introduction--background)
2. [REST API Namespace Enumeration](#2-rest-api-namespace-enumeration)
3. [Unauthenticated Endpoint Access Testing](#3-unauthenticated-endpoint-access-testing)
4. [User Enumeration](#4-user-enumeration)
5. [Posts/Pages Enumeration](#5-postspages-enumeration)
6. [Media Endpoint Exposure](#6-media-endpoint-exposure)
7. [Custom Plugin Endpoint Discovery](#7-custom-plugin-endpoint-discovery)
8. [Block Directory Endpoints](#8-block-directory-endpoints)
9. [Pattern Directory Endpoints](#9-pattern-directory-endpoints)
10. [Application Passwords Endpoint](#10-application-passwords-endpoint)
11. [CORS Configuration Test](#11-cors-configuration-test)
12. [REST API Disabled Check](#12-rest-api-disabled-check)
13. [JSONP Callback XSS](#13-jsonp-callback-xss)
14. [OEmbed SSRF Abuse](#14-oembed-ssrf-abuse)
15. [Search Endpoint Data Leakage](#15-search-endpoint-data-leakage)
16. [Complete REST API Footprint Script](#16-complete-rest-api-footprint-script)
17. [Remediation Recommendations](#17-remediation-recommendations)

---

## 1. Introduction & Background

WordPress introduced the REST API in core as part of **WP-API v2** (WordPress 4.7+, late 2016). Every modern WordPress site exposes a `/wp-json/` endpoint by default, even when the admin dashboard is locked down behind authentication or IP allowlists.

### Why This Matters

- **Attack surface expansion:** The REST API provides programmatic access to posts, users, comments, media, plugins, themes, and settings.
- **No authentication required by default:** Many endpoints are publicly readable. Sensitive data (email addresses, user slugs, password-protected content excerpts, private media URLs) can leak.
- **Plugin-bloated attack surface:** Each active plugin can register its own namespaces and endpoints, many are not security-reviewed.
- **WAF bypass:** Attackers use REST API calls because they look like legitimate traffic compared to `wp-admin` brute-force attempts.

### Pre-Audit Checklist

- [ ] Confirm the target domain resolves and is reachable
- [ ] Note if a WAF/CDN (Cloudflare, Sucuri, Wordfence, etc.) is present
- [ ] Test from an IP NOT allowlisted on the target (simulate real attacker)
- [ ] Use a fresh browser/curl session, no cookies, no cached auth tokens
- [ ] Respect `robots.txt` rate-limiting directives; throttle requests

---

## 2. REST API Namespace Enumeration

The `/wp-json/` root returns the entire API index, all registered namespaces, routes, and methods. This is your starting point.

### Curl Command

```bash
curl -s "https://target.tld/wp-json/" | jq '.'
```

### Stealth / Minimal Headers Variant

```bash
curl -s -H "User-Agent: Mozilla/5.0" -H "Accept: application/json" \
  "https://target.tld/wp-json/" | jq '.'
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| Namespaces listed under `namespaces` key | `"namespaces": ["oembed/1.0", "wp/v2", ...]` | ⚪ Informational |
| Total number of namespaces > 10 | Many custom namespaces = large attack surface | 🟡 Medium |
| Suspicious namespace names | `wp/v2/dg*`, `float-menu/*`, `erw-gdpr/*` (plugin names leak)  | 🟡 Medium |
| `_links` section revealing site metadata | `"href": "https://target.tld/wp-json/wp/v2/users"` | 🟡 Medium |
| Authentication methods exposed | `"authentication": [...]` shows what auth is available | ⚪ Informational |
| `site_logo`, `site_icon_url`, `site_icon` in index | Site identity information leakage | 🔵 Low |

### Expected JSON Structure

```json
{
  "namespaces": ["oembed/1.0", "wp/v2", "wp/v1", "akismet/v1", "contact-form-7/v1"],
  "authentication": {},
  "routes": {
    "/wp/v2/posts": { "endpoints": [...] },
    "/wp/v2/users": { "endpoints": [...] },
    ...
  },
  "site_logo": null,
  "site_icon_url": null
}
```

### Verification Steps

- [ ] Count namespaces, >15 is a red flag for bloat
- [ ] Search for versioned duplicates (`wp/v1`, `wp/v2`, `wp/v3`)
- [ ] Identify unknown namespaces that don't correspond to known plugins
- [ ] Check if `akismet/v1` is present (common leftover)

---

## 3. Unauthenticated Endpoint Access Testing

For every discovered namespace route, test GET, POST, PUT, DELETE access without authentication.

### Bulk Endpoint Discovery Command

First, extract all routes from the index:

```bash
curl -s "https://target.tld/wp-json/" | jq -r '.routes | keys[]' > routes.txt
```

### Per-Route Test Commands

```bash
# Define target and route
TARGET="https://target.tld"
ROUTE="/wp/v2/users"

# GET (Read), almost always public
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${ROUTE}"
echo ""

# POST (Create), should return 401/403 for unauth
curl -s -X POST -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${ROUTE}"
echo ""

# PUT (Update), should return 401/403 for unauth
curl -s -X PUT -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${ROUTE}"
echo ""

# DELETE (Delete), should return 401/403 for unauth
curl -s -X DELETE -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${ROUTE}"
echo ""
```

### Script for Bulk Testing All Routes

```bash
#!/bin/bash
# bulk-endpoint-test.sh, Test all routes for unauthenticated access
TARGET="https://target.tld"

echo "[+] Enumerating routes from ${TARGET}/wp-json/..."
ROUTES=$(curl -s "${TARGET}/wp-json/" | jq -r '.routes | keys[]')

echo "[+] Testing routes..."
echo "ROUTE | GET | POST | PUT | DELETE"
echo "------|-----|------|-----|-------"

for route in $ROUTES; do
  GET_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${route}")
  POST_CODE=$(curl -s -X POST -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${route}")
  PUT_CODE=$(curl -s -X PUT -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${route}")
  DEL_CODE=$(curl -s -X DELETE -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${route}")
  echo "${route} | ${GET_CODE} | ${POST_CODE} | ${PUT_CODE} | ${DEL_CODE}"
done
```

### Expected vs. Dangerous Response Codes

| Method | Expected (Secure) | Dangerous | Implication | Severity |
|--------|-------------------|-----------|-------------|----------|
| GET | 200 (public endpoints) or 401 | 200 on admin-only routes | Information disclosure | 🟡 Medium |
| POST | 401 or 403 | 200, 201, or 302 | Unauthenticated creation possible | 🔴 Critical |
| PUT  | 401 or 403 | 200 or 201 | Unauthenticated modification possible | 🔴 Critical |
| DELETE | 401 or 403 | 200 | Unauthenticated deletion possible | 🔴 Critical |

### HTTP Status Code Guide

| Code | Meaning | Security Implication |
|------|---------|---------------------|
| 200 | OK, endpoint returned data | Normal for GET on public routes |
| 201 | Created | Dangerous on POST without auth |
| 301/308 | Redirect, likely to login page | Common when logged-out users hit admin |
| 400 | Bad request, endpoint exists but params wrong | Confirms the route is active |
| 401 | Unauthorized, no auth provided | Expected for protected endpoints |
| 403 | Forbidden, auth attempted but denied | Better than 401; means access control works |
| 404 | Not found, route doesn't exist | Expected for nonexistent paths |
| 405 | Method not allowed | Acceptable for write methods on read-only routes |
| 500 | Server error, may leak debug info | 🟠 High if stack traces are returned |

### Verification Steps

- [ ] Run bulk test script against all routes
- [ ] For any POST/PUT/DELETE returning < 400, investigate manually
- [ ] Check response body for "rest_cannot_create"/"rest_cannot_edit" vs actual data
- [ ] Test with `-v` flag to inspect response headers for auth challenges

---

## 4. User Enumeration

One of the most well-known REST API abuses. By default, `/wp/v2/users/` returns a list of users with IDs, names, slugs, and, critically, **email addresses** on single-site installations after WordPress 4.7.1 (and always on multisite).

### WP v2 Users Endpoint

```bash
# List all users (paginated, 10 per page)
curl -s "https://target.tld/wp-json/wp/v2/users" | jq '.'

# Get more users (page through results)
curl -s "https://target.tld/wp-json/wp/v2/users?per_page=100&offset=0" | jq '.'

# Get specific user by ID
curl -s "https://target.tld/wp-json/wp/v2/users/1" | jq '.'

# Get current user (if any cookie/token present, for awareness)
curl -s "https://target.tld/wp-json/wp/v2/users/me" | jq '.'
```

### Legacy WP v1 Users Endpoint

Some sites still have WP REST API v1 active (either via plugin or outdated core):

```bash
curl -s "https://target.tld/wp-json/wp/v1/users" | jq '.'
curl -s "https://target.tld/wp-json/wp/v1/users/1" | jq '.'
```

### User Data Exposure Fields

```json
{
  "id": 1,
  "name": "Admin User",
  "url": "https://target.tld",
  "description": "",
  "link": "https://target.tld/author/admin/",
  "slug": "admin",
  "avatar_urls": { "24": "...", "48": "...", "96": "..." },
  "meta": [],
  "_links": { ... }
}
```

### What to Look For

| Finding | What to Check | Severity |
|---------|--------------|----------|
| Any users returned at all | Response array has > 0 entries | 🟠 High |
| Admin username discovered | `"slug": "admin"` or id=1 user exists | 🟠 High |
| Email addresses returned (multisite or < 4.7.1) | `"email": "user@domain.com"` in response | 🔴 Critical |
| Author archive URLs revealed | `"link": ".../author/admin/"` | 🟡 Medium |
| Gravatar hashes (avatar_urls) | Can be used to find associated email | 🟡 Medium |
| User IDs enumerable sequentially | IDs 1, 2, 3, 4, etc. all return valid users | 🟠 High |

### Mitigation Detections

| Indicator | Meaning |
|-----------|---------|
| `{"code":"rest_user_cannot_view","message":"..."}` | Users endpoint is restricted, good |
| `{"code":"rest_no_route","message":"..."}` | Route is disabled entirely, good |
| Empty array `[]` | Users exist but restricted from listing, partial protection |
| 404 Not Found | Route likely disabled via `remove_action` or plugin |
| Redirect to login | Access control plugin intercepting REST requests |

### Verification Steps

- [ ] Test `/wp/v2/users` with no parameters
- [ ] Test `/wp/v2/users/1` through `/wp/v2/users/20`
- [ ] Test `/wp/v2/users?who=authors` (only returns authors/editors)
- [ ] Test `/wp/v1/users` if namespace exists in root index
- [ ] Check if `X-WP-Total` and `X-WP-TotalPages` headers leak user count even on empty response

---

## 5. Posts/Pages Enumeration

The posts and pages endpoints can leak content, reveal post structure, and expose private/password-protected post metadata.

### Posts Endpoint

```bash
# List public posts
curl -s "https://target.tld/wp-json/wp/v2/posts" | jq '.'

# Get specific post
curl -s "https://target.tld/wp-json/wp/v2/posts/1" | jq '.'

# List all statuses (will only show public ones without auth)
curl -s "https://target.tld/wp-json/wp/v2/posts?status=publish,draft,private,future" | jq '.'

# Check for password-protected post content leakage
curl -s "https://target.tld/wp-json/wp/v2/posts?per_page=100" | \
  jq '.[] | select(.content.protected == true) | {id:, title:, slug:}'
```

### Pages Endpoint

```bash
# List all pages
curl -s "https://target.tld/wp-json/wp/v2/pages" | jq '.'

# Check for hidden/draft pages
curl -s "https://target.tld/wp-json/wp/v2/pages?per_page=100&status=any" | jq '.'
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| Password-protected posts detected | `"content.protected": true` appears | 🟡 Medium |
| Private post slugs/titles leaked | Private post appears in response (WP 4.7-4.7.4 vulnerability) | 🔴 Critical |
| Draft post content leaked | Draft posts visible in listing | 🟠 High |
| Future/scheduled posts exposed | Post dates in the future reveal content roadmap | 🟡 Medium |
| Revision history accessible | `/wp/v2/posts/1/revisions` returns data | 🟠 High |
| Post IDs sequential | Continuous IDs reveal total content count | 🔵 Low |
| `content.rendered` shows full body | Content body visibly readable | ⚪ Informational |
| Categories/tags exposed | Taxonomy data reveals content strategy | 🔵 Low |

### Post Status Values for Testing

```bash
for status in publish future draft pending private trash auto-draft inherit; do
  echo "=== Status: $status ==="
  curl -s "https://target.tld/wp-json/wp/v2/posts?status=$status&per_page=1" | \
    jq '[.[] | {id, title, status}]'
done
```

### Password-Protected Post Deep Check

```bash
# Check if password-protected post content leaks the excerpt
curl -s "https://target.tld/wp-json/wp/v2/posts" | \
  jq '.[] | select(.content.protected == true) | {id:, title:, excerpt:, guid:}'

# Try to access a protected post directly
curl -s "https://target.tld/wp-json/wp/v2/posts/42" | jq '.'
```

### Verification Steps

- [ ] Run posts listing with per_page=100
- [ ] Check for posts with `content.protected == true`
- [ ] Access `/wp/v2/posts/1/revisions` to check revision leakage
- [ ] Test `status` parameter with `any`, `private`, `draft`, `future`
- [ ] Count total posts via `X-WP-Total` header
- [ ] Test pages endpoint the same way

---

## 6. Media Endpoint Exposure

The media library can leak attachment metadata, full-size image URLs, and, critically, private media (images uploaded to password-protected or private posts).

### Media Endpoint

```bash
# List media items
curl -s "https://target.tld/wp-json/wp/v2/media" | jq '.'

# List media with more per page
curl -s "https://target.tld/wp-json/wp/v2/media?per_page=100" | jq '.'

# Get specific media item
curl -s "https://target.tld/wp-json/wp/v2/media/123" | jq '.'
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| Media IDs enumerable | Sequential IDs reveal total library size | 🔵 Low |
| Full-size image URLs exposed | `"source_url": "https://..."` reveals original files | 🟡 Medium |
| EXIF/metadata exposure | `"meta": {"exif": {...}}` leaks camera data, GPS | 🟠 High |
| Private media accessible | Media from private/password posts visible | 🟠 High |
| Attachment page URLs revealed | `"link": ".../attachment/..."` reveals structure | 🔵 Low |
| Alt text/descriptions leak content | `"alt_text"` and `"description"` may contain sensitive text | 🟡 Medium |
| Media uploaded by non-public users | `"author": 5` reveals additional user IDs | 🟡 Medium |

### Checking for Private Media Access

```bash
# Look for media items with no parent post (orphaned media)
curl -s "https://target.tld/wp-json/wp/v2/media?per_page=100" | \
  jq '.[] | select(.post == null) | {id:, title:, source_url:}'

# Check if media counts match expected public count vs actual total
curl -sI "https://target.tld/wp-json/wp/v2/media?per_page=1" | \
  grep -i "x-wp-total"
```

### Verification Steps

- [ ] List media items; check for any that look sensitive (screenshots, docs, PDFs)
- [ ] Check EXIF data on first 5 images
- [ ] Verify if media objects expose the original file path
- [ ] Attempt to access `/wp-json/wp/v2/media?per_page=100&offset=0`
- [ ] Check `media_details` for intermediate image sizes revealing full URL structure

---

## 7. Custom Plugin Endpoint Discovery

Third-party plugins frequently register their own REST API namespaces, often with authentication levels that are dangerously permissive.

### Discovery Commands

```bash
# Extract all custom namespaces (non-core)
curl -s "https://target.tld/wp-json/" | \
  jq -r '.namespaces[]' | \
  grep -v -E '^(oembed|wp/v[0-9])'
```

### Known Plugin Namespace Risk Database

| Namespace Pattern | Likely Plugin | Known Risk |
|-------------------|---------------|------------|
| `wp/v2/users` | Core | User enumeration (see §4) |
| `contact-form-7/v1` | Contact Form 7 | File upload bypass (historical) |
| `elementor/v1` | Elementor | Various CVEs |
| `akismet/v1` | Akismet | Low risk (spam checking) |
| `wpdiscuz/v1` | wpDiscuz | Comment injection |
| `woocommerce/*` | WooCommerce | Massive attack surface (see below) |
| `yoast/v1` | Yoast SEO | SEO data leakage |
| `jetpack/v[0-9]` | Jetpack | Token leakage (historical) |
| `rankmath/v1` | Rank Math | Schema injection |
| `wordfence/v1` | Wordfence | AI prompt injection (novel attack vector) |
| `wpgb/v1` | Gridbuilder | SQL injection (historical) |
| `wplms/v1` | WPLMS | Privilege escalation |
| `simple-jwt-login/v1` | Simple JWT Login | Critical auth bypass (many versions) |
| `wp-statistics/v1` | WP Statistics | Data exposure |
| `sassy-social-share` | Sassy Social Share | Unauthenticated options update |
| `really-simple-ssl/v1` | Really Simple SSL | Low risk |
| `litespeed/v1` | LiteSpeed Cache | Cache manipulation |
| `wp-file-manager/v1` | WP File Manager | Critical RCE (CVE-2020-25213) |
| `wpforms/v1` | WPForms | Form entry leakage |

### WooCommerce Sub-namespaces (Test Separately)

```bash
curl -s "https://target.tld/wp-json/" | jq -r '.namespaces[]' | grep -i woocommerce
# Expected: woocommerce, wc-analytics, wc-blocks, wc/store, wc/v3, wc/v2, wc/v1
```

For each custom namespace, run the bulk access test:

```bash
TARGET="https://target.tld"
NAMESPACE="wpdiscuz/v1"

echo "[*] Testing namespace: $NAMESPACE"
ROUTES=$(curl -s "${TARGET}/wp-json/" | \
  jq -r --arg ns "${NAMESPACE}" '.routes | to_entries[] | select(.key | startswith("/" + $ns)) | .key')

for route in $ROUTES; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/wp-json${route}")
  DATA=$(curl -s "${TARGET}/wp-json${route}" | jq '. | type')
  echo "  ${route} -> HTTP ${CODE} | Type: ${DATA}"
done
```

### What to Look For

| Finding | Severity |
|---------|----------|
| Plugin with known CVEs present | 🔴 Critical |
| Endpoint returns data for write methods | 🔴 Critical |
| Plugin namespace is still active but plugin is deactivated | 🟠 High |
| Unrecognized name-spaced endpoint returns user data | 🟠 High |
| Plugin exposes database queries directly | 🟠 High |
| Plugin endpoint has no auth check at all | 🟠 High |
| Deprecated plugin with no updates in 2+ years | 🟡 Medium |

### Verification Steps

- [ ] Document all non-core namespaces
- [ ] Cross-reference each with WPScan / CVE database
- [ ] Test each namespace's routes individually
- [ ] Google each unknown namespace for plugin identification
- [ ] Flag any namespace that allows POST/PUT/DELETE without auth

---

## 8. Block Directory Endpoints

WordPress 5.5+ introduced the Block Directory, an API endpoint that can leak information about installed blocks and search the WordPress block directory.

### Curl Commands

```bash
# Search the block directory (default WordPress endpoint)
curl -s "https://target.tld/wp-json/wp/v2/block-directory/search?term=accordion" | jq '.'

# Alternative: block types (lists registered blocks)
curl -s "https://target.tld/wp-json/wp/v2/block-types" | jq '.'
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| Block directory search returns results | Response is not 404 | ⚪ Informational |
| Internal blocks exposed | Core blocks listed in response | 🔵 Low |
| Plugin-added custom blocks visible | Custom block names reveal plugin stack | 🟡 Medium |
| Block metadata contains file paths | `"file": "..."` reveals server path | 🟡 Medium |

### Verification Steps

- [ ] Test `block-directory/search` with common terms
- [ ] Test `block-types` for registered blocks
- [ ] Check if `block-renderer` endpoint is accessible (can render blocks server-side)

---

## 9. Pattern Directory Endpoints

WordPress 5.5+ also introduced block patterns, reusable content layouts synced from the WordPress.org pattern directory.

### Curl Commands

```bash
# List available patterns
curl -s "https://target.tld/wp-json/wp/v2/pattern-directory/patterns?per_page=10" | jq '.'

# Search patterns by category
curl -s "https://target.tld/wp-json/wp/v2/pattern-directory/patterns?category=buttons" | jq '.'
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| Pattern directory accessible | Returns array of patterns | ⚪ Informational |
| Pattern content contains sensitive text | `"content": "...password..."` | 🟡 Medium |
| External requests triggered | Pattern fetching makes outbound calls | 🟠 High |

### SSRF Risk

The `pattern-directory/patterns` endpoint makes outbound HTTP requests to `api.wordpress.org`. In misconfigured environments, this can be abused:

```bash
# Trigger external request (monitor outbound traffic)
curl -s "https://target.tld/wp-json/wp/v2/pattern-directory/patterns" > /dev/null &

# Check server-side for requests to wp.org (on vulnerable configs)
# This is a passive observation test
```

### Verification Steps

- [ ] Access pattern directory endpoint
- [ ] Check if response contains any data from WordPress.org
- [ ] Note that this endpoint inherently makes outbound calls (potential SSRF vector in restricted networks)

---

## 10. Application Passwords Endpoint

WordPress 5.6+ introduced Application Passwords for REST API authentication. The endpoint can leak user data and confirm auth methods.

### Curl Commands

```bash
# Check if application passwords are available
curl -s "https://target.tld/wp-json/wp/v2/users/1/application-passwords" | jq '.'

# Check current user's application passwords (requires auth, but tests exposure)
curl -s "https://target.tld/wp-json/wp/v2/users/me/application-passwords" | jq '.'

# Test the applications-passwords endpoint directly
curl -s "https://target.tld/wp-json/wp/v2/users/1/application-passwords?context=edit" | jq '.'
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| Application passwords endpoint exists | Route is not 404 | 🟡 Medium |
| Endpoint returns data without auth | Any data in response | 🔴 Critical |
| Endpoint confirms user existence | "rest_user_invalid_id" vs "rest_no_route" difference | 🟡 Medium |
| Error message leaks user ID validity | `"message": "Invalid user ID."` vs generic 404 | 🟡 Medium |

### Error Message Oracle

```bash
# User exists → specific error
curl -s "https://target.tld/wp-json/wp/v2/users/1/application-passwords"
# Response: {"code":"rest_user_cannot_view","message":"...","data":{"status":401}}

# User doesn't exist → different error
curl -s "https://target.tld/wp-json/wp/v2/users/9999/application-passwords"
# Response: {"code":"rest_user_invalid_id","message":"...","data":{"status":404}}
```

This differential response allows user ID enumeration even when `/wp/v2/users` is restricted.

### Verification Steps

- [ ] Test `application-passwords` endpoint for user ID 1
- [ ] Check for oracle-based user enumeration (different error for valid vs. invalid users)
- [ ] Test `me/application-passwords` in case cookies are somehow present
- [ ] Note if Application Passwords are enabled (feature can be turned off)

---

## 11. CORS Configuration Test

CORS (Cross-Origin Resource Sharing) headers control which domains can read API responses via JavaScript. Misconfigured CORS can lead to data theft via CSRF-style attacks.

### Curl Commands

```bash
# Test with no Origin header (baseline)
curl -sI "https://target.tld/wp-json/wp/v2/posts" | \
  grep -i "access-control-allow-origin"

# Test with arbitrary Origin
curl -s -H "Origin: https://evil.com" "https://target.tld/wp-json/wp/v2/posts" | \
  grep -i "access-control-allow-origin"

# Test with null Origin
curl -s -H "Origin: null" "https://target.tld/wp-json/wp/v2/posts" | \
  grep -i -E "access-control-allow-origin|access-control-allow-credentials"

# Check credentialed requests
curl -s -I -H "Origin: https://evil.com" \
  -H "Cookie: test=value" \
  "https://target.tld/wp-json/wp/v2/posts" | \
  grep -i -E "access-control-allow-origin|access-control-allow-credentials"

# Full preflight check
curl -s -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization" \
  "https://target.tld/wp-json/wp/v2/posts" -I | \
  grep -i "access-control"
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| No CORS headers | No `Access-Control-Allow-Origin` header | ⚪ Informational (browser blocks) |
| Wildcard CORS | `Access-Control-Allow-Origin: *` | 🟡 Medium |
| Reflective CORS (dangerous) | `Access-Control-Allow-Origin: https://evil.com` (echoed) | 🔴 Critical |
| Null origin accepted | Origin: null → allowed | 🟠 High |
| Credentials allowed with wildcard | `Access-Control-Allow-Credentials: true` + `*` | 🔴 Critical |
| Credentials allowed with reflective origin | `Access-Control-Allow-Credentials: true` + echoed Origin | 🔴 Critical |
| Multiple origins returned | Broken header parsing | 🟡 Medium |

### Why Reflective CORS is Dangerous

If the server echoes back `Origin: https://evil.com` as `Access-Control-Allow-Origin: https://evil.com` AND includes `Access-Control-Allow-Credentials: true`, an attacker can:

1. Serve a malicious page at `https://evil.com`
2. Make authenticated `fetch()` calls to the WordPress REST API
3. Read the responses, including private data, because CORS allows it
4. Exfiltrate via `XMLHttpRequest` or `fetch()`

This is a **data exfiltration vulnerability** that bypasses standard CSRF protections.

### Verification Steps

- [ ] Check baseline CORS (no Origin header)
- [ ] Test with arbitrary Origin header
- [ ] Test with `Origin: null`
- [ ] Test with preflight OPTIONS request
- [ ] Check for `Access-Control-Allow-Credentials: true` combined with permissive origins

---

## 12. REST API Disabled Check

Some sites attempt to disable the REST API. These efforts are often incomplete and can be bypassed.

### Bypass Techniques

```bash
# Raw rest_route query parameter bypass
curl -s "https://target.tld/?rest_route=/wp/v2/posts" | head -50

# With JSON content negotiation
curl -s -H "Accept: application/json" "https://target.tld/?rest_route=/wp/v2/users" | head -50

# Alternative: X-HTTP-Method-Override
curl -s -X POST \
  -H "X-HTTP-Method-Override: GET" \
  "https://target.tld/wp-json/wp/v2/posts" | jq '.'

# Test with REST API constant (if site has custom code)
curl -s "https://target.tld/wp-json/wp/v2/posts?rest_enabled=false" | jq '.'
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| REST API fully accessible | JSON returned normally | ⚪ Informational |
| REST API disabled via `?rest_route=` | Returns HTML (not JSON) | 🔵 Low |
| REST API partially disabled | Users blocked but posts accessible | 🟡 Medium |
| REST API disabled but static `?rest_route=` works | Bypass found | 🟠 High |
| JSON returned via `?rest_route=` | Bypass confirms incomplete disable | 🟠 High |
| WP returns 404 for `/wp-json/` but `?rest_route=` works | Common incomplete config | 🟠 High |

### Detection Logic

```bash
# Method 1: Is JSON returned?
RESULT=$(curl -s "https://target.tld/?rest_route=/wp/v2/posts&per_page=1")
echo "$RESULT" | jq '.' > /dev/null 2>&1 && echo "JSON detected - REST API active" || echo "HTML/redirect - REST API may be disabled"

# Method 2: Compare content types
curl -sI "https://target.tld/wp-json/wp/v2/posts" | grep -i content-type
curl -sI "https://target.tld/?rest_route=/wp/v2/posts" | grep -i content-type
```

### Verification Steps

- [ ] Test `/wp-json/wp/v2/posts`, baseline
- [ ] Test `/?rest_route=/wp/v2/posts`, bypass check
- [ ] Test `/?rest_route=/wp/v2/users`, most commonly disabled
- [ ] Test with `Accept: application/json` header
- [ ] Compare content-type headers between methods

---

## 13. JSONP Callback XSS

WordPress historically supported JSONP callbacks, a technique where a `?_jsonp=` or `callback=` parameter wraps JSON in a function call. This is an XSS vector if not properly sanitized.

### Curl Commands

```bash
# Test JSONP callback in REST API
curl -s "https://target.tld/wp-json/wp/v2/posts?_jsonp=alert(1)" | head -5

# Test with callback parameter (legacy)
curl -s "https://target.tld/wp-json/wp/v2/posts?callback=alert(1)" | head -5

# Test with _envelope parameter (also wrapped)
curl -s "https://target.tld/wp-json/wp/v2/posts?_envelope=1" | head -5

# Test with _method parameter
curl -s "https://target.tld/wp-json/wp/v2/posts?_method=DELETE" | head -5
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| Reflection of callback name | Response starts with `alert(1)({...})` | 🔴 Critical |
| Sanitized callback (stripped) | `alert1` or `invalid` returned | 🟡 Medium |
| Callback rejected | 400 error returned | 🔵 Low (safe) |
| Callback not supported | Normal JSON response (ignore param) | ⚪ Informational |
| `_method` override accepted | DELETE response returned | 🟠 High |

### XSS Confirmation

```bash
# Check if callback value is reflected unsanitized
curl -s "https://target.tld/wp-json/wp/v2/posts?_jsonp=<script>alert(1)</script>" | head -3

# Response starts with: <script>alert(1)</script>({...}) → XSS confirmed
```

### Variation with Parameters

Test all common parameter names:

```bash
for param in "_jsonp" "callback" "jsonp" "jsoncallback" "fn" "cb" "format"; do
  echo "=== Testing: ${param} ==="
  curl -s "https://target.tld/wp-json/wp/v2/posts?${param}=testCallback" | head -3
  echo ""
done
```

### Verification Steps

- [ ] Test `_jsonp` parameter with `alert(1)` value
- [ ] Test `callback` parameter with `alert(1)` value
- [ ] Check if angle brackets `<` and `>` are stripped or encoded
- [ ] Test if the response content-type is `application/json` (safe) or `text/javascript` (XSS vector)

---

## 14. OEmbed SSRF Abuse

The oEmbed proxy endpoint can be abused for Server-Side Request Forgery (SSRF), internal network scanning, and data exfiltration.

### Curl Commands

```bash
# Default oEmbed endpoint (requires URL parameter)
curl -s "https://target.tld/wp-json/oembed/1.0/embed?url=https://target.tld/hello-world/" | jq '.'

# SSRF test, try to make the server fetch internal resources
curl -s "https://target.tld/wp-json/oembed/1.0/embed?url=http://127.0.0.1:80/wp-admin/"
curl -s "https://target.tld/wp-json/oembed/1.0/embed?url=http://127.0.0.1:3306/"
curl -s "https://target.tld/wp-json/oembed/1.0/embed?url=http://localhost/wp-json/"
curl -s "https://target.tld/wp-json/oembed/1.0/embed?url=http://169.254.169.254/latest/meta-data/"  # AWS metadata

# Proxy/SSRF, check if server fetches external URLs
curl -s "https://target.tld/wp-json/oembed/1.0/embed?url=https://webhook.site/YOUR-ID"
curl -s "https://target.tld/wp-json/oembed/1.0/embed?url=http://YOUR-SERVER:8080/"

# Proxy endpoint (alternative SSRF vector)
curl -s "https://target.tld/wp-json/oembed/1.0/proxy?url=http://127.0.0.1/wp-admin/"
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| oEmbed accessible | Returns JSON with oEmbed data | ⚪ Informational |
| SSRF confirmed | External server receives request | 🔴 Critical |
| Internal service response | Response contains data from internal service | 🔴 Critical |
| AWS metadata accessible | Returns IAM role credentials | 🔴 Critical |
| Error message leaks internal IP | `"message": "Could not connect to 10.0.0.5:80"` | 🟠 High |
| Timeout difference reveals host alive | Different response times for alive vs dead hosts | 🟠 High |
| Proxy endpoint accessible | `/oembed/1.0/proxy` returns data | 🟡 Medium |

### SSRF Detection via Timing

```bash
# Fast response (likely failed immediately)
time curl -s -o /dev/null "https://target.tld/wp-json/oembed/1.0/embed?url=http://192.168.1.1:80/"

# Slow response (possibly timed out trying to connect, host might exist)
time curl -s -o /dev/null "https://target.tld/wp-json/oembed/1.0/embed?url=http://192.168.1.254:80/"
```

### Verification Steps

- [ ] Test oEmbed with legitimate URL first
- [ ] Test SSRF on `127.0.0.1:80`, `127.0.0.1:3306`, `localhost`
- [ ] Test SSRF on RFC 1918 address range
- [ ] Test cloud metadata endpoints (AWS/GCP/Azure)
- [ ] Test with a webhook/collaborator to confirm outbound request
- [ ] Test proxy endpoint
- [ ] Check for 302 redirect abuse (oEmbed follows redirects)

---

## 15. Search Endpoint Data Leakage

The REST API search endpoint aggregates results across post types. It can reveal content not intended for public view.

### Curl Commands

```bash
# Basic search
curl -s "https://target.tld/wp-json/wp/v2/search?search=admin&per_page=20" | jq '.'

# Search for sensitive keywords
for term in "password" "confidential" "internal" "draft" "private" "secret" "api-key" \
            "token" "vpn" "192.168" "10.0." "admin" "root" "backup" "wp-config"; do
  echo "=== Searching: $term ==="
  curl -s "https://target.tld/wp-json/wp/v2/search?search=${term}&per_page=5" | \
    jq '[.[] | {id, title, type, url}]'
done
```

### Search by Type

```bash
# Search only posts
curl -s "https://target.tld/wp-json/wp/v2/search?search=confidential&type=post" | jq '.'

# Search only pages
curl -s "https://target.tld/wp-json/wp/v2/search?search=confidential&type=page" | jq '.'

# Search all subtypes
curl -s "https://target.tld/wp-json/wp/v2/search?search=confidential&subtype=any" | jq '.'
```

### What to Look For

| Finding | Indicator | Severity |
|---------|-----------|----------|
| Draft posts appear in search | `"title": "Draft Post"` in search results | 🟠 High |
| Private pages found in search | Search returns content from private posts | 🟠 High |
| Sensitive content indexed | `"title": "VPN Config"` appears | 🟠 High |
| User names found in search | `"type": "user"` results returned | 🟡 Medium |
| Search results > expected | More results than public posts exist | 🟠 High |
| Search URL format revealed | `"url": "https://...?p=123"` reveals permalinks | 🔵 Low |

### Verification Steps

- [ ] Search for "admin", "password", "confidential"
- [ ] Search for site-specific keywords (company name, project names)
- [ ] Check search response for different types (post, page, user)
- [ ] Compare search result count to public post count
- [ ] Search for user names revealed during user enumeration

---

## 16. Complete REST API Footprint Script

Below is a comprehensive, self-contained Bash script that performs all the checks above. Save it as `wp-rest-audit.sh` and run against any target.

```bash
#!/bin/bash
#===============================================================================
# WordPress REST API Security Audit Script
# Author: Professional Security Audit
# Usage:  ./wp-rest-audit.sh <target-url>
# Example: ./wp-rest-audit.sh https://example.com
#===============================================================================

set -e

TARGET="${1%/}"
OUTPUT_DIR="wp-rest-audit-$(echo $TARGET | sed 's|https\?://||' | tr '/:' '_')"
TIMESTAMP=$(date +"%Y-%m-%d_%H:%M:%S")
SCRIPT_VERSION="1.0.0"

if [ -z "$TARGET" ]; then
  echo "[!] Usage: $0 <target-url>"
  echo "[!] Example: $0 https://example.com"
  exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

mkdir -p "$OUTPUT_DIR"

echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║${NC}  WordPress REST API Security Audit v${SCRIPT_VERSION}            ${MAGENTA}║${NC}"
echo -e "${MAGENTA}║${NC}  Target: ${TARGET}                                     ${MAGENTA}║${NC}"
echo -e "${MAGENTA}║${NC}  Date:   ${TIMESTAMP}                               ${MAGENTA}║${NC}"
echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

REPORT="${OUTPUT_DIR}/audit-report.md"
FOOTPRINT="${OUTPUT_DIR}/footprint.json"

#----------------------------------------------------------------------
# Helper functions
#----------------------------------------------------------------------
check() {
  local test_name="$1"
  local test_command="$2"
  local severity="$3"
  echo -n "  [*] ${test_name}... "

  eval "$test_command" > "${OUTPUT_DIR}/${test_name// /_}.tmp" 2>&1
  local result=$?

  if [ $result -eq 0 ]; then
    echo -e "${GREEN}DONE${NC}"
  else
    echo -e "${RED}FAILED${NC}"
  fi
  return $result
}

print_banner() {
  echo "" >> "$REPORT"
  echo "---" >> "$REPORT"
  echo "## $1" >> "$REPORT"
  echo "" >> "$REPORT"
}

write_finding() {
  local finding="$1"
  local detail="$2"
  local severity="$3"
  
  local emoji=""
  case "$severity" in
    CRITICAL) emoji="🔴" ;;
    HIGH)     emoji="🟠" ;;
    MEDIUM)   emoji="🟡" ;;
    LOW)      emoji="🔵" ;;
    INFO)     emoji="⚪" ;;
  esac

  echo "  ${emoji} [${severity}] ${finding}" >> "$REPORT"
  echo "    ${detail}" >> "$REPORT"
  echo "" >> "$REPORT"
}

#----------------------------------------------------------------------
# Initialize report
#----------------------------------------------------------------------
cat > "$REPORT" << EOF
# WordPress REST API Security Audit Report

**Target:** ${TARGET}
**Date:** ${TIMESTAMP}
**Script Version:** ${SCRIPT_VERSION}

---

## Executive Summary

EOF

echo -e "${CYAN}[*] Phase 1: Reconnaissance, REST API Root${NC}"

#==============================================================================
# 1. REST API Namespace Enumeration
#==============================================================================
print_banner "1. REST API Namespace Enumeration"

echo -e "  ${CYAN}[+] Fetching /wp-json/ root...${NC}"
ROOT_JSON=$(curl -s --max-time 15 "${TARGET}/wp-json/" 2>&1) || echo '{"namespaces":[],"routes":{}}'

echo "$ROOT_JSON" > "${OUTPUT_DIR}/wp-json-root.json"
echo "$ROOT_JSON" | jq '.' > "${OUTPUT_DIR}/wp-json-root-pretty.json" 2>/dev/null || \
  echo "$ROOT_JSON" > "${OUTPUT_DIR}/wp-json-root-pretty.json"

NAMESPACES=$(echo "$ROOT_JSON" | jq -r '.namespaces[]' 2>/dev/null || echo "none")
ROUTE_COUNT=$(echo "$ROOT_JSON" | jq '.routes | length' 2>/dev/null || echo "0")

echo "  [-] Namespaces discovered:"
for ns in $NAMESPACES; do
  echo "        - $ns"
done
echo "  [-] Total routes: $ROUTE_COUNT"

if [ "$NAMESPACES" = "none" ]; then
  write_finding "No REST API namespaces found" "The /wp-json/ endpoint returned no namespaces. REST API may be disabled." "INFO"
else
  write_finding "REST API is active" "${ROUTE_COUNT} routes across $(echo "$NAMESPACES" | wc -w) namespaces" "INFO"
  
  CORE_NS=$(echo "$NAMESPACES" | grep -c -E '^(oembed|wp/v[0-9])' 2>/dev/null || echo "0")
  CUSTOM_NS=$(echo "$NAMESPACES" | grep -c -v -E '^(oembed|wp/v[0-9])' 2>/dev/null || echo "0")
  
  if [ "$CUSTOM_NS" -gt 5 ]; then
    write_finding "High number of custom namespaces" "${CUSTOM_NS} custom namespaces detected. Each represents a plugin's attack surface." "MEDIUM"
  fi
  
  for ns in $NAMESPACES; do
    echo "$ns" >> "${OUTPUT_DIR}/namespaces.txt"
  done
fi

#==============================================================================
# 2. Route Access Testing (Sample - all routes is expensive)
#==============================================================================
print_banner "2. Unauthenticated Endpoint Access Testing"

echo -e "  ${CYAN}[+] Testing key routes for unauthenticated access...${NC}"

# Test core routes that matter most
CORE_ROUTES=$(echo "$ROOT_JSON" | jq -r '.routes | keys[] | select(startswith("/wp/v2/") or startswith("/oembed/") or startswith("/wp/v1/"))' 2>/dev/null | head -30)

if [ -n "$CORE_ROUTES" ]; then
  echo "  Route | GET | POST | PUT | DELETE" > "${OUTPUT_DIR}/route-access.csv"
  echo "  -|-|-|-|-" >> "${OUTPUT_DIR}/route-access.csv"
  
  for route in $CORE_ROUTES; do
    GET_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/wp-json${route}")
    POST_CODE=$(curl -s -X POST -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/wp-json${route}")
    PUT_CODE=$(curl -s -X PUT -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/wp-json${route}")
    DEL_CODE=$(curl -s -X DELETE -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/wp-json${route}")
    
    echo "  ${route} | ${GET_CODE} | ${POST_CODE} | ${PUT_CODE} | ${DEL_CODE}" >> "${OUTPUT_DIR}/route-access.csv"
    
    # Flag dangerous methods
    if [ "$POST_CODE" = "200" ] || [ "$POST_CODE" = "201" ]; then
      write_finding "Unauthenticated POST allowed on ${route}" "HTTP ${POST_CODE}, potential data creation by unauthenticated users" "CRITICAL"
    fi
    if [ "$PUT_CODE" = "200" ] || [ "$PUT_CODE" = "201" ]; then
      write_finding "Unauthenticated PUT allowed on ${route}" "HTTP ${PUT_CODE}, potential data modification by unauthenticated users" "CRITICAL"
    fi
    if [ "$DEL_CODE" = "200" ]; then
      write_finding "Unauthenticated DELETE allowed on ${route}" "HTTP ${DEL_CODE}, potential data deletion by unauthenticated users" "CRITICAL"
    fi
  done
else
  write_finding "Could not extract routes" "REST API root may not be accessible or JSON format is unexpected" "INFO"
fi

#==============================================================================
# 3. User Enumeration
#==============================================================================
print_banner "3. User Enumeration"

echo -e "  ${CYAN}[+] Testing user enumeration...${NC}"

USERS_V2=$(curl -s --max-time 15 "${TARGET}/wp-json/wp/v2/users" 2>&1)
echo "$USERS_V2" > "${OUTPUT_DIR}/users-v2.json"

USERS_V2_COUNT=$(echo "$USERS_V2" | jq '. | length' 2>/dev/null || echo "0")
USERS_V2_ERROR=$(echo "$USERS_V2" | jq -r '.code // "none"' 2>/dev/null)

if [ "$USERS_V2_COUNT" -gt 0 ] 2>/dev/null; then
  write_finding "User enumeration via /wp/v2/users, ${USERS_V2_COUNT} users exposed" \
    "User IDs, slugs, names, and avatar URLs are publicly accessible" "HIGH"
  
  echo "$USERS_V2" | jq '.[] | {id, name, slug, link}' >> "${OUTPUT_DIR}/users-v2-dump.json"
  
  # Check for admin user
  ADMIN_CHECK=$(echo "$USERS_V2" | jq '.[] | select(.slug == "admin" or .id == 1) | {id, name, slug}' 2>/dev/null)
  if [ -n "$ADMIN_CHECK" ] && [ "$ADMIN_CHECK" != "{}" ] && [ "$ADMIN_CHECK" != "[]" ]; then
    write_finding "Admin user discovered" "User with id=1 or slug='admin' found: $(echo $ADMIN_CHECK | jq -c '.')" "HIGH"
  fi
elif [ "$USERS_V2_ERROR" != "none" ]; then
  write_finding "Users endpoint restricted" "Error: ${USERS_V2_ERROR}, users are protected" "INFO"
  
  # Check for info leakage in error
  if echo "$USERS_V2" | jq -r '.code' 2>/dev/null | grep -q "rest_user_cannot_view"; then
    write_finding "Users endpoint exists but restricted (rest_user_cannot_view)" \
      "Better than no protection, but confirms REST API user route is active" "LOW"
  fi
else
  write_finding "Users endpoint returned $USERS_V2_COUNT results" "Unexpected response format" "MEDIUM"
fi

# Check user by ID (oracle test)
for uid in 1 2 3 4 5; do
  USER_CHECK=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/users/${uid}" 2>&1)
  USER_CODE=$(echo "$USER_CHECK" | jq -r '.code // "data_returned"' 2>/dev/null)
  
  # Detailed oracle, different errors reveal user existence
  case "$USER_CODE" in
    "rest_user_invalid_id")
      echo "  [-] User $uid: Does not exist" >> "${OUTPUT_DIR}/user-oracle.txt"
      ;;
    "rest_user_cannot_view")
      echo "  [-] User $uid: Exists but protected" >> "${OUTPUT_DIR}/user-oracle.txt"
      write_finding "User ID oracle confirmed: User $uid exists" \
        "Differential error response reveals valid user IDs even when listing is blocked" "MEDIUM"
      ;;
    "data_returned")
      echo "  [-] User $uid: DATA EXPOSED" >> "${OUTPUT_DIR}/user-oracle.txt"
      ;;
  esac
done

# Check v1
USERS_V1=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v1/users" 2>&1)
echo "$USERS_V1" > "${OUTPUT_DIR}/users-v1.json"
USERS_V1_CODE=$(echo "$USERS_V1" | jq -r '.code // "data"' 2>/dev/null)
if [ "$USERS_V1_CODE" = "data" ] && [ "$(echo "$USERS_V1" | jq '. | length' 2>/dev/null)" -gt 0 ]; then
  write_finding "Legacy WP v1 users endpoint is active and exposes data" \
    "The wp/v1 namespace is outdated and may bypass restrictions on v2" "HIGH"
fi

#==============================================================================
# 4. Posts/Pages Enumeration
#==============================================================================
print_banner "4. Posts and Pages Enumeration"

echo -e "  ${CYAN}[+] Testing posts/pages exposure...${NC}"

# Count totals from headers
POSTS_HEADERS=$(curl -sI --max-time 10 "${TARGET}/wp-json/wp/v2/posts?per_page=1" 2>&1)
POSTS_TOTAL=$(echo "$POSTS_HEADERS" | grep -i "x-wp-total" | head -1 | awk '{print $2}' | tr -d '\r')

if [ -n "$POSTS_TOTAL" ]; then
  write_finding "Total posts disclosed via X-WP-Total header" "${POSTS_TOTAL} posts exist on this site" "LOW"
fi

# Check for password-protected posts
POSTS_DATA=$(curl -s --max-time 15 "${TARGET}/wp-json/wp/v2/posts?per_page=100" 2>&1)
echo "$POSTS_DATA" > "${OUTPUT_DIR}/posts.json"

PROTECTED_COUNT=$(echo "$POSTS_DATA" | jq '[.[] | select(.content.protected == true)] | length' 2>/dev/null || echo "0")
if [ "$PROTECTED_COUNT" -gt 0 ] 2>/dev/null; then
  write_finding "${PROTECTED_COUNT} password-protected posts detected" \
    "These posts have content.protected=true. Check if titles/slugs reveal sensitive info" "MEDIUM"
fi

# Test for private post leakage by trying status parameter
PRIVACY_TEST=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/posts?status=private&per_page=1" 2>&1)
PRIV_CODE=$(echo "$PRIVACY_TEST" | jq -r '.code // "data"' 2>/dev/null)
if [ "$PRIV_CODE" != "rest_invalid_param" ] && [ "$PRIV_CODE" != "data" ]; then
  echo "$PRIVACY_TEST" > "${OUTPUT_DIR}/posts-private.json"
fi

# Pages
PAGES_DATA=$(curl -s --max-time 15 "${TARGET}/wp-json/wp/v2/pages?per_page=100" 2>&1)
echo "$PAGES_DATA" > "${OUTPUT_DIR}/pages.json"
PAGE_COUNT=$(echo "$PAGES_DATA" | jq '. | length' 2>/dev/null || echo "0")
if [ "$PAGE_COUNT" -gt 0 ] 2>/dev/null; then
  write_finding "${PAGE_COUNT} pages accessible via REST API" \
    "All public pages are enumerable" "INFO"
fi

# Check revisions
REV_TEST=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/posts/1/revisions?per_page=1" 2>&1)
REV_CODE=$(echo "$REV_TEST" | jq -r '.code // "data"' 2>/dev/null)
if [ "$REV_CODE" = "data" ] && [ "$(echo "$REV_TEST" | jq '. | length' 2>/devμβρίου)" -gt 0 ]; then
  write_finding "Post revisions accessible unauthenticated" \
    "Post revisions may contain content not present in published versions" "HIGH"
fi

#==============================================================================
# 5. Media Endpoint
#==============================================================================
print_banner "5. Media Endpoint Exposure"

echo -e "  ${CYAN}[+] Testing media endpoint...${NC}"

MEDIA_HEADERS=$(curl -sI --max-time 10 "${TARGET}/wp-json/wp/v2/media?per_page=1" 2>&1)
MEDIA_TOTAL=$(echo "$MEDIA_HEADERS" | grep -i "x-wp-total" | head -1 | awk '{print $2}' | tr -d '\r')

MEDIA_DATA=$(curl -s --max-time 15 "${TARGET}/wp-json/wp/v2/media?per_page=20" 2>&1)
echo "$MEDIA_DATA" > "${OUTPUT_DIR}/media.json"

if [ -n "$MEDIA_TOTAL" ] && [ "$MEDIA_TOTAL" -gt 0 ] 2>/dev/null; then
  write_finding "Media library exposes ${MEDIA_TOTAL} items" \
    "Public media items are enumerable via REST API" "LOW"
  
  # Check for EXIF
  EXIF_CHECK=$(echo "$MEDIA_DATA" | jq '.[].meta | select(.exif != null)' 2>/dev/null)
  if [ -n "$EXIF_CHECK" ] && [ "$EXIF_CHECK" != "[]" ]; then
    write_finding "EXIF metadata exposed in media items" \
      "Camera data, GPS coordinates, and timestamps may be leaked" "HIGH"
  fi
fi

#==============================================================================
# 6. Custom Plugin Endpoints
#==============================================================================
print_banner "6. Custom Plugin Endpoints"

echo -e "  ${CYAN}[+] Analyzing custom namespaces...${NC}"

for ns in $NAMESPACES; do
  # Skip core namespaces
  case "$ns" in
    oembed/1.0|oembed/1.0/embed|wp/v2|wp/v1|wp/v3|wp/site-health|wp/block*|wp/pattern*) continue ;;
  esac
  
  ns_routes=$(echo "$ROOT_JSON" | jq -r --arg ns "$ns" '.routes | keys[] | select(startswith("/" + $ns))' 2>/dev/null)
  
  if [ -n "$ns_routes" ]; then
    echo "  [${ns}]" >> "${OUTPUT_DIR}/custom-namespaces.txt"
    echo "$ns_routes" >> "${OUTPUT_DIR}/custom-namespaces.txt"
    
    # Test first route
    first_route=$(echo "$ns_routes" | head -1)
    if [ -n "$first_route" ]; then
      ns_response=$(curl -s --max-time 10 "${TARGET}/wp-json${first_route}" 2>&1)
      ns_code=$(echo "$ns_response" | jq -r '.code // "data"' 2>/dev/null)
      
      if [ "$ns_code" = "data" ]; then
        write_finding "Custom namespace '${ns}' returns unauthenticated data" \
          "First route: ${first_route}, returns data without authentication" "MEDIUM"
      fi
    fi
  fi
done

#==============================================================================
# 7. Block Directory Endpoints
#==============================================================================
print_banner "7. Block Directory Endpoints"

echo -e "  ${CYAN}[+] Testing block directory...${NC}"

BLOCK_TYPES=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/block-types" 2>&1)
echo "$BLOCK_TYPES" > "${OUTPUT_DIR}/block-types.json"
BT_CODE=$(echo "$BLOCK_TYPES" | jq -r '.code // "data"' 2>/dev/null)
if [ "$BT_CODE" = "data" ]; then
  BT_COUNT=$(echo "$BLOCK_TYPES" | jq '. | length' 2>/dev/null || echo "0")
  write_finding "Block types endpoint accessible (${BT_COUNT} block types)" \
    "Registers all available blocks including plugin-added custom blocks" "LOW"
fi

BLOCK_DIR=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/block-directory/search?term=accordion" 2>&1)
echo "$BLOCK_DIR" > "${OUTPUT_DIR}/block-directory.json"
BD_CODE=$(echo "$BLOCK_DIR" | jq -r '.code // "data"' 2>/dev/null)
if [ "$BD_CODE" = "data" ]; then
  write_finding "Block directory search endpoint accessible" \
    "Can be used to search the WordPress.org block directory. Limited risk." "LOW"
fi

#==============================================================================
# 8. Pattern Directory Endpoints
#==============================================================================
print_banner "8. Pattern Directory Endpoints"

echo -e "  ${CYAN}[+] Testing pattern directory...${NC}"

PATTERNS=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/pattern-directory/patterns?per_page=1" 2>&1)
echo "$PATTERNS" > "${OUTPUT_DIR}/pattern-directory.json"
PT_CODE=$(echo "$PATTERNS" | jq -r '.code // "data"' 2>/dev/null)
if [ "$PT_CODE" = "data" ]; then
  write_finding "Pattern directory endpoint accessible" \
    "Makes outbound requests to WordPress.org. Low risk for SSRF." "INFO"
fi

#==============================================================================
# 10. Application Passwords
#==============================================================================
print_banner "9. Application Passwords Endpoint"

echo -e "  ${CYAN}[+] Testing application passwords...${NC}"

APP_PASSWORDS=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/users/1/application-passwords" 2>&1)
echo "$APP_PASSWORDS" > "${OUTPUT_DIR}/application-passwords.json"
AP_CODE=$(echo "$APP_PASSWORDS" | jq -r '.code // "data"' 2>/dev/null)

case "$AP_CODE" in
  "rest_no_route")
    write_finding "Application passwords endpoint not found (rest_no_route)" \
      "Feature is likely disabled, secure" "INFO"
    ;;
  "rest_user_cannot_view"|"rest_cannot_view"*)
    write_finding "Application passwords endpoint exists but restricted" \
      "Route is active but requires authentication" "LOW"
    ;;
  "rest_user_invalid_id")
    write_finding "Application passwords endpoint confirms user ID oracle" \
      "Different error for invalid user (rest_user_invalid_id) vs unauthorized (rest_user_cannot_view)" "MEDIUM"
    ;;
  "data")
    write_finding "Application passwords endpoint returned DATA without auth" \
      "CRITICAL: Application passwords are exposed to unauthenticated users" "CRITICAL"
    ;;
esac

#==============================================================================
# 11. CORS Test
#==============================================================================
print_banner "10. CORS Configuration Test"

echo -e "  ${CYAN}[+] Testing CORS headers...${NC}"

# Baseline
CORS_BASELINE=$(curl -sI --max-time 10 "${TARGET}/wp-json/wp/v2/posts" 2>&1 | grep -i "access-control")
echo "$CORS_BASELINE" > "${OUTPUT_DIR}/cors-baseline.txt"

# Evil origin
CORS_EVIL=$(curl -s -H "Origin: https://evil.com" --max-time 10 "${TARGET}/wp-json/wp/v2/posts" 2>&1 | grep -i "access-control")
echo "$CORS_EVIL" > "${OUTPUT_DIR}/cors-evil.txt"

# Null origin
CORS_NULL=$(curl -s -H "Origin: null" --max-time 10 "${TARGET}/wp-json/wp/v2/posts" 2>&1 | grep -i "access-control")
echo "$CORS_NULL" > "${OUTPUT_DIR}/cors-null.txt"

# With credentials
CORS_CRED=$(curl -sI -H "Origin: https://evil.com" -H "Cookie: test=1" --max-time 10 "${TARGET}/wp-json/wp/v2/posts" 2>&1 | grep -i "access-control")
echo "$CORS_CRED" > "${OUTPUT_DIR}/cors-cred.txt)

if echo "$CORS_BASELINE" | grep -qi "access-control-allow-origin"; then
  ALLOW_ORIGIN=$(echo "$CORS_BASELINE" | grep -i "access-control-allow-origin" | head -1)
  ALLOW_CREDENTIALS=$(echo "$CORS_BASELINE" | grep -i "access-control-allow-credentials" | head -1)
  
  if echo "$ALLOW_ORIGIN" | grep -q "[*]"; then
    write_finding "Wildcard CORS: Access-Control-Allow-Origin: *" \
      "Any website can read REST API responses via JavaScript. Combined with credentials cookie, this is critical." "MEDIUM"
  elif echo "$ALLOW_CREDENTIALS" | grep -qi "true"; then
    write_finding "CORS with credentials allowed" \
      "${ALLOW_ORIGIN} with Access-Control-Allow-Credentials: true" "MEDIUM"
  fi
fi

# Test reflective CORS
if echo "$CORS_EVIL" | grep -qi "evil.com"; then
  write_finding "Reflective CORS detected, Origin header is echoed back" \
    "Server reflects Access-Control-Allow-Origin: https://evil.com. If credentials are also allowed, this is exploitable." "CRITICAL"
fi

if echo "$CORS_NULL" | grep -qi "null"; then
  write_finding "Null Origin accepted in CORS" \
    "Origin: null is allowed. Sandboxed iframes can make cross-origin requests." "HIGH"
fi

#==============================================================================
# 12. REST API Disabled Check
#==============================================================================
print_banner "11. REST API Disabled Check (?rest_route= bypass)"

echo -e "  ${CYAN}[+] Testing rest_route bypass...${NC}"

REST_ROUTE=$(curl -s --max-time 10 "${TARGET}/?rest_route=/wp/v2/posts&per_page=1" 2>&1)
echo "$REST_ROUTE" > "${OUTPUT_DIR}/rest-route-bypass.json"

if echo "$REST_ROUTE" | jq '.' > /dev/null 2>&1; then
  write_finding "REST API accessible via ?rest_route= parameter" \
    "Even if /wp-json/ is blocked, the API remains accessible via query parameter. This bypass is frequently overlooked." "HIGH"
else
  write_finding "?rest_route= bypass not working (returns HTML)" \
    "REST API appears disabled or the bypass has been mitigated" "INFO"
fi

# Check JSON content negotiation bypass
ACCEPT_JSON=$(curl -s -H "Accept: application/json" --max-time 10 "${TARGET}/?rest_route=/wp/v2/users" 2>&1)
if echo "$ACCEPT_JSON" | jq '.' > /dev/null 2>&1; then
  write_finding "REST API accessible via Accept: application/json + ?rest_route=" \
    "Content-negotiation bypass works for user enumeration" "HIGH"
fi

#==============================================================================
# 13. JSONP Callback XSS
#==============================================================================
print_banner "12. JSONP Callback XSS"

echo -e "  ${CYAN}[+] Testing JSONP callbacks...${NC}"

JSONP_TEST=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/posts?_jsonp=testCallback" 2>&1)
echo "$JSONP_TEST" > "${OUTPUT_DIR}/jsonp-test.txt"

if echo "$JSONP_TEST" | grep -q "^testCallback("; then
  write_finding "JSONP callback reflection confirmed, XSS vector" \
    "The _jsonp parameter value is reflected in the response. If unsanitized, this allows XSS: try _jsonp=<script>alert(1)</script>" "CRITICAL"
elif echo "$JSONP_TEST" | grep -q "^/\\*\\*/"; then
  write_finding "JSONP with santized prefix (/**/), partial protection" \
    "Response is wrapped but with an opaque prefix. Limited XSS protection." "LOW"
elif echo "$JSONP_TEST" | grep -q "testCallback"; then
  write_finding "JSONP callback parameter recognized but sanitized" \
    "Parameter name changed or invalid characters stripped" "LOW"
else
  write_finding "JSONP callback not supported" \
    "The _jsonp parameter is not processed, safe" "INFO"
fi

# Test other callback names
for param in "_jsonp" "callback" "jsonp" "jsoncallback" "fn" "cb" "format"; do
  CB_TEST=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/posts?${param}=xssTest" 2>&1)
  if echo "$CB_TEST" | grep -q "^xssTest(" 2>/dev/null; then
    write_finding "JSONP callback via '${param}' parameter" \
      "Parameter '${param}' reflects callback name, potential XSS vector" "HIGH"
  fi
done

#==============================================================================
# 14. OEmbed SSRF
#==============================================================================
print_banner "13. OEmbed SSRF Abuse"

echo -e "  ${CYAN}[+] Testing oEmbed endpoint...${NC}"

OEMBED_TEST=$(curl -s --max-time 10 "${TARGET}/wp-json/oembed/1.0/embed?url=${TARGET}/hello-world/" 2>&1)
echo "$OEMBED_TEST" > "${OUTPUT_DIR}/oembed-test.json"
OEMBED_CODE=$(echo "$OEMBED_TEST" | jq -r '.code // "data"' 2>/dev/null)

if [ "$OEMBED_CODE" = "data" ]; then
  write_finding "OEmbed endpoint is accessible" \
    "Endpoint at /oembed/1.0/embed is active and returns data" "INFO"
  
  # Test SSRF on internal IPs
  for internal_url in \
    "http://127.0.0.1:80/" \
    "http://127.0.0.1:3306/" \
    "http://localhost/wp-admin/" \
    "http://169.254.169.254/latest/meta-data/"; do
    
    SSRF_TEST=$(curl -s --max-time 5 "${TARGET}/wp-json/oembed/1.0/embed?url=$(echo $internal_url | jq -sRr @uri)" 2>&1)
    SSRF_CODE=$(echo "$SSRF_TEST" | jq -r '.code // "data"' 2>/dev/null)
    
    if [ "$SSRF_CODE" != "oembed_invalid_url" ]; then
      write_finding "OEmbed SSRF potential, URL accepted: ${internal_url}" \
        "The URL '${internal_url}' did not return oembed_invalid_url. Check response body." "HIGH"
    fi
  done
  
  # Proxy endpoint
  PROXY_TEST=$(curl -s --max-time 10 "${TARGET}/wp-json/oembed/1.0/proxy?url=${TARGET}/hello-world/" 2>&1)
  echo "$PROXY_TEST" > "${OUTPUT_DIR}/oembed-proxy.json"
  PROXY_CODE=$(echo "$PROXY_TEST" | jq -r '.code // "data"' 2>/dev/null)
  if [ "$PROXY_CODE" = "data" ]; then
    write_finding "OEmbed proxy endpoint accessible" \
      "The /oembed/1.0/proxy endpoint is also active, alternative SSRF vector" "MEDIUM"
  fi
fi

#==============================================================================
# 15. Search Endpoint
#==============================================================================
print_banner "14. Search Endpoint Data Leakage"

echo -e "  ${CYAN}[+] Testing search endpoint...${NC}"

SEARCH_TEST=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/search?search=admin&per_page=10" 2>&1)
echo "$SEARCH_TEST" > "${OUTPUT_DIR}/search-test.json"
SEARCH_CODE=$(echo "$SEARCH_TEST" | jq -r '.code // "data"' 2>/dev/null)

if [ "$SEARCH_CODE" = "data" ]; then
  SEARCH_COUNT=$(echo "$SEARCH_TEST" | jq '. | length' 2>/dev/null || echo "0")
  write_finding "Search endpoint accessible (${SEARCH_COUNT} results for 'admin')" \
    "The search endpoint aggregates results across post types" "MEDIUM"
  
  # Search for sensitive terms
  for term in "password" "confidential" "draft" "private" "secret" "internal"; do
    SENSITIVE=$(curl -s --max-time 10 "${TARGET}/wp-json/wp/v2/search?search=${term}&per_page=5" 2>&1)
    SENSITIVE_COUNT=$(echo "$SENSITIVE" | jq '. | length' 2>/dev/null || echo "0")
    
    if [ "$SENSITIVE_COUNT" -gt 0 ] 2>/dev/null; then
      write_finding "Search for '${term}' returned ${SENSITIVE_COUNT} results" \
        "Sensitive keyword found in searchable content" "MEDIUM"
    fi
  done
elif echo "$SEARCH_TEST" | grep -q "rest_no_route"; then
  write_finding "Search endpoint disabled (rest_no_route)" \
    "The REST API search endpoint is not registered" "INFO"
fi

#==============================================================================
# Summary
#==============================================================================
print_banner "Summary of Findings"

echo -e "${CYAN}[*] Compiling report...${NC}"

CRIT_COUNT=$(grep -c "CRITICAL" "$REPORT" 2>/dev/null || echo "0")
HIGH_COUNT=$(grep -c "\"HIGH\"" "$REPORT" 2>/dev/null || echo "0")
MED_COUNT=$(grep -c "\"MEDIUM\"" "$REPORT" 2>/dev/null || echo "0")
LOW_COUNT=$(grep -c "\"LOW\"" "$REPORT" 2>/dev/null || echo "0")

cat >> "$REPORT" << EOF

## Risk Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${CRIT_COUNT} |
| 🟠 High | ${HIGH_COUNT} |
| 🟡 Medium | ${MED_COUNT} |
| 🔵 Low | ${LOW_COUNT} |
| ⚪ Info | (not counted) |

## Remediation Priorities

### Immediate (Critical)
- Disable any endpoint allowing unauthenticated POST/PUT/DELETE
- Disable JSONP callbacks or sanitize callback parameter
- Fix reflective CORS configuration
- Block Application Passwords endpoint if not needed

### Short-term (High)
- Restrict user enumeration via filter or plugin
- Block sensitive search terms
- Disable oEmbed proxy endpoint if not needed
- Patch vulnerable plugins
- Remove legacy WP REST API v1 if present

### Medium-term
- Audit all custom plugin endpoints
- Restrict media endpoint access for private uploads
- Disable block/pattern directory endpoints
- Rate-limit REST API requests

### Ongoing
- Regular REST API footprint audits
- Monitor for new namespaces after plugin updates
- Test CORS configuration after CDN/WAF changes

EOF

#==============================================================================
# Output
#==============================================================================
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Audit Complete!${NC}"
echo -e "${GREEN}  Report: ${REPORT}${NC}"
echo -e "${GREEN}  Data:   ${OUTPUT_DIR}/${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Raw data saved to: ${OUTPUT_DIR}/"
echo "  Report saved to:   ${REPORT}"
```

---

## 17. Remediation Recommendations

### REST API Hardening Steps

| # | Recommendation | Effort | Impact |
|---|---------------|--------|--------|
| 1 | Disable specific endpoints via `rest_endpoints` filter in `functions.php` | Low | High |
| 2 | Install a security plugin with REST API controls (Wordfence, Sucuri, Solid Security) | Low | High |
| 3 | Require authentication for all REST API endpoints with custom code | Medium | High |
| 4 | Disable user endpoint: `remove_action('rest_api_init', 'wp_rest_user_endpoints')` | Low | High |
| 5 | Restrict oEmbed: disable proxy endpoint if not needed | Low | Medium |
| 6 | Remove legacy WP API v1 namespace | Low | Medium |
| 7 | Add CORS headers to only allow known origins via `rest_pre_serve_request` | Medium | Medium |
| 8 | Rate-limit REST API by IP (Wordfence, fail2ban, Nginx) | Medium | High |
| 9 | Monitor for new namespaces with automated scanning | Low | Medium |
| 10 | Disable XML-RPC alongside REST API if not needed | Low | Medium |

### .htaccess Snippet for Apache

```apache
# Block REST API user enumeration
RewriteCond %{QUERY_STRING} ^rest_route=/wp/v2/users(/|$) [OR]
RewriteCond %{REQUEST_URI} ^/wp-json/wp/v2/users
RewriteRule ^ - [F,L]

# Block oEmbed SSRF attempts
RewriteCond %{QUERY_STRING} rest_route=/oembed/ [OR]
RewriteCond %{REQUEST_URI} ^/wp-json/oembed/
RewriteRule ^ - [F,L]

# Block JSONP callbacks
RewriteCond %{QUERY_STRING} _jsonp= [OR]
RewriteCond %{QUERY_STRING} callback=
RewriteRule ^ - [F,L]
```

### Nginx Snippet

```nginx
# Block REST API user enumeration
location ~ ^/wp-json/wp/v2/users {
    deny all;
    return 403;
}

# Block rest_route bypass for sensitive endpoints
if ($arg_rest_route ~ "^/wp/v2/users") {
    return 403;
}

# Block oEmbed SSRF abuse
location ~ ^/wp-json/oembed/ {
    deny all;
    return 403;
}
```

### WordPress functions.php Snippets

```php
// 1. Require authentication for all REST API requests
add_filter('rest_authentication_errors', function($result) {
    if (!is_user_logged_in()) {
        return new WP_Error(
            'rest_not_logged_in',
            'You must be logged in to access the REST API.',
            ['status' => 401]
        );
    }
    return $result;
});

// 2. Disable user endpoint entirely
add_action('rest_api_init', function() {
    remove_action('rest_api_init', 'wp_rest_user_endpoints');
}, 5);

// 3. Remove specific namespaces
add_filter('rest_endpoints', function($endpoints) {
    // Remove users endpoint
    unset($endpoints['/wp/v2/users']);
    unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    // Remove oEmbed proxy
    unset($endpoints['/oembed/1.0/proxy']);
    return $endpoints;
});

// 4. Disable Application Passwords
add_filter('wp_is_application_passwords_available', '__return_false');
```

---

## References

- [WordPress REST API Handbook](https://developer.wordpress.org/rest-api/)
- [WP REST API User Enumeration (WPScan)](https://wpscan.com/vulnerability/8736)
- [OEmbed SSRF in WordPress Core](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29447)
- [Application Passwords Feature](https://make.wordpress.org/core/2020/11/05/application-passwords-integration-guide/)
- [CORS Misconfiguration in REST API](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

> **Document Version:** 1.0  
> **Audit Methodology:** Remote, unauthenticated, black-box  
> **Last Updated:** 2026-07-16
