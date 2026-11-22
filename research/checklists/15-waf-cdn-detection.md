# WAF / CDN Detection Checklist, WordPress (Remote, No Login)

> **Purpose:** Identify the presence and type of Web Application Firewall (WAF) and/or Content Delivery Network (CDN) protecting a target WordPress site *before* launching scans or exploitation attempts.
> **Scope:** Remote reconnaissance only, no admin credentials, no server shell, no plugin activation.
> **Audience:** Professional WordPress security auditors and penetration testers.

---

## Table of Contents

1. [Cloudflare](#1-cloudflare)
2. [Sucuri](#2-sucuri)
3. [StackPath / Highwinds](#3-stackpath--highwinds)
4. [Fastly](#4-fastly)
5. [Akamai](#5-akamai)
6. [KeyCDN](#6-keycdn)
7. [ModSecurity](#7-modsecurity)
8. [Wordfence Firewall](#8-wordfence-firewall)
9. [Generic WAF Detection](#9-generic-waf-detection)
10. [Rate Limiting Detection](#10-rate-limiting-detection)
11. [CDN Geographic Detection](#11-cdn-geographic-detection)
12. [Bash Fingerprinting Script](#12-bash-fingerprinting-script)

---

## 1. Cloudflare

Cloudflare is the most widely deployed CDN + WAF. It proxies traffic through its global edge network and can layer challenge pages, JS challenges, and CAPTCHA.

### Detection via Response Headers

```bash
# Standard header check
curl -sI "https://target.com/" | grep -iE "^(cf-ray|server:|cf-|x-frame-options)"

# Show all response headers
curl -sI -L "https://target.com/"
```

**Headers to look for:**

| Header | Expected Value | Confidence |
|--------|---------------|-----------|
| `cf-ray` | `xxxxxxxxxxxxxx-XXX` (e.g., `7a1b2c3d4e5f6-YYZ`) | **Definitive** |
| `server` | `cloudflare` | **Strong** |
| `cf-cache-status` | `HIT` / `MISS` / `DYNAMIC` / `EXPIRED` | **Definitive** |
| `cf-request-id` | Hex string | **Definitive** |
| `cf-connecting-ip` | Client IP | **Definitive** (when present) |
| `cf-ray` | Ray ID tracing request path | **Definitive** |

### Detection via HTTP/2 Alt-Svc

Cloudflare advertises HTTP/3 via `alt-svc`:

```bash
curl -sI --http2 "https://target.com/" | grep -i "alt-svc"
# Expected: alt-svc: h3=":443"; ma=86400
```

### Detection via Challenge Pages

```bash
# Force an HTTP request that may trigger a JS challenge
curl -v "https://target.com/wp-login.php" 2>&1 | head -50

# Check for Cloudflare challenge (response code 503, body contains 'cf-browser-verification')
curl -s "https://target.com/?" | grep -iE "cf-browser-verification|challenge-platform|cf-challenge"
```

**Pattern:** Cloudflare challenge pages contain:
- Response code: `503 Service Unavailable`
- HTML comments: `<!--[if IE]><![endif]-->`
- `window._cf_chl_opt` JavaScript object
- `cf-browser-verification` in inline script
- `challenge-platform` in script paths

### Detection via Error Codes

```bash
# Trigger a 1020 error (access denied by Cloudflare WAF rule)
curl -v "https://target.com/wp-admin/" 2>&1 | grep -iE "1020|1003|cloudflare"
```

| Error Code | Meaning |
|-----------|---------|
| **1020** | Access denied, WAF custom rule blocked the request |
| **1003** | Access denied, direct IP access (not allowed) |
| **1006** | Access denied, ASN/origin blocked |
| **1015** | Rate limited at Cloudflare edge |
| **1025** | JS challenge failed |

### Detection via DNS

```bash
# Cloudflare proxy (orange cloud) exposes Cloudflare IP ranges
dig +short A target.com
# Check if resolved IP belongs to Cloudflare range
curl -s "https://raw.githubusercontent.com/cloudflare/python-cloudflare/master/cloudflare/iptypes.py" 2>/dev/null | grep -oP '[\d.]+/\d+' || echo "Offline; check manually at https://www.cloudflare.com/ips/"
```

### WordPress-Specific Detection

```bash
# Cloudflare may inject cf-cache-status on wp-content assets
curl -sI "https://target.com/wp-content/themes/twentytwentyfour/style.css" | grep -i "^cf-"
```

---

## 2. Sucuri

Sucuri is a popular WordPress-specific WAF. It sits between the visitor and the origin server, filtering malicious traffic. It is also used as a CDN.

### Detection via Response Headers

```bash
# Primary detection
curl -sI "https://target.com/" | grep -iE "x-sucuri|server:"

# Full header inspection
curl -sI -L "https://target.com/"
```

**Headers to look for:**

| Header | Expected Value | Confidence |
|--------|---------------|-----------|
| `X-Sucuri-ID` | Numeric ID (e.g., `12345`) | **Definitive** |
| `X-Sucuri-Cache` | `HIT` / `MISS` / `BYPASS` / `REFRESH` | **Definitive** |
| `server` | `Sucuri/CloudProxy` or `sucuri.net` | **Strong** |
| `X-Sucuri-Block` | `true` (when blocked) | **Definitive** |

### Detection via Sucuri-Specific 403 Pages

```bash
# Trigger a potential block (brute-force login endpoint)
curl -s "https://target.com/wp-login.php" | grep -iE "sucuri|cloudproxy|blocked by sucuri"

# Send a request that may trigger Sucuri's WAF (malformed query string)
curl -s "https://target.com/?author=1&../../../etc/passwd" | head -50
```

**403 Body Patterns:**
- Page title: `Blocked, Sucuri WebSite Firewall`
- Body text: `Sucuri WebSite Firewall, CloudProxy, Access Denied`
- Sucuri support links: `https://support.sucuri.net`
- HTML comment: `<!-- Sucuri CloudProxy WAF -->`

```bash
# Check HTML comments for Sucuri reference
curl -s "https://target.com/" | grep -i "sucuri"
```

### Detection via Sucuri Block Page

```bash
# If blocked, the response body contains a specific Sucuri signature
curl -s "https://target.com/" 2>&1 | grep -oi "sucuri security\|sucuri.net\|CloudProxy\|Sucuri WAF"
```

### Detection via TTL and Caching Behavior

Sucuri's CDN sets specific cache TTL patterns:

```bash
curl -sI "https://target.com/" | grep -iE "cache-control|expires"
# Sucuri often sets Cache-Control: no-cache, no-store, must-revalidate
# or very specific expiry patterns
```

---

## 3. StackPath / Highwinds

StackPath acquired Highwinds (a CDN). Their CDN nodes serve cached content and may have firewall rules enabled.

### Detection via Response Headers

```bash
curl -sI "https://target.com/" | grep -iE "^(server:|x-cache:|x-powered-by|x-stackpath)"

# Full dump
curl -sI -L "https://target.com/"
```

**Headers to look for:**

| Header | Expected Value | Confidence |
|--------|---------------|-----------|
| `server` | `Highwinds` / `StackPath` / `StackPath CDN` | **Strong** |
| `X-Cache` | `HIT`, `MISS`, `TCP_HIT`, `TCP_MISS` | **Moderate** (shared with other CDNs) |
| `X-Powered-By` | `StackPath` | **Definitive** |
| `X-StackPath-*` | Various (custom headers) | **Definitive** |

### Detection via CNAME or Origin Response

```bash
# StackPath often sets specific Cache-Control and Vary headers
curl -sI "https://target.com/" | grep -iE "vary:|cache-control:|access-control-"
```

### Detection via Edge Server Identification

```bash
# StackPath may identify edge server in headers
curl -sI "https://target.com/" | grep -iE "x-served-by|x-cache-hits|x-edge-"
```

---

## 4. Fastly

Fastly is a high-performance CDN with WAF capabilities (acquired Signal Sciences). Used by many large WordPress sites.

### Detection via Response Headers

```bash
curl -sI "https://target.com/" | grep -iE "x-served-by|x-cache|fastly|surrogate-key"

# Full header inspection
curl -sI -L "https://target.com/"
```

**Headers to look for:**

| Header | Expected Value | Confidence |
|--------|---------------|-----------|
| `X-Served-By` | Cache node ID (e.g., `cache-yyz1234-YYZ`) | **Definitive** |
| `X-Cache` | `HIT`, `MISS`, `HIT, HIT`, `MISS, HIT` | **Strong** |
| `X-Cache-Hits` | Integer count | **Strong** |
| `X-Timer` | `S123456789.123456,VS0,VE123` (Fastly-specific) | **Definitive** |
| `Fastly-Debug-Digest` | Base64 encoded debug info | **Definitive** (when enabled) |
| `Surrogate-Key` | `key_name` | **Strong** (Fastly origin) |
| `Accept-Ranges` | `bytes` (Fastly standard) | **Weak** |

### Detection via Varnish Pattern

Fastly is built on a heavily modified Varnish. Some Varnish artifacts may leak:

```bash
curl -sI "https://target.com/" | grep -iE "via:|x-varnish"
# Fastly may strip x-varnish but can leak custom VCL headers
```

### Detection via Fastly Error Pages

```bash
# Fastly 503 error pages are distinctive
curl -v "https://target.com/" 2>&1 | grep -iE "fastly error|guru meditation"
```

Fastly error pages feature the "Guru Meditation" message (inherited from Varnish).

### Detection via Response Timing

```bash
# Fastly pop regions are visible in X-Served-By
curl -sI "https://target.com/" | grep -i "x-served-by"
# e.g., cache-yyz1234-YYZ → Toronto edge
# e.g., cache-lax1234-LAX → Los Angeles edge
```

---

## 5. Akamai

Akamai is a major enterprise CDN with powerful WAF capabilities (Kona Site Defender, Web Application Protector).

### Detection via Response Headers

```bash
curl -sI "https://target.com/" | grep -iE "server:|x-akamai|x-powered-by|x-check-cacheable"

# Full dump
curl -sI -L "https://target.com/"
```

**Headers to look for:**

| Header | Expected Value | Confidence |
|--------|---------------|-----------|
| `server` | `AkamaiGHost` / `AkamaiNetStorage` / `Akamaized` | **Definitive** |
| `X-Akamai-Transformed` | `9` / `9-xxx` (transformation ID) | **Definitive** |
| `X-Akamai-Request-ID` | UUID-like string | **Definitive** |
| `X-Check-Cacheable` | `YES` / `NO` | **Strong** |
| `X-True-Cache-Key` | Cache key path | **Strong** |
| `X-Akamai-Staging` | `EDGE` / `STAGING` | **Definitive** |
| `X-Content-Type-Options` | `nosniff` (Akamai default) | **Weak** |

### Detection via Error Pages

```bash
# Akamai 403 error pages (Kona WAF block)
curl -s "https://target.com/?../../etc/passwd" | grep -iE "akamai|reference.*#[0-9]{8,}|kona"

# Akamai 404 on edge may look different from origin 404
curl -sI "https://target.com/nonexistent-akamai-test" | grep -i "server:"
```

**403 Body Patterns:**
- `This site is protected by an Akamai WAF`
- `Reference #[0-9]{8,}` (8+ digit reference number)
- `AkamaiGHost` in server response
- Contact akamai support links

### Detection via Edge Server Hostnames

```bash
# Akamai edge servers have identifiable naming
curl -sI "https://target.com/" | grep -iE "via:|x-forwarded-by|x-akamai-"
```

### Detection via DNS

```bash
# Akamai CDN uses *.akamaiedge.net or *.akamaihd.net CNAMEs
dig +short CNAME target.com
# Or: dig +short A target.com | head -5
# Look for akamai patterns in reverse DNS
for ip in $(dig +short A target.com); do host "$ip"; done | grep -i "akamai"
```

---

## 6. KeyCDN

KeyCDN is a performance-focused CDN with edge caching but limited WAF capabilities.

### Detection via Response Headers

```bash
curl -sI "https://target.com/" | grep -iE "server:|x-cache-status|x-edge-location|keycdn"

# Full dump
curl -sI -L "https://target.com/"
```

**Headers to look for:**

| Header | Expected Value | Confidence |
|--------|---------------|-----------|
| `server` | `keycdn-engine` | **Definitive** |
| `X-Cache-Status` | `HIT` / `MISS` / `BYPASS` / `STALE` / `DYNAMIC` | **Strong** |
| `X-Edge-Location` | Edge node location ID | **Strong** |
| `X-Served-By` | KeyCDN node identifier | **Moderate** |
| `X-Cache` | Sometimes present with HIT/MISS | **Weak** |

### Detection via TTL Headers

```bash
curl -sI "https://target.com/" | grep -iE "cache-control|expires|surrogate-control"
# KeyCDN respects origin Cache-Control headers
```

### Detection via KeyCDN Zone

```bash
# KeyCDN sometimes leaks the zone name
curl -sI "https://target.com/" | grep -iE "x-zone|x-pullzone|x-keycdn"
```

---

## 7. ModSecurity

ModSecurity (mod_security) is an open-source WAF that runs as an Apache/Nginx module or reverse proxy. It can be used standalone or via vendors like OWASP CRS.

### Detection via HTTP Status Codes

```bash
# Test for 406 Not Acceptable (ModSecurity default for invalid accept headers)
curl -sI -H "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8, invalid-mime-type" "https://target.com/" | head -20

# Test for 501 Not Implemented (ModSecurity blocking via method restriction)
curl -sI -X TRACE "https://target.com/" | head -20
curl -sI -X TRACK "https://target.com/" | head -20
```

### Detection via Response Headers

```bash
curl -sI "https://target.com/" | grep -iE "^sec-|x-mod-|mod_security"
```

**Headers to look for:**

| Header | Expected Value | Confidence |
|--------|---------------|-----------|
| `Sec-ModSecurity` | `enabled` | **Definitive** |
| `X-Mod-Security` | various | **Definitive** |
| `server` | `Apache` (with mod_security loaded) | **Weak** |
| `X-Powered-By` | May reveal mod_security version | **Moderate** |

### Detection via Error Page Signatures

```bash
# Trigger SQLi rule (OWASP CRS)
curl -s "https://target.com/?id=1'+OR+'1'%3D'1" | grep -iE "mod_security|not acceptable|rule|owasp|web application firewall|blocked by"

# Trigger XSS rule
curl -s "https://target.com/?q=<script>alert(1)</script>" | grep -iE "mod_security|not acceptable"
```

**403/406 Body Patterns:**
- `406 Not Acceptable` response with no body (Minimal ModSecurity config)
- `ModSecurity: Access denied with code 406` in response body
- `This error was generated by ModSecurity` in error page
- `OWASP ModSecurity Core Rule Set` in response (if CRS is deployed)
- Reference to rule ID: `[id "942100"]` or similar
- `Request Rejected` page with specific formatting

### Detection via Specific CRS Rule Triggering

```bash
# Test known ModSecurity CRS rules
# Protocol attack (920320, missing accept header)
curl -sI -H "Accept: " "https://target.com/" 2>&1 | grep -iE "406|501|403"

# Method restriction
curl -sI -X PUT "https://target.com/" | head -20
```

### Detection via Response Body

```bash
curl -s "https://target.com/?a=b AND 1=1" -D - 2>&1 | head -30
# Look for "ModSecurity" or "OWASP_CRS" text anywhere in response
```

---

## 8. Wordfence Firewall

Wordfence is a WordPress plugin firewall (not a network-level WAF). It runs inside WordPress itself, but detecting it remotely is possible.

### Detection via 403 Block Page

```bash
# Trigger Wordfence rate limiter and block
for i in $(seq 1 10); do curl -s -o /dev/null -w "%{http_code} " "https://target.com/wp-login.php?wpe-login=admin"; done

# Check for Wordfence 403 page content
curl -s "https://target.com/wp-login.php" | grep -iE "wordfence|blocked by wordfence|generated by wordfence|wfBlocked"
```

### Detection via Wordfence Cookie

```bash
# Wordfence sets a wfvt_ cookie (Wordfence visitor token)
curl -sIc "https://target.com/" | grep -i "wfvt_"
```

**Cookie Pattern:**
- `wfvt_<32_hex_chars>`, Wordfence visitor tracking cookie
- `wordfence_verifiedHuman`, Present after passing CAPTCHA

### Detection via Wordfence 403 Page Specifics

```bash
curl -s "https://target.com/?author=1" 2>&1 | grep -oiE "wordfence|blocked|firewall"
```

**403 Page Fingerprints:**
- Body contains: `"Blocked by Wordfence"`
- Body contains: `"Generated by Wordfence"`
- Background image is a shield logo (base64 encoded)
- Link to Wordfence documentation: `https://www.wordfence.com/`
- HTTP response code: `403 Forbidden`

### Detection via Wordfence Learning Mode

```bash
# During learning mode, Wordfence may inject comments in HTML
curl -s "https://target.com/" | grep -iE "wordfence|wfwaf"
```

### Detection via PHP Headers

```bash
# Wordfence may reveal itself via X-Powered-By or custom headers
curl -sI "https://target.com/" | grep -iE "x-powered-by|wordfence|x-firewall"
```

---

## 9. Generic WAF Detection

These methods identify the *presence* of a WAF without naming the specific product. Use when the above vendor-specific tests are inconclusive.

### Detection via 403 Forbidden Responses

```bash
# Baseline, normal request
curl -sI "https://target.com/" | head -20

# Trigger WAF, SQL injection
curl -sI "https://target.com/?id=1'+UNION+SELECT+1,2,3--" | head -20

# Trigger WAF, XSS
curl -sI "https://target.com/?q=<script>alert(1)</script>" | head -20

# Trigger WAF, Path traversal
curl -sI "https://target.com/?file=../../../etc/passwd" | head -20

# Trigger WAF, Command injection
curl -sI "https://target.com/?cmd=cat+/etc/passwd" | head -20
```

**Pattern:** If baseline returns `200` and any malicious request returns `403`, `406`, or `503` → WAF present.

### Detection via 406 Not Acceptable

```bash
# WAF rejecting based on Accept headers
curl -sI -H "Accept: text/plain" "https://target.com/wp-login.php" | head -20
```

### Detection via Challenge Pages

```bash
# JavaScript challenge detection
curl -s "https://target.com/" | head -50
```

**JS Challenge Patterns:**
- Inline JavaScript with `document.cookie` manipulation
- `window.location` redirect in JS
- `<noscript>` tag with warning
- `Refresh` meta tag redirect
- Challenge JavaScript that computes a value (e.g., `document.cookie`)

### Detection via CAPTCHA

```bash
curl -s "https://target.com/wp-login.php" | grep -iE "recaptcha|g-recaptcha|hcaptcha|turnstile|cloudflare"
```

**CAPTCHA Indicators:**
- `g-recaptcha` div or iframe (Google reCAPTCHA)
- `h-captcha` (hCaptcha)
- `cf-turnstile` (Cloudflare Turnstile)
- CAPTCHA is triggered by failed login attempts or suspicious behavior

### Detection via Cookie Challenge

```bash
# A WAF may set a challenge cookie on first visit
curl -v "https://target.com/" 2>&1 | grep -iE "set-cookie.*(challenge|verify|test|check)"
```

**Cookie Challenge Patterns:**
- First visit returns `Set-Cookie` with a verification token
- Subsequent request must include that cookie
- Without the cookie, WAF returns 403 or redirects

### Detection via Response Size Differences

```bash
# Compare response sizes with and without malicious payloads
baseline=$(curl -s "https://target.com/" | wc -c)
blocked=$(curl -s "https://target.com/?id=1'OR'1'='1" | wc -c)
echo "Baseline: $baseline | Blocked: $blocked"
# Large difference may indicate WAF block page
```

### Detection via WAF Inconsistency

```bash
# Try the same request with different HTTP versions
curl -sI --http1.0 "https://target.com/?id=1'OR'1'='1" | head -10
curl -sI --http1.1 "https://target.com/?id=1'OR'1'='1" | head -10
curl -sI --http2 "https://target.com/?id=1'OR'1'='1" | head -10
# Different behaviors across HTTP versions may indicate WAF rules
```

---

## 10. Rate Limiting Detection

Rate limiting is often the first line of defense. Identifying the rate limit threshold helps plan scan cadence.

### Detection via 429 Too Many Requests

```bash
# Aggressive request pattern
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/")
  echo "Request $i: $code"
done
```

### Detection via Retry-After Header

```bash
curl -sD - "https://target.com/" 2>&1 | grep -iE "retry-after|429"
```

**Headers to look for:**

| Header | Expected Value | Confidence |
|--------|---------------|-----------|
| `Retry-After` | Seconds or HTTP-date | **Definitive** |
| `X-RateLimit-*` | Various (limits/remaining/reset) | **Definitive** |
| `X-Rate-Limit` | Various | **Strong** |
| `RateLimit-*` | Various (draft standard) | **Strong** |

### Detection via WordPress-Specific Limits

```bash
# WordPress XML-RPC is often rate-limited
for i in $(seq 1 10); do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/xmlrpc.php" \
    -H "Content-Type: text/xml" -d "<methodCall><methodName>system.listMethods</methodName></methodCall>")
  echo "Request $i: $code"
done
```

### Detection via WordPress Login Rate Limits

```bash
# wp-login.php is typically rate-limited
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/wp-login.php")
  echo "Request $i: $code"
done
```

**Rate Limit Fingerprints by WAF:**

| WAF | Rate Limit Behavior |
|-----|-------------------|
| **Cloudflare** | 1015 error code, JS challenge, or 429 with `Retry-After` |
| **Sucuri** | 403 with Sucuri block page after threshold |
| **Wordfence** | 403 with "Blocked by Wordfence" message |
| **Generic** | 429 with or without Retry-After; gradual slowdown (503) |

---

## 11. CDN Geographic Detection

Determining if a CDN serves different content based on visitor location helps identify the CDN provider and its regional edge nodes.

### Detection via Varying Edge Server

```bash
# Check from different regions using curl --resolve or multiple VPN endpoints
# North America
curl -sI "https://target.com/" | grep -iE "x-served-by|x-cache|server:|via:"

# If you have access to proxies in different regions:
# Europe
curl -sI -x "http://eu-proxy:port" "https://target.com/" | grep -iE "x-served-by|x-cache|server:"
```

### Detection via Response Time Differences

```bash
# Measure response time from current location
curl -s -o /dev/null -w "Total time: %{time_total}s\nConnect: %{time_connect}s\nTTFB: %{time_starttransfer}s\n" "https://target.com/"
```

### Detection via Vary Header

```bash
# CDNs use Vary to serve different content
curl -sI "https://target.com/" | grep -i "vary:"
```

**Vary header patterns by CDN:**

| CDN | Typical Vary Header |
|-----|-------------------|
| **Cloudflare** | `Accept-Encoding` (minimal) |
| **Fastly** | May include `Vary: Accept-Encoding, X-Forwarded-Proto` |
| **Akamai** | Complex Vary with cookie/device-type |
| **KeyCDN** | Respects origin Vary |

### Detection via Multi-Region Cache Status

```bash
# Run twice and compare cache status
curl -sI "https://target.com/" | grep -i "x-cache"
# First request may be MISS, second HIT → CDN caches
curl -sI "https://target.com/" | grep -i "x-cache"
```

### Detection via CDN Geo-Blocking

```bash
# Test with different Accept-Language to infer geo-behavior
curl -sI -H "Accept-Language: fr-CH, fr;q=0.9, en;q=0.8" "https://target.com/" | head -15
curl -sI -H "Accept-Language: zh-CN, zh;q=0.9" "https://target.com/" | head -15

# Some CDNs redirect based on geo (e.g., Cloudflare Geolocation)
curl -sI "https://target.com/" | grep -iE "location:|content-language:"
```

### Detection via CDN IP Range

```bash
# Check if resolved IP belongs to known CDN ranges
dig +short A target.com

# Known CDN ASNs:
# Cloudflare: AS13335
# Fastly: AS54113
# Akamai: AS16625, AS20940, AS21342
# Sucuri: AS30148, AS39705
# KeyCDN: AS42708
# StackPath: AS33438
```

---

## 12. Bash Fingerprinting Script

Below is a self-contained script that performs all the above checks and outputs a structured fingerprint report.

Save as `waf-cdn-fingerprint.sh` and run as:
```bash
chmod +x waf-cdn-fingerprint.sh
./waf-cdn-fingerprint.sh https://target.com
```

```bash
#!/usr/bin/env bash
#===============================================================================
# WAF / CDN Fingerprinting Tool, WordPress Remote Detection
# Usage: ./waf-cdn-fingerprint.sh <url>
# Example: ./waf-cdn-fingerprint.sh https://example.com
#===============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

TARGET="${1:-}"
[ -z "$TARGET" ] && echo -e "${RED}Usage: $0 <url>${NC}" && exit 1

# Strip trailing slash
TARGET="${TARGET%/}"

HEADERS_FILE=$(mktemp)
BODY_FILE=$(mktemp)
trap 'rm -f "$HEADERS_FILE" "$BODY_FILE"' EXIT

echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  WAF / CDN Fingerprinting Tool${NC}"
echo -e "${CYAN}  Target: $TARGET${NC}"
echo -e "${CYAN}  Date:   $(date -u '+%Y-%m-%d %H:%M:%S UTC')${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"

#-------------------------------------------------------------------------
# Phase 1: Baseline headers
#-------------------------------------------------------------------------
echo -e "\n${GREEN}[*] Phase 1: Baseline Headers${NC}"
curl -sI -L "$TARGET" > "$HEADERS_FILE" 2>/dev/null || true

echo -e "${YELLOW}  → Response headers:${NC}"
while IFS= read -r line; do
  [ -n "$line" ] && echo "    $line"
done < "$HEADERS_FILE"

#-------------------------------------------------------------------------
# Phase 2: Detect individual WAF / CDN fingerprints
#-------------------------------------------------------------------------
echo -e "\n${GREEN}[*] Phase 2: Vendor-Specific Detection${NC}"

DETECTED=()

# -- Cloudflare --
if grep -qiE "^cf-ray:|^server: cloudflare|^cf-cache-status:" "$HEADERS_FILE" 2>/dev/null; then
  echo -e "  ${RED}✓ Cloudflare${NC}, detected via headers"
  DETECTED+=("Cloudflare")
elif curl -s "$TARGET" 2>/dev/null | grep -qiE "cf-browser-verification|challenge-platform|cf-challenge" 2>/dev/null; then
  echo -e "  ${RED}✓ Cloudflare${NC}, detected via challenge page"
  DETECTED+=("Cloudflare (challenge page)")
elif curl -sI --http2 "$TARGET" 2>/dev/null | grep -qiE "alt-svc.*h3=" 2>/dev/null; then
  echo -e "  ${RED}✓ Cloudflare${NC}, detected via HTTP/3 alt-svc"
  DETECTED+=("Cloudflare (likely)")
else
  echo -e "  ${YELLOW}✗ Cloudflare${NC}, not detected"
fi

# -- Sucuri --
if grep -qiE "^x-sucuri-id:|^x-sucuri-cache:|^server: sucuri|^x-sucuri-block:" "$HEADERS_FILE" 2>/dev/null; then
  echo -e "  ${RED}✓ Sucuri${NC}, detected via headers"
  DETECTED+=("Sucuri")
elif curl -s "$TARGET" 2>/dev/null | grep -qiE "sucuri.*cloudproxy|blocked by sucuri|Sucuri WebSite Firewall" 2>/dev/null; then
  echo -e "  ${RED}✓ Sucuri${NC}, detected via block page"
  DETECTED+=("Sucuri (block page)")
else
  echo -e "  ${YELLOW}✗ Sucuri${NC}, not detected"
fi

# -- StackPath / Highwinds --
if grep -qiE "^server: highwinds|^server: stackpath|^x-stackpath" "$HEADERS_FILE" 2>/dev/null; then
  echo -e "  ${RED}✓ StackPath/Highwinds${NC}, detected via headers"
  DETECTED+=("StackPath/Highwinds")
else
  echo -e "  ${YELLOW}✗ StackPath/Highwinds${NC}, not detected"
fi

# -- Fastly --
if grep -qiE "^x-served-by:|^x-timer:|^surrogate-key:|^x-cache.*fastly" "$HEADERS_FILE" 2>/dev/null; then
  echo -e "  ${RED}✓ Fastly${NC}, detected via headers"
  DETECTED+=("Fastly")
elif curl -s "$TARGET" 2>/dev/null | grep -qiE "guru meditation|fastly error" 2>/dev/null; then
  echo -e "  ${RED}✓ Fastly${NC}, detected via error page"
  DETECTED+=("Fastly (error page)")
else
  echo -e "  ${YELLOW}✗ Fastly${NC}, not detected"
fi

# -- Akamai --
if grep -qiE "^server: akamai|^x-akamai-transformed:|^x-akamai-request-id:|^x-check-cacheable:" "$HEADERS_FILE" 2>/dev/null; then
  echo -e "  ${RED}✓ Akamai${NC}, detected via headers"
  DETECTED+=("Akamai")
elif curl -s "$TARGET/?../../../etc/passwd" 2>/dev/null | grep -qiE "akamai.*waf|reference.*#[0-9]{8,}" 2>/dev/null; then
  echo -e "  ${RED}✓ Akamai${NC}, detected via WAF block page"
  DETECTED+=("Akamai (WAF block)")
else
  echo -e "  ${YELLOW}✗ Akamai${NC}, not detected"
fi

# -- KeyCDN --
if grep -qiE "^server: keycdn-engine|^x-cache-status: (HIT|MISS)" "$HEADERS_FILE" 2>/dev/null; then
  echo -e "  ${RED}✓ KeyCDN${NC}, detected via headers"
  DETECTED+=("KeyCDN")
else
  echo -e "  ${YELLOW}✗ KeyCDN${NC}, not detected"
fi

# -- ModSecurity --
curl -sI -H "Accept: text/html, invalid-mime" "$TARGET" > "$HEADERS_FILE" 2>/dev/null || true
if grep -qiE "^sec-modsecurity:|^x-mod-security:|\"mod_security\"|406 Not Acceptable" "$HEADERS_FILE" 2>/dev/null; then
  echo -e "  ${RED}✓ ModSecurity${NC}, detected via headers"
  DETECTED+=("ModSecurity")
elif curl -s "$TARGET/?id=1'+OR+'1'%3D'1" 2>/dev/null | grep -qiE "mod_security|not acceptable|owasp.*core.*rule" 2>/dev/null; then
  echo -e "  ${RED}✓ ModSecurity${NC}, detected via block response"
  DETECTED+=("ModSecurity (block page)")
elif curl -sI -X TRACE "$TARGET" 2>/dev/null | grep -qi "501" 2>/dev/null; then
  echo -e "  ${RED}✓ ModSecurity${NC}, detected via TRACE 501"
  DETECTED+=("ModSecurity (method restriction)")
else
  echo -e "  ${YELLOW}✗ ModSecurity${NC}, not detected"
fi

# -- Wordfence --
if curl -sIc "$TARGET" 2>/dev/null | grep -qi "wfvt_" 2>/dev/null; then
  echo -e "  ${RED}✓ Wordfence${NC}, detected via wfvt_ cookie"
  DETECTED+=("Wordfence")
elif curl -s "$TARGET/wp-login.php" 2>/dev/null | grep -qiE "blocked by wordfence|generated by wordfence" 2>/dev/null; then
  echo -e "  ${RED}✓ Wordfence${NC}, detected via 403 block page"
  DETECTED+=("Wordfence (block page)")
else
  echo -e "  ${YELLOW}✗ Wordfence${NC}, not detected"
fi

#-------------------------------------------------------------------------
# Phase 3: Generic WAF indicators
#-------------------------------------------------------------------------
echo -e "\n${GREEN}[*] Phase 3: Generic WAF Indicators${NC}"

WAF_PRESENT=false

# Test malicious payloads
baseline_code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/" 2>/dev/null || echo "000")
sqli_code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/?id=1'+UNION+SELECT+1,2,3--" 2>/dev/null || echo "000")
xss_code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/?q=<script>alert(1)</script>" 2>/dev/null || echo "000")
pt_code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/?file=../../../etc/passwd" 2>/dev/null || echo "000")

echo -e "  Baseline HTTP code:  $baseline_code"
echo -e "  SQLi    HTTP code:  $sqli_code"
echo -e "  XSS     HTTP code:  $xss_code"
echo -e "  PathTr  HTTP code:  $pt_code"

if [ "$baseline_code" = "200" ] || [ "$baseline_code" = "301" ] || [ "$baseline_code" = "302" ]; then
  if [ "$sqli_code" = "403" ] || [ "$sqli_code" = "406" ] || [ "$sqli_code" = "503" ]; then
    echo -e "  ${RED}⚠ WAF detected${NC}, SQLi returned $sqli_code (baseline: $baseline_code)"
    WAF_PRESENT=true
  fi
  if [ "$xss_code" = "403" ] || [ "$xss_code" = "406" ] || [ "$xss_code" = "503" ]; then
    echo -e "  ${RED}⚠ WAF detected${NC}, XSS returned $xss_code"
    WAF_PRESENT=true
  fi
  if [ "$pt_code" = "403" ] || [ "$pt_code" = "406" ] || [ "$pt_code" = "503" ]; then
    echo -e "  ${RED}⚠ WAF detected${NC}, Path traversal returned $pt_code"
    WAF_PRESENT=true
  fi
fi

if ! $WAF_PRESENT; then
  # Check for challenge pages
  body=$(curl -s "$TARGET" 2>/dev/null || true)
  if echo "$body" | grep -qiE "document\.cookie|window\.location.*redirect|g-recaptcha|h-captcha|cf-turnstile" 2>/dev/null; then
    echo -e "  ${RED}⚠ WAF likely${NC}, challenge page or CAPTCHA detected"
    WAF_PRESENT=true
  fi
fi

if ! $WAF_PRESENT; then
  echo -e "  ${GREEN}✓ No generic WAF indicators found${NC}"
fi

#-------------------------------------------------------------------------
# Phase 4: Rate limiting check
#-------------------------------------------------------------------------
echo -e "\n${GREEN}[*] Phase 4: Rate Limiting Check${NC}"

RATE_LIMITED=false
for i in $(seq 1 15); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/" 2>/dev/null || echo "000")
  if [ "$code" = "429" ]; then
    echo -e "  ${RED}⚠ Rate limited at request $i (HTTP 429)${NC}"
    RATE_LIMITED=true
    break
  elif [ "$code" = "503" ]; then
    echo -e "  ${RED}⚠ Rate limited at request $i (HTTP 503)${NC}"
    RATE_LIMITED=true
    break
  fi
done

if ! $RATE_LIMITED; then
  echo -e "  ${GREEN}✓ No rate limiting detected (15 requests)${NC}"
fi

#-------------------------------------------------------------------------
# Phase 5: CDN geographic & cache check
#-------------------------------------------------------------------------
echo -e "\n${GREEN}[*] Phase 5: CDN Analysis${NC}"

# Check for cached static assets
static_code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/wp-content/themes/" 2>/dev/null || echo "000")
if [ "$static_code" != "000" ]; then
  echo -e "  ${YELLOW}  Static assets accessible (HTTP $static_code)${NC}"
fi

# Check cache status
cache_status=$(curl -sI "$TARGET/" 2>/dev/null | grep -iE "^x-cache:|^x-cache-status:|^cf-cache-status:" || true)
if [ -n "$cache_status" ]; then
  echo -e "  ${YELLOW}  Cache header:${NC} $cache_status"
fi

# Check Vary header
vary=$(curl -sI "$TARGET/" 2>/dev/null | grep -i "^vary:" || true)
if [ -n "$vary" ]; then
  echo -e "  ${YELLOW}  Vary header:${NC} $vary"
fi

#-------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------
echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FINGERPRINT SUMMARY${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"

if [ ${#DETECTED[@]} -eq 0 ]; then
  if $WAF_PRESENT; then
    echo -e "  ${YELLOW}→ Generic WAF detected but no specific vendor identified${NC}"
  else
    echo -e "  ${GREEN}→ No WAF or CDN detected${NC}"
    echo -e "  ${YELLOW}  Note: Origin-IP-level WAF or .htaccess rules may still exist${NC}"
  fi
else
  echo -e "  ${RED}Detected:${NC}"
  for d in "${DETECTED[@]}"; do
    echo -e "    ✓ $d"
  done
  if $WAF_PRESENT && [ ${#DETECTED[@]} -eq 0 ]; then
    echo -e "  ${YELLOW}  (plus generic WAF behavior observed)${NC}"
  fi
fi

echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Scan Complete, Use findings to adapt scan strategy${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
```

> **Usage Note:** Run against a *public* target you own or have explicit permission to test. Rate-limit checks and malicious payload tests may trigger blocks IP-wide.

---

## References

- Cloudflare IP ranges: https://www.cloudflare.com/ips-v4
- OWASP Core Rule Set: https://coreruleset.org/
- Wordfence documentation: https://www.wordfence.com/help/
- Sucuri documentation: https://docs.sucuri.net/
- Fastly VCL reference: https://docs.fastly.com/en/guides

---

*Last updated: 2026-07-16*
