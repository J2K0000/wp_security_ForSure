# Security Headers Audit Checklist, WordPress (Remote, No Login)

> **Audience:** Technical professionals (devs, sysadmins, security auditors) who may not be security specialists.
> **Scope:** Remote scanning only, no WordPress admin credentials required.
> **Method:** `curl` commands against the live site. No paid tools.
> **Format:** Each header is self-contained with what it does, how to check it, secure values, misconfigurations, and impact.
> **Severity:** 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low

---

## Quick Reference, One-Liner to Check All Headers

```bash
curl -sI "https://example.com" | grep -iE '(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection)' | sort
```

Replace `https://example.com` with the target WordPress site URL.  
This returns only the security-relevant headers. If a header is absent, it simply won't appear, absence is a finding.

For a more verbose output showing **all** response headers (useful to spot unknown/custom headers):

```bash
curl -sI "https://example.com" | head -30
```

> **⚠️ Important:** Always use `https://`, HTTP responses will never include `Strict-Transport-Security` and defeat the purpose of the audit.

---

## 1. 🔴 Strict-Transport-Security (HSTS)

### What It Does

HTTP Strict-Transport-Security tells browsers to **only** communicate with the server over HTTPS, never plain HTTP. It protects against:
- SSL-stripping attacks (MITM downgrading HTTPS → HTTP)
- Cookie hijacking on insecure connections
- Users manually typing `http://` or following old HTTP links

Once a browser receives this header, it "remembers" to use HTTPS for the domain for the duration of `max-age`.

### How to Check It

```bash
curl -sI "https://example.com" | grep -i strict-transport-security
```

### Secure Value

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

| Directive | Purpose | Recommended |
|-----------|---------|-------------|
| `max-age=31536000` | Duration (seconds) the browser should enforce HTTPS | ≥ 1 year (31,536,000 s) |
| `includeSubDomains` | Apply HSTS to all subdomains | Always add |
| `preload` | Opt into browser preload lists (Chrome, Firefox, Safari) | Include if submitting to HSTS preload list |

### Common Misconfigurations

| Issue | Example | Impact |
|-------|---------|--------|
| **Too-short max-age** | `max-age=300` | Browser forgets quickly; user can be downgraded after 5 minutes |
| **Missing `includeSubDomains`** | `max-age=31536000` | Subdomains (e.g., `wp-admin.example.com`, `cdn.example.com`) remain vulnerable |
| **No `preload` directive** | `max-age=31536000; includeSubDomains` | First-visit users are still exposed (the "first click" problem) |
| **Served over HTTP** | Header only sent on HTTPS response | Correct, this is intentional per spec, but an HTTP→HTTPS redirect must exist |
| **Mixed content on the same page** | HSTS present but page loads HTTP images/scripts | Browser may block mixed content; HSTS doesn't fix broken assets |

### Impact

| Scenario | Risk |
|----------|------|
| **Missing HSTS** | 🔴 **Critical**, Users can be downgraded to HTTP on every first visit or after cache expiry; cookie theft on open Wi-Fi |
| **Short max-age** | 🟠 **High**, Token theft window reopens every few minutes/hours |
| **Missing includeSubDomains** | 🟡 **Medium**, Subdomain takeover or MITM on neglected subdomains (common in WordPress multisite) |

---

## 2. 🔴 Content-Security-Policy (CSP)

### What It Does

CSP is the most powerful defense against **Cross-Site Scripting (XSS)**, **data injection**, and **clickjacking** attacks. It defines a whitelist of trusted sources from which the browser can load resources (scripts, styles, images, fonts, etc.).

For WordPress sites, CSP is especially critical because:
- WordPress core, themes, and plugins often have XSS vulnerabilities
- User-generated content (comments, uploads) is a common injection vector
- Third-party scripts (analytics, ads, CDNs) increase the attack surface

### How to Check It

```bash
curl -sI "https://example.com" | grep -i content-security-policy
```

CSP can also be delivered via a `<meta>` tag. To check for that:

```bash
curl -sL "https://example.com" | grep -oiE '<meta[^>]*http-equiv="content-security-policy"[^>]*>' | head -1
```

### Secure Value (WordPress Starter)

A reasonably secure starting point for a typical WordPress site:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-src 'self' https://www.youtube.com; object-src 'none'; base-uri 'self'; form-action 'self'
```

> **⚠️ `'unsafe-inline'`** is often required by WordPress themes and plugins (inline `<script>` tags, inline `style` attributes). Removing it will break many sites. A **nonce-based** or **hash-based** CSP is more secure but requires server-side integration.

### CSP Directive Reference

| Directive | Controls | Typical WordPress Sources | Notes |
|-----------|----------|--------------------------|-------|
| `default-src` | Fallback for all resource types | `'self'` | Acts as default when a specific directive is absent |
| `script-src` | JavaScript sources | `'self' 'unsafe-inline' https://*.googletagmanager.com https://*.google-analytics.com` | `'unsafe-inline'` is a compromise, nonce/hash is better |
| `style-src` | Stylesheet sources | `'self' 'unsafe-inline' https://fonts.googleapis.com` | WordPress admin uses inline styles heavily |
| `img-src` | Image sources | `'self' data: https:` | `https:` is permissive but practical for user uploads |
| `font-src` | Font sources | `'self' https://fonts.gstatic.com` | Google Fonts CDN |
| `connect-src` | XHR / fetch / WebSocket | `'self' https://*.google-analytics.com` | Analytics, REST API calls |
| `frame-src` | `<iframe>` sources | `'self' https://www.youtube.com` | Embeds (YouTube, Vimeo) |
| `frame-ancestors` | Who can embed this page in an iframe | `'self'` | Clickjacking protection (supersedes `X-Frame-Options`) |
| `object-src` | `<object>`, `<embed>`, `<applet>` | `'none'` | Flash/plugin-based attacks, always set to `'none'` |
| `base-uri` | `<base>` tag hijacking | `'self'` | Prevents attackers from changing the base URL for relative links |
| `form-action` | Where forms can submit | `'self'` | Prevents form-jacking |
| `upgrade-insecure-requests` | Upgrade HTTP to HTTPS | (present as directive name) | Automatically upgrades all HTTP requests on the page |
| `block-all-mixed-content` | Block mixed content | (present as directive name) | Stricter than default browser behavior |

### Common Misconfigurations

| Issue | Example | Impact |
|-------|---------|--------|
| **`'unsafe-inline'` + `'unsafe-eval'`** | `script-src 'self' 'unsafe-inline' 'unsafe-eval'` | Drastically reduces XSS protection, allows arbitrary inline scripts and `eval()` |
| **Wildcard `*`** | `script-src *` | Essentially disables CSP for scripts; any domain can serve JS |
| **Missing `object-src 'none'`** | Not specified (falls back to `default-src`) | Flash/plugin vectors remain open |
| **Too-permissive `frame-ancestors`** | `frame-ancestors *` | Clickjacking exposure |
| **Report-only mode misused** | `Content-Security-Policy-Report-Only:` instead of `Content-Security-Policy:` | Header is observed but NOT enforced, only reports violations |
| **No `base-uri` restriction** | Not specified | DOM clobbering attack via `<base>` tag injection |
| **CSP over HTTPS only but page serves mixed content** | CSP `upgrade-insecure-requests` missing | Mixed content warnings and blocked resources |
| **Blocking WordPress REST API** | `connect-src 'self'` without REST API endpoint | Blocks Gutenberg editor, admin AJAX calls, etc. |

### Impact

| Scenario | Risk |
|----------|------|
| **No CSP** | 🔴 **Critical**, No defense against XSS injection in plugins/themes/comments |
| **CSP with `'unsafe-inline'` only** | 🟠 **High**, Partial protection; inline XSS still possible |
| **Nonce-based CSP** | 🟢 **Low**, Strong XSS protection; inline scripts require a valid nonce |
| **Missing `object-src` / `base-uri`** | 🟡 **Medium**, Specific attack vectors (Flash, base tag hijack) remain open |
| **CSP-Report-Only instead of enforced** | 🟡 **Medium**, Violations are logged but NOT blocked; useful as a transition step |

---

## 3. 🟠 X-Frame-Options

### What It Does

Controls whether the page can be embedded in a `<frame>`, `<iframe>`, or `<object>`. Prevents **clickjacking** attacks where an attacker overlays a transparent iframe on a malicious page to trick users into clicking something they didn't intend.

### How to Check It

```bash
curl -sI "https://example.com" | grep -i x-frame-options
```

### Secure Value

```
X-Frame-Options: DENY
```

Or, if you need to allow framing from the same origin (e.g., WordPress admin loaded in an iframe for a page builder):

```
X-Frame-Options: SAMEORIGIN
```

### Common Misconfigurations

| Issue | Example | Impact |
|-------|---------|--------|
| **`ALLOW-FROM` (obsolete)** | `ALLOW-FROM https://partner.com` | Not supported by Chrome/Safari; use `frame-ancestors` in CSP instead |
| **Missing entirely** | *(no header)* | Page can be embedded by any site, clickjacking risk |
| **`SAMEORIGIN` when unnecessary** | `SAMEORIGIN` on a public-facing login page | Minimal risk, but `DENY` is stricter if no legitimate iframe use case |

### Impact

| Scenario | Risk |
|----------|------|
| **Missing** | 🟠 **High**, Clickjacking on login pages, admin panels, payment forms |
| **`DENY` or `SAMEORIGIN` present** | 🟢 **Low**, Protected |
| **`ALLOW-FROM` (legacy only)** | 🟡 **Medium**, Partial protection (Chrome/Safari ignore it) |

> **Note:** If CSP `frame-ancestors` is set, it takes precedence over `X-Frame-Options` in modern browsers. Including both is best for backward compatibility.

---

## 4. 🟠 X-Content-Type-Options

### What It Does

Prevents **MIME-type sniffing**, the browser trying to guess the content type of a response. Without it, a browser might interpret a user-uploaded file (e.g., `image.jpg` containing malicious JavaScript) as a script, allowing XSS. This header forces the browser to respect the declared `Content-Type`.

### How to Check It

```bash
curl -sI "https://example.com" | grep -i x-content-type-options
```

### Secure Value

```
X-Content-Type-Options: nosniff
```

### Common Misconfigurations

| Issue | Example | Impact |
|-------|---------|--------|
| **Missing entirely** | *(no header)* | Browser may MIME-sniff; user-uploaded files can be executed as scripts |
| **Incorrect value** | `X-Content-Type-Options: nosniff=true` | Invalid; header is ignored |
| **Only on HTML pages, not on assets** | Header present on `/` but missing on `/wp-content/uploads/file.pdf` | Uploaded files remain vulnerable if accessed directly |

### Impact

| Scenario | Risk |
|----------|------|
| **Missing** | 🟠 **High**, Especially critical for WordPress sites with user uploads (comments, media library) |
| **Present and correct** | 🟢 **Low**, Protected |

---

## 5. 🟡 Referrer-Policy

### What It Does

Controls how much referrer information is included in the `Referer` header when a user clicks a link or a page loads a resource. It governs what data is leaked to external sites about the originating URL (including query parameters, paths, and sensitive identifiers).

### How to Check It

```bash
curl -sI "https://example.com" | grep -i referrer-policy
```

### Secure Value

```
Referrer-Policy: strict-origin-when-cross-origin
```

This is the recommended default, it sends the full URL as referrer for same-origin requests, only the origin for cross-origin, and nothing when navigating from HTTPS→HTTP.

Other reasonable options depending on sensitivity:

| Policy | Behavior |
|--------|----------|
| `strict-origin-when-cross-origin` | ✅ **Recommended**, Balances privacy with utility |
| `same-origin` | Sends referrer only for same-origin requests |
| `no-referrer` | Never sends a referrer (strictest, but breaks analytics) |
| `no-referrer-when-downgrade` | Default browser behavior, sends referrer except HTTPS→HTTP |
| `strict-origin` | Sends only origin, always (no path/query), except HTTPS→HTTP |
| `origin-when-cross-origin` | Like `strict-origin-when-cross-origin` but sends origin on downgrade too |

### Common Misconfigurations

| Issue | Example | Impact |
|-------|---------|--------|
| **No policy set** | *(no header)* | Browser default (`no-referrer-when-downgrade`), full URL leaked on cross-origin |
| **`unsafe-url`** | `unsafe-url` | Leaks the **entire URL** (including query params, session IDs, passwords in URLs) to any external site |
| **`origin`** | `origin` | Only leaks origin, but on HTTPS→HTTP downgrades too, minor privacy leak |
| **Too strict for analytics** | `no-referrer` | Breaks referrer-based analytics, campaign tracking, and affiliate links |
| **Missing on admin pages** | Header on `/` but not on `/wp-admin/` | Sensitive admin URLs leaked when navigating to external links |

### Impact

| Scenario | Risk |
|----------|------|
| **Missing** | 🟡 **Medium**, Privacy leak; sensitive URL paths/prams exposed to external sites |
| **`unsafe-url`** | 🟠 **High**, Full URLs with query strings leaked (reset tokens, session IDs, payment params) |
| **`strict-origin-when-cross-origin`** | 🟢 **Low**, Protected (recommended) |
| **`no-referrer`** | 🟢 **Low**, Fully private, but analytics impacted |

---

## 6. 🟡 Permissions-Policy (formerly Feature-Policy)

### What It Does

Allows/denies browser features and APIs on a per-origin basis. This controls what the page (and its third-party scripts) can access: camera, microphone, geolocation, fullscreen, notifications, clipboard, etc. For a WordPress site, it limits what compromised plugins or injected scripts can do with browser APIs.

### How to Check It

```bash
curl -sI "https://example.com" | grep -i permissions-policy
```

> Older sites may use the legacy header name: `Feature-Policy`

### Secure Value

```
Permissions-Policy: geolocation=(), camera=(), microphone=(), midi=(), payment=(), sync-xhr=(), usb=()
```

Or the more comprehensive lockdown:

```
Permissions-Policy: accelerometer=(), ambient-light-sensor=(), autoplay=*, battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=*, fullscreen=*, gamepad=(), geolocation=(), gyroscope=(), keyboard-map=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=*, publickey-credentials-get=(), screen-wake-lock=(), serial=(), speaker-selection=(), sync-xhr=(), usb=(), xr-spatial-tracking=()
```

| Directive | Controls | WordPress Context |
|-----------|----------|-------------------|
| `geolocation=()` | Block geolocation access | No legitimate need for most content sites |
| `camera=()` | Block camera access | Needed only for vlogging/streaming sites |
| `microphone=()` | Block microphone access | Needed only for podcasts/live streaming |
| `payment=()` | Block Payment Request API | Only enable if accepting payments in-browser |
| `sync-xhr=()` | Block synchronous XHR | Bad for UX anyway; blocks malicious synchronous requests |
| `fullscreen=*` | Allow fullscreen API | May be needed for video embeds |

### Common Misconfigurations

| Issue | Example | Impact |
|-------|---------|--------|
| **Missing entirely** | *(no header)* | All browser APIs available to any script on the page |
| **Too permissive** | `geolocation=*` | Any script (including compromised ads) can access user location |
| **Breaking embedded content** | `fullscreen=()` on a video site | YouTube/Vimeo embeds may fail fullscreen |
| **Legacy `Feature-Policy` syntax** | `Feature-Policy: geolocation 'self'` | Older syntax, modern browsers use `Permissions-Policy` with `=` syntax |
| **No sync-xhr restriction** | Not specified | Synchronous XHR can be used for tracking/enumeration |

### Impact

| Scenario | Risk |
|----------|------|
| **Missing** | 🟡 **Medium**, Third-party scripts/ads/compromised plugins have unrestricted API access |
| **Locked down** | 🟢 **Low**, Attack surface reduced |
| **Breaking site functionality** | 🟢 **Informational**, No security impact, but user experience degraded |

---

## 7. 🔵 X-XSS-Protection

### What It Does

Controls the **now-deprecated** XSS filter built into older browsers (Internet Explorer, older Edge, Safari). Modern browsers (Chrome ≥ 78, Firefox ≥ 4) have removed their XSS filters in favor of CSP.

**Current status:** This header is obsolete. CSP is the modern XSS defense. However, setting it to `0` is recommended to prevent inconsistencies in the few browsers that still have it.

### How to Check It

```bash
curl -sI "https://example.com" | grep -i x-xss-protection
```

### Secure Value

```
X-XSS-Protection: 0
```

### Why `0` (Disable) and Not `1; mode=block`

| Value | What It Does | Problem |
|-------|-------------|---------|
| `0` | Disables the filter entirely | ✅ Correct modern choice |
| `1` | Enables the filter (default) | ❌ Can introduce XSS vulnerabilities on some pages |
| `1; mode=block` | Enables filter, blocks page if attack detected | ❌ Same as above, filter itself has caused XSS in the past |
| `1; report=<uri>` | Enables filter + sends violation report | ❌ Obsolete, rarely supported |

The old advice to use `1; mode=block` is now considered harmful because the browser's XSS filter itself has been a source of XSS vulnerabilities (it can be bypassed to inject scripts on otherwise safe pages).

### Common Misconfigurations

| Issue | Example | Impact |
|-------|---------|--------|
| **`1; mode=block` (old recommendation)** | `X-XSS-Protection: 1; mode=block` | Minor, won't hurt modern browsers (they ignore it), but may cause issues in legacy IE |
| **Missing entirely** | *(no header)* | No impact in modern browsers; legacy IE/Edge may have filter on by default (minimal risk) |
| **Setting `1` without `mode=block`** | `X-XSS-Protection: 1` | Legacy browsers may try to sanitize the page, potentially breaking layout |

### Impact

| Scenario | Risk |
|----------|------|
| **Missing or `0` on modern site with CSP** | 🟢 **Low**, CPS handles XSS protection |
| **`1; mode=block` on legacy-only site** | 🟢 **Low**, Minimal risk; filter is imperfect |
| **No CSP AND missing X-XSS-Protection** | 🟡 **Medium**, No XSS defense for legacy browsers |
| **Depends entirely on this header** | 🟠 **High**, False sense of security; must use CSP instead |

---

## Summary Compliance Matrix

| # | Header | Secure Value | Severity If Missing | Difficulty to Fix |
|---|--------|-------------|---------------------|-------------------|
| 1 | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | 🔴 Critical | Easy (server config) |
| 2 | `Content-Security-Policy` | Site-specific (see starter above) | 🔴 Critical | Hard (needs testing) |
| 3 | `X-Frame-Options` | `DENY` or `SAMEORIGIN` | 🟠 High | Easy (server config) |
| 4 | `X-Content-Type-Options` | `nosniff` | 🟠 High | Easy (server config) |
| 5 | `Referrer-Policy` | `strict-origin-when-cross-origin` | 🟡 Medium | Easy (server config) |
| 6 | `Permissions-Policy` | Lock down unused APIs | 🟡 Medium | Medium (test for breakage) |
| 7 | `X-XSS-Protection` | `0` (disable) | 🔵 Low | Easy (server config) |

---

## How to Fix Missing Headers in WordPress

### Option 1: `.htaccess` (Apache)

```apache
# Security Headers, Add to .htaccess
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=()"
    Header always set X-XSS-Protection "0"
</IfModule>
```

> ⚠️ **CSP intentionally omitted**, it must be tailored to your specific theme and plugins.

### Option 2: Nginx

```nginx
# In the server block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=()" always;
add_header X-XSS-Protection "0" always;
```

### Option 3: WordPress Plugin

- **HTTP Headers** (by Acnam), lightweight, no bloat
- **Really Simple SSL**, includes HSTS
- **Wordfence Security**, includes several security headers in its firewall options

> ⚠️ **Plugin note:** Avoid security plugins that only add headers if you already have a caching/CDN layer. Headers must survive cache, verify with curl after deployment.

---

## Verification Script

Save as `check-security-headers.sh`:

```bash
#!/bin/bash
# Security Headers Checker, WordPress Remote Audit
# Usage: ./check-security-headers.sh https://example.com

TARGET="${1%/}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 https://example.com"
    exit 1
fi

echo ""
echo "══════════════════════════════════════════════"
echo "  Security Headers Audit, $TARGET"
echo "══════════════════════════════════════════════"
echo ""

HEADERS=$(curl -sI "$TARGET" 2>/dev/null)

# Define checks
declare -A CHECKS
CHECKS["Strict-Transport-Security"]='max-age=31536000'
CHECKS["Content-Security-Policy"]='default-src'
CHECKS["X-Frame-Options"]='DENY|SAMEORIGIN'
CHECKS["X-Content-Type-Options"]='nosniff'
CHECKS["Referrer-Policy"]='strict-origin|same-origin|no-referrer'
CHECKS["Permissions-Policy"]='='  # at least one directive
CHECKS["X-XSS-Protection"]='0'

PASS=0
FAIL=0

for HEADER in "${!CHECKS[@]}"; do
    VALUE=$(echo "$HEADERS" | grep -i "^$HEADER:" 2>/dev/null)
    if [ -n "$VALUE" ]; then
        echo "  ✅ $HEADER"
        echo "     $VALUE"
        ((PASS++))
    else
        echo "  ❌ $HEADER, MISSING"
        ((FAIL++))
    fi
done

echo ""
echo "══════════════════════════════════════════════"
echo "  Results: $PASS present, $FAIL missing"
echo "══════════════════════════════════════════════"
echo ""
```

---

## WordPress-Specific Considerations

### 1. Admin vs. Frontend
WordPress often serves different headers on `/wp-admin/` routes. Always check both:
```bash
curl -sI "https://example.com/wp-admin/" | grep -iE '(strict-transport-security|x-frame-options)'
```

### 2. CDN / Reverse Proxy
If the site uses Cloudflare, CloudFront, or similar, headers may be set at the CDN level rather than on the origin server.
```bash
# Bypass CDN to check origin (if IP is known)
curl -sI -H "Host: example.com" "https://<origin-ip>/"
```

### 3. Caching Plugins
WP Rocket, W3 Total Cache, and similar may strip or override headers on cached pages. Always verify from an **uncached request**:
```bash
curl -sI "https://example.com" -H "Cache-Control: no-cache"
```

### 4. Mixed Content
Even with perfect headers, WordPress sites are notorious for mixed content (HTTP resources embedded in HTTPS pages). CSP's `upgrade-insecure-requests` directive can fix this automatically.

### 5. REST API Endpoint
WordPress REST API endpoints often lack security headers. Check:
```bash
curl -sI "https://example.com/wp-json/wp/v2/posts" | grep -iE '(x-frame-options|content-security-policy)'
```

---

## References

- [Mozilla Observatory](https://observatory.mozilla.org/), Free online scanner (no login, checks all headers)
- [securityheaders.com](https://securityheaders.com/), Quick header grading
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/), Google's CSP analyzer
- [HSTS Preload List](https://hstspreload.org/), Submit your site for browser preloading
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)

---

*Checklist generated for WordPress security audit service. Last updated: 2026-07-16.*
