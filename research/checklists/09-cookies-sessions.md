# 09, Cookies & Sessions Security Audit (WordPress)

> **Scope:** Remote, no login required unless noted
> **Category:** Authentication & Session Management
> **Severity Range:** Low → Critical
> **Dependencies:** `curl`, `jq` (optional), `openssl` (for cookie expiry parsing)

---

## Table of Contents

1. [WordPress Auth Cookie Detection](#1-wordpress-auth-cookie-detection)
2. [Cookie Flags Check (Secure, HttpOnly, SameSite)](#2-cookie-flags-check)
3. [Session Fixation Test](#3-session-fixation-test)
4. [WordPress Test Cookie (Comment Form)](#4-wordpress-test-cookie)
5. [Session Timeout Length Detection](#5-session-timeout-length-detection)
6. [Multiple Auth Cookies / Subdomain Scope](#6-multiple-auth-cookies--subdomain-scope)
7. [Application Passwords vs Auth Cookies](#7-application-passwords-vs-auth-cookies)
8. [Remember Me Cookie Detection & Expiry](#8-remember-me-cookie-detection--expiry)
9. [Comprehensive Cookie Inspector Script](#9-comprehensive-cookie-inspector-script)
10. [Remediation Summary](#10-remediation-summary)

---

## 1. WordPress Auth Cookie Detection

### Background

WordPress sets several authentication cookies when a user logs in:

| Cookie Name Prefix | Purpose | Scope |
|---|---|---|
| `wordpress_logged_in_[hash]` | Indicates user is logged in, used for front-end | Non-HTTPS pages if site not fully HTTPS |
| `wordpress_[hash]` | Backend auth (wp-admin), non-SSL version | Admin area |
| `wordpress_sec_[hash]` | Backend auth over HTTPS (when using SSL) | Admin area over HTTPS |
| `wordpress_[hash]_expired` | Expired session marker | Admin area |
| `wp-settings-[user_id]` | User dashboard settings (non-auth but user-specific) | Admin area |
| `wp-settings-time-[user_id]` | Timestamp of last settings update | Admin area |

### curl Commands

**Extract all `Set-Cookie` headers (unauthenticated):**

```bash
# Verbose mode, capture every Set-Cookie header
curl -skv "https://target.tld" 2>&1 | grep -i '^< set-cookie'

# Or with -o /dev/null for cleaner output
curl -skv "https://target.tld" -o /dev/null 2>&1 | grep -i '^< set-cookie'
```

**Check login page for any pre-auth cookie leakage:**

```bash
curl -sk "https://target.tld/wp-login.php" -D - -o /dev/null 2>&1 | grep -i 'set-cookie'
```

**Follow redirect chain to see cookies set across redirects:**

```bash
curl -skL "https://target.tld/wp-login.php" -D - -o /dev/null 2>&1 | grep -i 'set-cookie'
```

**Check admin-ajax for auth cookie reflection (useful for CSRF testing):**

```bash
curl -sk "https://target.tld/wp-admin/admin-ajax.php" -D - -o /dev/null 2>&1 | grep -i 'set-cookie'
```

### What to Look For

- **Presence of `wordpress_logged_in_[hash]`**, If visible without authentication → CRITICAL bug (usually misconfiguration or cache exposure)
- **Presence of `wordpress_sec_[hash]`**, Expected only after login; if present pre-auth → session leakage
- **Presence of `wp-settings-*`**, These appear after login; if visible without auth → potential user enumeration
- **`wordpress_[hash]` without `_sec` suffix**, Suggests non-HTTPS admin access is possible
- **Multiple instances of same cookie name**, Indicates conflicting cookie paths or misconfigured cache

### Severity

| Finding | Severity |
|---|---|
| `wordpress_logged_in_*` visible without auth | **Critical** |
| `wordpress_sec_*` visible on non-HTTPS page | **High** |
| `wp-settings-*` exposed pre-auth | **Medium** |
| Any auth cookie on non-HTTPS connection | **High** |
| Multiple conflicting auth cookies | **Medium** |

---

## 2. Cookie Flags Check

### Background

Security flags on cookies control how browsers handle them:

| Flag | What It Does |
|---|---|
| **Secure** | Cookie is only sent over HTTPS connections |
| **HttpOnly** | Cookie is inaccessible to JavaScript (`document.cookie`) |
| **SameSite** | Controls cross-site request behaviour: `Strict` / `Lax` / `None` |

### curl Commands

**Extract full cookie headers with all attributes:**

```bash
# Show raw Set-Cookie header (includes all flags)
curl -skv "https://target.tld" 2>&1 | grep -i '^< set-cookie'

# Parse into readable format
curl -sk "https://target.tld" -D /tmp/wp_headers.txt -o /dev/null
grep -i 'set-cookie' /tmp/wp_headers.txt

# Check login page specifically
curl -sk "https://target.tld/wp-login.php" -D /tmp/wp_login_headers.txt -o /dev/null
grep -i 'set-cookie' /tmp/wp_login_headers.txt
```

**Check cookies on wp-admin (redirected, but headers before redirect are visible):**

```bash
curl -sk "https://target.tld/wp-admin/" -D /tmp/wp_admin_headers.txt -o /dev/null
grep -i 'set-cookie' /tmp/wp_admin_headers.txt
```

**Check comment page / any POST endpoint that sets test cookies:**

```bash
curl -sk -X POST "https://target.tld/wp-comments-post.php" -D - -o /dev/null 2>&1 | grep -i 'set-cookie'
```

**Scripted flag audit:**

```bash
#!/bin/bash
# cookie_flags_audit.sh
SITE="$1"
COOKIE_FILE=$(mktemp)

curl -skL -D "$COOKIE_FILE" "https://$SITE/wp-login.php" -o /dev/null

echo "=== Cookie Flag Audit for $SITE ==="
echo ""

while IFS= read -r line; do
  if echo "$line" | grep -qi 'set-cookie'; then
    cookie=$(echo "$line" | sed 's/^[^:]*:[[:space:]]*//')
    name=$(echo "$cookie" | cut -d= -f1)
    has_secure=$(echo "$cookie" | grep -qi 'secure' && echo "✅ PRESENT" || echo "❌ MISSING")
    has_httponly=$(echo "$cookie" | grep -qi 'httponly' && echo "✅ PRESENT" || echo "❌ MISSING")
    samesite=$(echo "$cookie" | grep -ioP 'samesite=\K\w+' || echo "❌ NOT SET")

    echo "Cookie: $name"
    echo "  Secure:   $has_secure"
    echo "  HttpOnly: $has_httponly"
    echo "  SameSite: $samesite"
    echo ""
  fi
done < "$COOKIE_FILE"

rm -f "$COOKIE_FILE"
```

### What to Look For

- **Missing `Secure` flag** on any auth cookie → cookie can be sent over plain HTTP (session hijacking via network sniffing)
- **Missing `HttpOnly` flag** on auth cookie → XSS can steal the session (document.cookie)
- **`SameSite=None`** → cookie sent on cross-site requests (CSRF risk), only legitimate if `Secure` is also set
- **`SameSite=Strict`** → most secure but may break some legitimate cross-site flows
- **`SameSite=Lax`** → good default, prevents most CSRF but allows top-level GET navigations
- **Inconsistent flags** across cookies from same domain

### Severity

| Finding | Severity |
|---|---|
| Auth cookie missing `Secure` flag | **High** |
| Auth cookie missing `HttpOnly` flag | **High** |
| Session cookie missing both `Secure` + `HttpOnly` | **Critical** |
| `SameSite=None` without `Secure` | **High** |
| No `SameSite` attribute at all | **Medium** |
| Test/comment cookies missing flags | **Low** |

---

## 3. Session Fixation Test

### Background

Session fixation occurs when an attacker can force a victim to use a session identifier known to the attacker. WordPress uses PHP sessions which generate a new session ID on login, but this is configurable and misconfigurations can bypass it.

> **Note:** This test requires being able to observe session cookies before and after a login. If you lack credentials, check for **session ID regeneration behaviour** and **pre-login session cookies**.

### curl Commands

**Step 1, Capture pre-login session cookie:**

```bash
# Get a session cookie from the login page (unauthenticated)
curl -skL "https://target.tld/wp-login.php" -D /tmp/prelogin_headers.txt -c /tmp/prelogin_cookies.txt -o /dev/null

echo "=== Pre-Login Session Cookies ==="
cat /tmp/prelogin_cookies.txt
```

**Step 2, Attempt login and capture post-login session:**

```bash
# Replace USER and PASS below
curl -skL "https://target.tld/wp-login.php" \
  -b /tmp/prelogin_cookies.txt \
  -c /tmp/postlogin_cookies.txt \
  -D /tmp/postlogin_headers.txt \
  -d "log=USER&pwd=PASS&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
  -o /dev/null

echo "=== Post-Login Session Cookies ==="
cat /tmp/postlogin_cookies.txt
```

**Step 3, Compare session IDs:**

```bash
# Extract PHPSESSID or equivalent from both files
echo "Pre-login PHPSESSID:  $(grep 'PHPSESSID' /tmp/prelogin_cookies.txt 2>/dev/null | awk '{print $NF}')"
echo "Post-login PHPSESSID: $(grep 'PHPSESSID' /tmp/postlogin_cookies.txt 2>/dev/null | awk '{print $NF}')"

# Also check WordPress auth cookies that might have changed
echo ""
echo "Pre-login wordpress_* cookies:"
grep -E 'wordpress_' /tmp/prelogin_cookies.txt 2>/dev/null
echo ""
echo "Post-login wordpress_* cookies:"
grep -E 'wordpress_' /tmp/postlogin_cookies.txt 2>/dev/null

# Check if any pre-login cookie value persists after login
echo ""
echo "=== Session Fixation Check ==="
if grep -q 'PHPSESSID' /tmp/prelogin_cookies.txt && grep -q 'PHPSESSID' /tmp/postlogin_cookies.txt; then
  PRE_SESS=$(grep 'PHPSESSID' /tmp/prelogin_cookies.txt | awk '{print $NF}')
  POST_SESS=$(grep 'PHPSESSID' /tmp/postlogin_cookies.txt | awk '{print $NF}')
  if [ "$PRE_SESS" = "$POST_SESS" ]; then
    echo "❌ VULNERABLE: Session ID unchanged after login (session fixation)"
  else
    echo "✅ Session ID regenerated after login"
  fi
else
  echo "⚠️  No PHPSESSID cookie found (WordPress may not use session cookies)"
fi
```

### What to Look For

- **Same session ID before and after login** → classic session fixation vulnerability
- **PHPSESSID cookie set pre-login**, WordPress doesn't normally set session cookies on login page by default; if present, something (plugin/theme) is creating PHP sessions
- **No session ID regeneration on privilege change** → attacker can fixate a session
- **WordPress auth cookies (`wordpress_logged_in_*`) present before login** → residual session from cache or proxy

### Severity

| Finding | Severity |
|---|---|
| Session ID unchanged after login (fixation) | **Critical** |
| Session ID present pre-login (any cookie) | **Low-Medium** (depends on context) |
| WordPress auth cookies visible pre-login (cache leak) | **High** |

---

## 4. WordPress Test Cookie (Comment Form)

### Background

WordPress sets a `wordpress_test_cookie` on the comment form page to check if the browser accepts cookies. This cookie is:
- Set via JavaScript (`wp-set-cookie()` or inline script)
- Visible in page source / HTTP response
- Not an auth cookie, but its presence confirms the cookie mechanism works
- Sometimes used by security scanners as a fingerprint

### curl Commands

**Check for test cookie in HTTP response headers:**

```bash
curl -sk "https://target.tld/wp-comments-post.php" \
  -D - -o /dev/null 2>&1 | grep -i 'set-cookie.*test'

# Or on the post/page itself
curl -sk "https://target.tld/sample-post/" \
  -D - -o /dev/null 2>&1 | grep -i 'set-cookie.*test'
```

**Check for test cookie JavaScript in page source:**

```bash
curl -sk "https://target.tld/sample-post/" 2>&1 | grep -oP 'wordpress_test_cookie[^"]*'

# Or more targeted
curl -sk "https://target.tld/sample-post/" 2>&1 | grep -i 'test.cookie'
```

**Check comments endpoint directly:**

```bash
curl -sk "https://target.tld/wp-json/wp/v2/comments" \
  -D - -o /dev/null 2>&1 | grep -i 'set-cookie'
```

**Scripted test cookie analysis:**

```bash
#!/bin/bash
# test_cookie_audit.sh
SITE="$1"

echo "=== WordPress Test Cookie Audit for $SITE ==="
echo ""

# 1. Check headers for test cookie
echo "[1] HTTP Header Check:"
HEADER_RESULT=$(curl -sk "https://$SITE" -D - -o /dev/null 2>&1 | grep -i 'test.cookie')
if [ -n "$HEADER_RESULT" ]; then
  echo "  ✅ Test cookie found in headers:"
  echo "    $HEADER_RESULT"
else
  echo "  ℹ️  No test cookie in headers (normal for non-comment pages)"
fi
echo ""

# 2. Check comment form page for JavaScript-set test cookie
echo "[2] Page Source Check (common paths):"
for path in "" "/sample-post/" "/hello-world/" "/?p=1"; do
  result=$(curl -sk "https://$SITE$path" 2>&1 | grep -ioP '.{0,50}wordpress_test_cookie.{0,50}')
  if [ -n "$result" ]; then
    echo "  Found on $path:"
    echo "    $result"
    echo ""
    break
  fi
done

# 3. Check if test cookie is set via JavaScript (security concern if JIT)
echo "[3] Test Cookie Attribute Check:"
curl -sk "https://$SITE" -D /tmp/wp_test_hdr.txt -o /dev/null
grep -i 'test.cookie' /tmp/wp_test_hdr.txt | while read -r line; do
  has_secure=$(echo "$line" | grep -qi 'secure' && echo "✅" || echo "❌")
  has_httponly=$(echo "$line" | grep -qi 'httponly' && echo "✅" || echo "❌")
  echo "  Secure:   $has_secure"
  echo "  HttpOnly: $has_httponly"
done

rm -f /tmp/wp_test_hdr.txt
```

### What to Look For

- **Test cookie visible in HTTP headers**, confirms WordPress cookie mechanism is active
- **Test cookie in JavaScript-injected form**, `wp-set-cookie` function in page source
- **Test cookie missing Secure/HttpOnly flags**, low severity but indicates lax cookie policy
- **Test cookie set on every page, not just comment forms**, may indicate aggressive cookie setting by a plugin
- **Leaked via cache/CDN**, test cookie appearing on cached copies of pages can indicate CDN bypassing WordPress cookie handling

### Severity

| Finding | Severity |
|---|---|
| Test cookie present (expected) | **Info** |
| Test cookie missing Secure flag on HTTPS site | **Low** |
| Test cookie injected via JS without HttpOnly (expected, it's a JS check) | **Info** |
| Test cookie visible in cached responses | **Low-Medium** |
| Test cookie path exposing internal PHP logic | **Low** |

---

## 5. Session Timeout Length Detection

### Background

WordPress auth cookies have configurable expiry. Defaults:
- **Logged-in cookie:** 2 days (48 hours), defined by `AUTH_COOKIE_EXPIRY` or `AUTH_COOKIE` + session token
- **Remember Me cookie:** 14 days (336 hours)
- **PHP session garbage collection:** Controlled by PHP's `session.gc_maxlifetime` (default: 1440 seconds / 24 minutes)

### curl Commands

**Extract cookie expiry from Set-Cookie headers:**

```bash
# Parse expiry dates from cookies
curl -sk "https://target.tld/wp-login.php" \
  -D /tmp/wp_expiry.txt -o /dev/null

echo "=== Cookie Expiry Analysis ==="
grep -i 'set-cookie' /tmp/wp_expiry.txt | while read -r line; do
  echo "Raw: $line"
  expiry=$(echo "$line" | grep -ioP '(expires|Max-Age)=\K[^;]+' || echo "No expiry set (session cookie)")
  echo "  Expiry: $expiry"
  echo ""
done
```

**Check for session.gc_maxlifetime via error disclosure or headers:**

```bash
# PHP default session timeout detection, check for PHPSESSID
curl -sk "https://target.tld" -D /tmp/wp_phpsessid.txt -o /dev/null
grep -i 'set-cookie' /tmp/wp_phpsessid.txt

# Check if session cookie has an expiry or is session-only
if grep -qi 'PHPSESSID' /tmp/wp_phpsessid.txt; then
  echo "PHP Sessions active"
  grep 'PHPSESSID' /tmp/wp_phpsessid.txt | while read -r line; do
    if echo "$line" | grep -qi 'expires'; then
      echo "  Session has explicit expiry"
    else
      echo "  ❌ Session cookie is session-only (expires on browser close)"
    fi
  done
fi
```

**Check for server-time exposure (helps calculate cookie age):**

```bash
# Date header gives server time
curl -skI "https://target.tld" 2>&1 | grep -i '^date:'

# Compare with local time to determine timezone offset
echo "Server date: $(curl -skI 'https://target.tld' 2>&1 | grep -i '^date:' | sed 's/^[^:]*:[[:space:]]*//')"
echo "Local  date: $(date -u)"
```

**Parse cookie expiry into human-readable format:**

```bash
# Extract and decode cookie expiry
COOKIE_EXPIRY=$(curl -sk "https://target.tld" -D - -o /dev/null 2>&1 | \
  grep -i 'set-cookie' | grep -oP 'expires=\K[^;]+' | head -1)

if [ -n "$COOKIE_EXPIRY" ]; then
  echo "Cookie expires on: $COOKIE_EXPIRY"
  echo "Expiry timestamp:  $(date -d "$COOKIE_EXPIRY" +%s 2>/dev/null)"
  echo "Current timestamp: $(date -u +%s)"
  NOW=$(date -u +%s)
  EXP=$(date -d "$COOKIE_EXPIRY" +%s 2>/dev/null)
  if [ -n "$EXP" ] && [ "$EXP" -gt "$NOW" ]; then
    DIFF=$((EXP - NOW))
    echo "Time until expiry: $((DIFF / 3600)) hours $(((DIFF % 3600) / 60)) minutes"
  fi
else
  echo "No cookie expiry found (session-only cookies)"
fi
```

### What to Look For

- **Excessively long cookie expiry**, > 48 hours for standard auth, > 14 days for remember-me
- **No expiry on remember-me cookie** → session never expires (persistent login risk)
- **Session-only cookies** → expire on browser close (good for security, bad for UX)
- **Max-Age vs Expires**, `Max-Age` takes precedence in HTTP spec; if both present, check for contradictions
- **PHP session.gc_maxlifetime**, if PHP sessions are used, default 1440s (24min) may be too short or misconfigured

### Severity

| Finding | Severity |
|---|---|
| Auth cookie expiry > 48 hours (no remember-me) | **Medium** |
| Remember-me cookie > 30 days | **Medium** |
| Auth cookie never expires | **High** |
| No expiry set on any cookie (all session-only) | **Low** |
| Max-Age and Expires contradict each other | **Low** |

---

## 6. Multiple Auth Cookies / Subdomain Scope

### Background

WordPress auth cookies are scoped to the domain and path where they're set. Subdomain handling depends on the `COOKIE_DOMAIN` constant in `wp-config.php` and the `wordpress` cookie hash.

- **Default behaviour:** Cookies scoped to the exact domain (e.g., `www.target.tld`)
- **Wildcard domain:** If `COOKIE_DOMAIN` is set to `.target.tld`, cookies are shared across all subdomains
- **Multiple cookie hashes:** Different WordPress installations on different subdomains produce different cookie hashes

### curl Commands

**Check cookie domain scope from Set-Cookie headers:**

```bash
# Check domain parameter in cookies
curl -sk "https://www.target.tld" \
  -D /tmp/wp_domain.txt -o /dev/null

echo "=== Cookie Domain Scope ==="
grep -i 'set-cookie' /tmp/wp_domain.txt | while read -r line; do
  name=$(echo "$line" | cut -d= -f1 | sed 's/^[^:]*:[[:space:]]*//')
  domain=$(echo "$line" | grep -ioP 'domain=\K[^;]+' || echo "No domain restriction")
  path=$(echo "$line" | grep -ioP 'path=\K[^;]+' || echo "/")
  echo "Cookie: $name"
  echo "  Domain: $domain"
  echo "  Path:   $path"
  echo ""
done
```

**Compare cookies across subdomains:**

```bash
# Test multiple subdomains for cookie consistency
for sub in "www" "blog" "app" "shop" "admin" "mail"; do
  echo "=== $sub.target.tld ==="
  curl -sk "https://$sub.target.tld" \
    -D - -o /dev/null 2>&1 | grep -i 'set-cookie' | head -3
  echo ""
done
```

**Check for cookie domain wildcard:**

```bash
# If a cookie has domain=.target.tld, it's shared across all subdomains
curl -sk "https://target.tld" -D /tmp/wp_wildcard.txt -o /dev/null
if grep -qiP 'domain=\.[^;]*target\.tld' /tmp/wp_wildcard.txt; then
  echo "❌ WILDCARD COOKIE DOMAIN DETECTED, cookies shared across subdomains"
  grep -i 'set-cookie' /tmp/wp_wildcard.txt | grep -iP 'domain=\.'
else
  echo "✅ No wildcard cookie domain detected (scoped to specific domain)"
fi
```

**Check for cookie path misconfigurations:**

```bash
# Auth cookies should be scoped to /wp-admin/ or /
curl -sk "https://target.tld/wp-admin/" -D /tmp/wp_path.txt -o /dev/null
grep -i 'set-cookie' /tmp/wp_path.txt | grep -iP 'path='

# Check if admin cookies bleed into front-end
curl -sk "https://target.tld/some-page/" -D /tmp/wp_front.txt -o /dev/null
grep -i 'set-cookie' /tmp/wp_front.txt
```

### What to Look For

- **Wildcard domain** (`.target.tld`), any XSS on any subdomain can steal auth cookies for all subdomains
- **No `domain` attribute**, browser defaults to the origin domain (usually correct)
- **Cookie path too broad**, auth cookie set on `/` instead of `/wp-admin/` means it's sent on every request
- **Cookie path too narrow**, e.g., `/wp-admin/` only, may break admin AJAX calls
- **Different WP hashes across subdomains**, indicates separate installations; auth cookies from one won't work on another

### Severity

| Finding | Severity |
|---|---|
| Wildcard cookie domain (`.target.tld`) with subdomain XSS risk | **High** |
| Auth cookie path is `/` (not `/wp-admin/`) | **Medium** |
| Multiple auth cookies from different WP installs on same domain | **Low-Medium** |
| Cookie domain mismatch between www and non-www | **Medium** |

---

## 7. Application Passwords vs Auth Cookies

### Background

WordPress 5.6+ introduced **Application Passwords**, a separate authentication mechanism for REST API and XML-RPC. These are not cookies but Base64-encoded tokens sent via the `Authorization` header or as URL parameters.

- **Auth Cookies:** `wordpress_logged_in_*`, `wordpress_sec_*`, browser-based, short-lived
- **Application Passwords:** Longer-lived, sent via `Authorization: Basic` header, bypass cookie checks
- **Cookies from Application Passwords:** None, application passwords don't set cookies; they authenticate directly

### curl Commands

**Test for Application Password acceptance on REST API:**

```bash
# Test if REST API accepts application passwords (unauthenticated)
curl -sk "https://target.tld/wp-json/wp/v2/users/me" \
  -D /tmp/wp_apppw_hdr.txt -o /dev/null 2>&1 | grep -i 'set-cookie'

# Try with a deliberately invalid app password, check error message
curl -sk -u "admin:test_app_password_123" \
  "https://target.tld/wp-json/wp/v2/users/me" \
  -D /tmp/wp_apppw_resp.txt -o /dev/null

echo "=== Application Password Detection ==="
echo "Response status: $(head -1 /tmp/wp_apppw_resp.txt)"
echo ""
echo "Response body:"
curl -sk -u "admin:test_app_password_123" \
  "https://target.tld/wp-json/wp/v2/users/me" 2>/dev/null | head -5
```

**Check if application passwords create any cookie:**

```bash
# Authenticate with a real app password, observe if any cookie is set
# Replace with known valid app password
curl -sk -u "username:valid_app_password" \
  "https://target.tld/wp-json/wp/v2/users/me" \
  -D /tmp/wp_apppw_cookies.txt -o /dev/null

echo "=== Cookies Set by App Password Auth ==="
grep -i 'set-cookie' /tmp/wp_apppw_cookies.txt
if [ $? -ne 0 ]; then
  echo "No cookies set (expected, app passwords are stateless)"
fi
echo ""

# Compare: cookie auth vs app password auth
echo "=== Auth Method Comparison ==="
echo "Cookie auth: sets wordpress_logged_in_*, wordpress_sec_*"
echo "App password auth: NO cookies set (stateless)"
```

**Check for application password header leakage:**

```bash
# Check if app password is reflected in any response header or URL
curl -skv -u "user:app_password_test" \
  "https://target.tld/wp-json/wp/v2/posts" 2>&1 | grep -i 'authorization'
```

### What to Look For

- **Application passwords enabled** → check via REST API error messages (default WordPress returns `"code":"wp_rest_authentication_required"`)
- **Application passwords do NOT set cookies** (expected), stateless authentication
- **Application passwords being used alongside cookies**, mixed auth models can confuse security tools
- **App passwords exposed in server logs**, because they're sent as Basic Auth headers, they appear in `Authorization` header logs
- **Overly permissive app passwords**, if application passwords have full admin scope, they bypass MFA and cookie security controls

### Severity

| Finding | Severity |
|---|---|
| Application passwords enabled (no further restrictions) | **Medium** |
| App passwords with full admin scope | **High** |
| App passwords without HTTPS enforcement | **Critical** |
| App passwords leaked via error messages | **Medium** |

---

## 8. Remember Me Cookie Detection & Expiry

### Background

WordPress's "Remember Me" feature sets a longer-lived auth cookie. The remember-me cookie is not a different _name_, it's the same `wordpress_logged_in_[hash]` cookie but with a longer expiry (14 days default).

- **Without "Remember Me":** Cookie expires in ~48 hours (or browser close for session cookies)
- **With "Remember Me":** Cookie expires in ~14 days (configurable via `define('COOKIE_EXPIRY', value);` in `wp-config.php`)
- **Detection method:** The cookie name is identical, you differentiate by expiry length

### curl Commands

**Check cookie expiry to infer remember-me vs session:**

```bash
# Check the expiry on wordpress_logged_in_* cookie
curl -sk "https://target.tld/wp-login.php" \
  -D /tmp/wp_remember.txt -o /dev/null

echo "=== Remember Me Detection ==="
grep -iE '(wordpress_logged_in|wordpress_sec)' /tmp/wp_remember.txt | while read -r line; do
  echo "Raw: $line"
  expiry=$(echo "$line" | grep -ioP 'expires=\K[^;]+' || echo "No expiry")
  max_age=$(echo "$line" | grep -ioP 'Max-Age=\K[^;]+' || echo "Not set")
  echo "  Expires: $expiry"
  echo "  Max-Age: $max_age seconds"
  echo ""
  
  # Calculate duration
  if [ "$max_age" != "Not set" ] && [ -n "$max_age" ]; then
    if [ "$max_age" -gt 172800 ]; then  # > 48 hours
      echo "  ❌ LONG-LIVED COOKIE (>48h, likely remember-me)"
      echo "  Duration: $((max_age / 86400)) days $(((max_age % 86400) / 3600)) hours"
    elif [ "$max_age" -gt 0 ]; then
      echo "  ✅ Standard session cookie"
      echo "  Duration: $((max_age / 3600)) hours"
    fi
  fi
done
```

**Simulate remember-me login to observe cookie expiry:**

```bash
# Simulate login with remember-me checked
# Replace with actual credentials
curl -skL "https://target.tld/wp-login.php" \
  -X POST \
  -c /tmp/wp_remember_cookies.txt \
  -D /tmp/wp_remember_headers.txt \
  -d "log=USER&pwd=PASS&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1&rememberme=forever" \
  -o /dev/null

echo "=== Remember Me Cookie Analysis ==="
grep -E 'wordpress_' /tmp/wp_remember_cookies.txt | while read -r name value domain path flags expires; do
  echo "Cookie: $name"
  echo "  Expires timestamp: $expires"
  if [ "$expires" != "0" ] && [ -n "$expires" ]; then
    NOW=$(date -u +%s)
    DIFF=$((expires - NOW))
    DAYS=$((DIFF / 86400))
    echo "  Lifetime remaining: ~$DAYS days"
    if [ "$DAYS" -gt 14 ]; then
      echo "  ⚠️  Expiry exceeds default 14-day remember-me period"
    fi
  else
    echo "  Session cookie (expires on browser close)"
  fi
done
```

**Scripted remember-me detection:**

```bash
#!/bin/bash
# remember_me_audit.sh
SITE="$1"

echo "=== Remember Me Cookie Detection for $SITE ==="
echo ""

# Fetch and analyse cookie expiry
curl -skL "https://$SITE/wp-login.php" \
  -c /tmp/wp_rm_cookies.txt \
  -D /tmp/wp_rm_headers.txt \
  -o /dev/null

echo "[1] Cookie Names with Expiry:"
awk '{print $6, $7, $5}' /tmp/wp_rm_cookies.txt 2>/dev/null | grep -v '^#' | while read -r expires name domain; do
  if [ "$name" != "#HttpOnly_" ]; then
    if [ "$expires" = "0" ] || [ -z "$expires" ]; then
      echo "  $name, SESSION ONLY"
    else
      NOW=$(date -u +%s)
      if [ "$expires" -gt "$NOW" ] 2>/dev/null; then
        DIFF=$((expires - NOW))
        HOURS=$((DIFF / 3600))
        echo "  $name, $HOURS hours remaining"
        if [ "$HOURS" -gt 48 ]; then
          echo "    ⚠️  This exceeds 48h standard session, likely remember-me"
        fi
      fi
    fi
  fi
done

echo ""
echo "[2] Risk Assessment:"
# Check any cookie with >48h lifespan
while read -r expires name; do
  if [ "$expires" != "0" ] && [ -n "$expires" ] && [ "$expires" -gt 0 ] 2>/dev/null; then
    DIFF=$((expires - $(date -u +%s)))
    HOURS=$((DIFF / 3600))
    if [ "$HOURS" -gt 336 ]; then
      echo "  ❌ CRITICAL: Cookie $name expires in $HOURS hours (>14 days)"
    elif [ "$HOURS" -gt 168 ]; then
      echo "  ⚠️  HIGH: Cookie $name expires in $HOURS hours (>7 days)"
    elif [ "$HOURS" -gt 48 ]; then
      echo "  ⚠️  MEDIUM: Cookie $name expires in $HOURS hours (>2 days, remember-me)"
    fi
  fi
done < <(awk '{print $5, $6}' /tmp/wp_rm_cookies.txt 2>/dev/null | grep -v '^#')

rm -f /tmp/wp_rm_cookies.txt /tmp/wp_rm_headers.txt
```

### What to Look For

- **Auth cookie expiry > 48 hours** → remember-me is active
- **No expiry set on auth cookie** → session cookie (browser close clears it)
- **Remember-me expiry > 14 days** → non-standard, may be configured via `COOKIE_EXPIRY`
- **Remember-me expiry > 30 days** → security risk (stolen cookie usable for a month+)
- **Remember-me cookie without Secure flag** → can be stolen via network sniffing
- **Inconsistent expiry**, different cookie expiry times suggest custom plugin behaviour

### Severity

| Finding | Severity |
|---|---|
| Remember-me expiry > 30 days | **High** |
| Remember-me expiry > 14 days | **Medium** |
| No remember-me option (all session cookies) | **Info** |
| Remember-me cookie without Secure flag | **High** |
| Remember-me cookie without HttpOnly (XSS-exposed) | **High** |

---

## 9. Comprehensive Cookie Inspector Script

Below is a standalone bash script that performs **all** the above checks in one pass. Save it to your auditing toolkit and run it against any target.

```bash
#!/bin/bash
#===============================================================================
# WordPress Cookie & Session Security Inspector
# Usage: ./wp-cookie-inspector.sh <target.tld>
# Dependencies: curl, grep, awk, sed, date, openssl
#===============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

SITE="${1:?Usage: $0 <target.tld>}"
SCRIPT_DIR="/tmp/wp_cookie_audit_$$"
mkdir -p "$SCRIPT_DIR"

cleanup() { rm -rf "$SCRIPT_DIR"; }
trap cleanup EXIT

info()    { echo -e "${BLUE}[*]${NC} $*"; }
pass()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "${RED}[X]${NC} $*"; }
hr()      { echo "────────────────────────────────────────────────────────────"; }

#===============================================================================
# PRELIMINARY
#===============================================================================
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   WordPress Cookie & Session Security Inspector             ║"
echo "║   Target: $SITE"
echo "║   Date:   $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Test connectivity
info "Testing connectivity to $SITE..."
if ! curl -sk --connect-timeout 10 "https://$SITE" -o /dev/null 2>/dev/null; then
  fail "Cannot reach $SITE over HTTPS. Trying HTTP..."
  if ! curl -sk --connect-timeout 10 "http://$SITE" -o /dev/null 2>/dev/null; then
    fail "Cannot reach $SITE at all. Exiting."
    exit 1
  fi
  PROTO="http"
  warn "Using HTTP (insecure), results will reflect insecure connection"
else
  PROTO="https"
  pass "Connectivity OK ($PROTO)"
fi
echo ""

#===============================================================================
# 1. AUTH COOKIE DETECTION
#===============================================================================
hr
info "1. WordPress Auth Cookie Detection"
hr

curl -skL "${PROTO}://${SITE}" -D "${SCRIPT_DIR}/home_headers.txt" -o /dev/null
curl -skL "${PROTO}://${SITE}/wp-login.php" -D "${SCRIPT_DIR}/login_headers.txt" -o /dev/null
curl -skL "${PROTO}://${SITE}/wp-admin/" -D "${SCRIPT_DIR}/admin_headers.txt" -o /dev/null

echo ""
info "Cookies set on homepage:"
grep -i 'set-cookie' "${SCRIPT_DIR}/home_headers.txt" 2>/dev/null | sed 's/^/  /' || echo "  (none)"

echo ""
info "Cookies set on wp-login.php:"
grep -i 'set-cookie' "${SCRIPT_DIR}/login_headers.txt" 2>/dev/null | sed 's/^/  /' || echo "  (none)"

echo ""
info "Cookies set on wp-admin (redirect):"
grep -i 'set-cookie' "${SCRIPT_DIR}/admin_headers.txt" 2>/dev/null | sed 's/^/  /' || echo "  (none)"

echo ""

# Check for auth cookie names
AUTH_COOKIES=$(grep -iE '(wordpress_logged_in|wordpress_sec|wordpress_\[|wp-settings)' \
  "${SCRIPT_DIR}/home_headers.txt" "${SCRIPT_DIR}/login_headers.txt" "${SCRIPT_DIR}/admin_headers.txt" 2>/dev/null || true)

if [ -n "$AUTH_COOKIES" ]; then
  warn "Auth-related cookies found without authentication!"
  echo "$AUTH_COOKIES" | sed 's/^/  /'
  echo ""
  fail "Auth cookie leakage detected (critical)"
else
  pass "No auth cookies leaked without authentication (expected)"
fi

#===============================================================================
# 2. COOKIE FLAGS CHECK
#===============================================================================
hr
info "2. Cookie Security Flags Check"
hr

for header_file in "${SCRIPT_DIR}/home_headers.txt" "${SCRIPT_DIR}/login_headers.txt"; do
  grep -i 'set-cookie' "$header_file" 2>/dev/null | while read -r line; do
    cookie_name=$(echo "$line" | sed 's/^[^:]*:[[:space:]]*//' | cut -d= -f1)
    flags_secure=$(echo "$line" | grep -qi 'secure' && echo "✅" || echo "❌")
    flags_httponly=$(echo "$line" | grep -qi 'httponly' && echo "✅" || echo "❌")
    flags_samesite=$(echo "$line" | grep -ioP 'samesite=\K\w+' || echo "NOT SET")
    
    echo "  Cookie: $cookie_name"
    echo "    Secure:   $flags_secure"
    echo "    HttpOnly: $flags_httponly"
    echo "    SameSite: $flags_samesite"
    
    # Severity assessment per cookie
    if echo "$cookie_name" | grep -qiE '(wordpress_logged_in|wordpress_sec|wordpress_)'; then
      if echo "$line" | grep -vqi 'secure'; then
        fail "  -> Auth cookie missing Secure flag!"
      fi
      if echo "$line" | grep -vqi 'httponly'; then
        fail "  -> Auth cookie missing HttpOnly flag!"
      fi
    fi
  done
done
echo ""

#===============================================================================
# 3. SESSION FIXATION TEST (pre-login cookies only)
#===============================================================================
hr
info "3. Session Fixation, Pre-Login Cookie Analysis"
hr

curl -skL "${PROTO}://${SITE}/wp-login.php" \
  -c "${SCRIPT_DIR}/prelogin_cookies.txt" \
  -D "${SCRIPT_DIR}/prelogin_headers2.txt" \
  -o /dev/null

if [ -s "${SCRIPT_DIR}/prelogin_cookies.txt" ]; then
  info "Pre-login cookies stored:"
  cat "${SCRIPT_DIR}/prelogin_cookies.txt" | grep -v '^#' | awk '{printf "  %-30s %s\n", $6, $7}' || echo "  (none)"
  
  # Check for PHPSESSID (indicates PHP sessions active pre-auth)
  if grep -qi 'PHPSESSID' "${SCRIPT_DIR}/prelogin_cookies.txt"; then
    warn "PHPSESSID cookie set before authentication, PHP sessions active"
    warn "Session fixation risk if ID is not regenerated on login"
  else
    pass "No PHPSESSID pre-login (WordPress default behaviour)"
  fi
else
  info "No cookies set before login (expected)"
fi
echo ""

#===============================================================================
# 4. TEST COOKIE DETECTION
#===============================================================================
hr
info "4. WordPress Test Cookie Detection"
hr

# Check headers
TEST_COOKIE_HDR=$(grep -i 'test.cookie' "${SCRIPT_DIR}/login_headers.txt" 2>/dev/null || true)
if [ -n "$TEST_COOKIE_HDR" ]; then
  info "Test cookie found in headers:"
  echo "$TEST_COOKIE_HDR" | sed 's/^/  /'
else
  info "No test cookie in headers"
fi

# Check page source
TEST_COOKIE_SRC=$(curl -skL "${PROTO}://${SITE}/" 2>/dev/null | grep -ioP '.{0,40}wordpress_test_cookie.{0,40}' || true)
if [ -n "$TEST_COOKIE_SRC" ]; then
  info "Test cookie found in page source:"
  echo "$TEST_COOKIE_SRC" | sed 's/^/  /'
else
  info "No test cookie reference in page source (site may have comments disabled)"
fi
echo ""

#===============================================================================
# 5. COOKIE EXPIRY / SESSION TIMEOUT
#===============================================================================
hr
info "5. Session Timeout & Cookie Expiry Analysis"
hr

for header_file in "${SCRIPT_DIR}/home_headers.txt" "${SCRIPT_DIR}/login_headers.txt"; do
  grep -i 'set-cookie' "$header_file" 2>/dev/null | while read -r line; do
    cookie_name=$(echo "$line" | sed 's/^[^:]*:[[:space:]]*//' | cut -d= -f1)
    expiry=$(echo "$line" | grep -ioP 'expires=\K[^;]+' || echo "NOT SET")
    max_age=$(echo "$line" | grep -ioP 'Max-Age=\K[^;]+' || echo "NOT SET")
    
    echo "  Cookie: $cookie_name"
    echo "    Expires: $expiry"
    echo "    Max-Age: $max_age"
    
    # Calculate remaining time if Max-Age is set
    if [ "$max_age" != "NOT SET" ] && [ -n "$max_age" ] && [ "$max_age" -gt 0 ] 2>/dev/null; then
      if [ "$max_age" -gt 172800 ]; then
        warn "    -> Long-lived cookie (>48h): $((max_age / 86400))d $(((max_age % 86400) / 3600))h"
      elif [ "$max_age" -gt 0 ]; then
        pass "    -> Session cookie: $((max_age / 3600))h $(((max_age % 3600) / 60))m"
      fi
    fi
    
    # Check for remember-me (>14 days)
    if [ "$max_age" != "NOT SET" ] && [ -n "$max_age" ] && [ "$max_age" -gt 1209600 ] 2>/dev/null; then
      fail "    -> Exceeds 14-day remember-me default: $((max_age / 86400)) days"
    fi
  done
done
echo ""

# Get server time for reference
SERVER_DATE=$(curl -skI "${PROTO}://${SITE}" 2>&1 | grep -i '^date:' | sed 's/^[^:]*:[[:space:]]*//')
echo "  Server time: $SERVER_DATE"
echo "  Local  time: $(date -u '+%a, %d %b %Y %H:%M:%S GMT')"
echo ""

#===============================================================================
# 6. SUBDOMAIN / COOKIE SCOPE
#===============================================================================
hr
info "6. Cookie Domain & Subdomain Scope Analysis"
hr

grep -i 'set-cookie' "${SCRIPT_DIR}/home_headers.txt" 2>/dev/null | while read -r line; do
  cookie_name=$(echo "$line" | sed 's/^[^:]*:[[:space:]]*//' | cut -d= -f1)
  domain=$(echo "$line" | grep -ioP 'domain=\K[^;]+' || echo "ORIGIN-ONLY")
  path=$(echo "$line" | grep -ioP 'path=\K[^;]+' || echo "/")
  
  echo "  $cookie_name"
  echo "    Domain: $domain"
  echo "    Path:   $path"
  
  if echo "$domain" | grep -qP '^\.[^.]+\.[^.]+$'; then
    fail "    -> WILDCARD DOMAIN: $domain (cookies shared across subdomains!)"
  fi
done
echo ""

#===============================================================================
# 7. APPLICATION PASSWORDS CHECK
#===============================================================================
hr
info "7. Application Passwords Detection (REST API)"
hr

REST_RESULT=$(curl -sk "${PROTO}://${SITE}/wp-json/wp/v2/users/me" -D "${SCRIPT_DIR}/rest_headers.txt" -o "${SCRIPT_DIR}/rest_body.txt" -w '%{http_code}' 2>/dev/null || echo "000")

if grep -qi 'rest_authentication_required\|application_password' "${SCRIPT_DIR}/rest_body.txt" 2>/dev/null; then
  warn "REST API requires authentication (application passwords may be accepted)"
  if grep -qi 'application_password' "${SCRIPT_DIR}/rest_body.txt" 2>/dev/null; then
    fail "Application passwords mentioned in error response, likely enabled"
  fi
else
  info "REST API response code: $REST_RESULT"
  if [ "$REST_RESULT" = "200" ] || [ "$REST_RESULT" = "403" ]; then
    info "Authentication is active on REST API"
  fi
fi

# Check if REST API sets cookies
REST_COOKIES=$(grep -i 'set-cookie' "${SCRIPT_DIR}/rest_headers.txt" 2>/dev/null || true)
if [ -n "$REST_COOKIES" ]; then
  info "REST API sets cookies:"
  echo "$REST_COOKIES" | sed 's/^/  /'
else
  info "REST API does not set cookies (expected for stateless API)"
fi
echo ""

#===============================================================================
# 8. SUMMARY & RISK SCORING
#===============================================================================
hr
info "8. Audit Summary"
hr

echo ""
echo "  Site:       $SITE"
echo "  Protocol:   $PROTO"
echo "  Date:       $(date -u '+%Y-%m-%d %H:%M UTC')"
echo ""

# Count findings
CRIT=$(grep -c 'CRITICAL\|\[X\]' "${SCRIPT_DIR}/"*.txt 2>/dev/null || echo 0)
HIGH=$(grep -c '⚠️\|HIGH' "${SCRIPT_DIR}/"*.txt 2>/dev/null || echo 0)

echo "  Quick Risk Summary:"
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Cookies found on target: Check above for names/flags           │"
echo "  │ Session fixation risk: Yes if PHPSESSID present pre-auth       │"
echo "  │ Test cookie: Check section 4                                   │"
echo "  │ Cookie expiry: Check section 5                                 │"
echo "  │ Wildcard domain: Check section 6                               │"
echo "  │ App passwords: Check section 7                                 │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo "  For detailed remediation guidance, see the checklist document."
echo ""

#===============================================================================
# CLEANUP
#===============================================================================
cleanup
```

> **Usage:** Save as `wp-cookie-inspector.sh`, make executable (`chmod +x wp-cookie-inspector.sh`), and run:
> ```bash
> ./wp-cookie-inspector.sh target.tld
> ```

---

## 10. Remediation Summary

### Critical Issues (Fix Immediately)

| Issue | Fix |
|---|---|
| Auth cookies visible without login | Disable caching of authenticated pages; check CDN/reverse proxy config |
| Missing Secure flag on auth cookies | Set `define('FORCE_SSL_ADMIN', true);` in `wp-config.php` |
| Missing HttpOnly flag on auth cookies | Add `define('COOKIE_HTTPONLY', true);` in `wp-config.php` |
| Session fixation (PHPSESSID unchanged) | Ensure `wp_salt()` is properly configured; update PHP session handling |
| App passwords over HTTP | Block HTTP access to `/wp-json/` and `/xmlrpc.php` |
| Remember-me > 30 days | Set `define('COOKIE_EXPIRY', 1209600);` in `wp-config.php` (14 days in seconds) |

### High Issues (Fix Soon)

| Issue | Fix |
|---|---|
| Wildcard cookie domain | Set `define('COOKIE_DOMAIN', false);` in `wp-config.php` to scope to exact domain |
| Auth cookies on non-HTTPS connections | Full site HTTPS redirect; HSTS header |
| Remember-me without Secure flag | Same fix as Secure flag above |
| App passwords with full admin scope | Restrict via `WP_APPLICATION_PASSWORD` capabilities filter |
| Session timeout > 48h without remember-me | Set `define('AUTH_COOKIE_EXPIRY', 172800);` in `wp-config.php` |

### Medium Issues (Plan)

| Issue | Fix |
|---|---|
| No SameSite attribute on cookies | Add via server config or WordPress filter (`send_cookies` hook) |
| Cookie path too broad (`/`) | Set `define('ADMIN_COOKIE_PATH', '/');` or scope via plugin |
| Auth cookie mismatch www vs non-www | Canonical domain redirect; consistent `COOKIE_DOMAIN` |
| Long-lived cookies > 14 days | Reduce `COOKIE_EXPIRY` to `1209600` max |

### Low / Informational

| Issue | Note |
|---|---|
| Test cookie missing Secure flag | Low impact, not an auth cookie |
| No remember-me option | Higher security but worse UX |
| PHP sessions active | OK if properly configured; check session.gc_maxlifetime |
| Multiple WP installs on same domain | Use separate cookie hashes for each install |

### wp-config.php Hardening Snippet

```php
// --- Cookie & Session Security Hardening ---
define('FORCE_SSL_ADMIN', true);                  // Force HTTPS for admin
define('COOKIE_DOMAIN', false);                   // Scoped to exact domain (no wildcard)
define('COOKIE_HTTPONLY', true);                  // Prevent JS access to cookies
define('COOKIE_SAMESITE', 'Strict');              // WordPress 6.2+ supported
define('AUTH_COOKIE_EXPIRY', 172800);             // 48 hours
define('COOKIE_EXPIRY', 1209600);                 // 14 days for remember-me
define('RECOVERY_MODE_COOKIE_EXPIRY', 86400);     // 24 hours

// Prevent session fixation, ensure salts are unique and rotated
// (defined in wp-config.php by default, keep them unique per install)
```

---

> **Last Updated:** 2026-07-16
> **Audit Type:** Remote, unauthenticated
> **Test Coverage:** 8 of 8 checklist items covered; comprehensive inspector script included
