# 🔐 WordPress, Brute Force & Login Protection Audit Checklist

> **Audit type** : Remote (no credentials) + semi-auth (can verify after login)
> **Delivery** : Curl-based probes, timing analysis, response inspection
> **Goal** : Assess login security strength to sell hardening / repair services

---

## Severity Legend

| Severity | Label | Meaning |
|----------|-------|---------|
| 🔴 **CRITICAL** | Direct exploitation path, account takeover, credential leak, or DDoS amplification |
| 🟠 **HIGH** | Significant attack surface expansion, user enumeration, brute-force amplification, bypass of auth controls |
| 🟡 **MEDIUM** | Information leakage, structural weakness, or config weakness that aids targeted attacks |
| 🔵 **LOW** | Minor exposure, version disclosure, or hardening gap |

---

## 1. Login Page Detection

Attackers need to find the login page first. WordPress defaults to `wp-login.php` but hardening plugins and custom themes often change the login URL.

### 1.1, Default wp-login.php

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Redirect: %{redirect_url}" \
  "https://example.com/wp-login.php"
```

```bash
# Also check abbreviated paths
curl -s -o /dev/null -w "%{http_code}" "https://example.com/login"
curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-admin/"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| HTTP 200 (login form rendered) | Default login page accessible, standard but targetable | 🔵 **LOW** (baseline) |
| HTTP 302 redirect → `wp-login.php` | Login page exists but redirected | 🔵 **LOW** |
| HTTP 200 but not a login form (custom login URL) | Custom login URL in use, harder to locate | ✅ **HARDENED** |
| HTTP 403 / 404 | Login page hidden or removed | 🟢 **GOOD** |

### 1.2, Custom Login URL Discovery

If the default path returns something unexpected, try to locate the custom login URL via:

```bash
# Check robots.txt for clues
curl -s "https://example.com/robots.txt" | grep -i "login\|admin\|auth\|signin"

# Check sitemap for login-like paths
curl -s "https://example.com/sitemap.xml" | grep -oiE '(login|admin|auth|signin|connexion)'

# Check common custom login paths
for path in login admin connexion auth account entrar ingreso log-in \
  site-login cms-login secure portal loginpage wp-login-signup; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com/$path/" 2>/dev/null)
  echo "$path → $code"
done
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Custom login URL found in robots.txt | Login URL exposed in publicly indexed file | 🟡 **MEDIUM** |
| Login URL found via sitemap | Login page indexed, bad operational security | 🟠 **HIGH** |
| Login URL found via common path brute-force | Custom login but predictable | 🟡 **MEDIUM** |
| Login URL completely hidden | Proper security-through-obscurity + rate limiting | ✅ **HARDENED** |

> 💡 A custom login URL is **not a security measure on its own**, it's protection through obscurity. Always pair with rate limiting and 2FA.

---

## 2. User Enumeration via Author Parameter (?author=N)

WordPress URLs of the form `/?author=N` redirect to the author archive page with the username in the URL. This is the simplest user enumeration technique.

### 2.1, Standard Author Parameter Enumeration

```bash
# Test a range of numeric IDs
for i in 1 2 3 4 5 10 20 50 100; do
  response=$(curl -s -o /dev/null -w "HTTP %{http_code} | Redirect: %{redirect_url}" \
    "https://example.com/?author=$i" 2>/dev/null)
  echo "?author=$i → $response"
done
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| `302 → /author/username/` | Username leaked in redirect | 🔴 **CRITICAL** |
| `302 → /author/admin/` | Admin username confirmed | 🔴 **CRITICAL** |
| HTTP 200 with `?author=N` in body | Author name in page content | 🟠 **HIGH** |
| HTTP 404 for all values | Author enumeration blocked | ✅ **HARDENED** |

### 2.2, Author Archive Direct Access

```bash
curl -s -o /dev/null -w "HTTP %{http_code}" "https://example.com/author/admin/"
curl -s -o /dev/null -w "HTTP %{http_code}" "https://example.com/author/administrator/"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| HTTP 200 with content | Username confirmed and author archive accessible | 🟠 **HIGH** |
| HTTP 404 / 301 redirect to homepage | Author archives disabled or blocked | ✅ **HARDENED** |

### 2.3, Login Page Username Hint

```bash
# Some login pages reveal the username in hidden fields or page source
curl -s "https://example.com/wp-login.php" | grep -oiE 'name="log"|user_login|username|admin' | head -5
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Pre-filled "admin" or "Administrator" in login form | Username hint exposed | 🟠 **HIGH** |
| Form field IDs referencing "admin" | Minor informational leak | 🔵 **LOW** |

> 💡 **Interpretation:** If ANY author ID returns a username, the site is vulnerable to user enumeration. Attackers use this to target specific accounts, usually the admin. Combine with weak password checks.

---

## 3. REST API User Leak (wp-json/wp/v2/users)

WordPress REST API exposes registered users at `/wp-json/wp/v2/users` by default. In WordPress 4.7+, this endpoint lists users with their IDs, names, and avatars.

### 3.1, Basic User Endpoint Check

```bash
curl -s "https://example.com/wp-json/wp/v2/users" | python3 -m json.tool 2>/dev/null || \
  curl -s "https://example.com/wp-json/wp/v2/users"
```

```bash
# Also check with per_page parameter
curl -s "https://example.com/wp-json/wp/v2/users?per_page=100"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| JSON array with `id`, `name`, `slug` fields | Full user list exposed, **most common WP info leak** | 🔴 **CRITICAL** |
| `[]` empty array | No users returned, possibly blocked or no user authors | 🟡 **MEDIUM** (needs further investigation) |
| `{"code":"rest_user_cannot_list"}` | Properly restricted, needs authentication | ✅ **HARDENED** |
| `{"code":"rest_no_route"}` | REST API disabled entirely | ✅ **HARDENED** |
| HTTP 404 or redirect | REST API path changed or blocked | ✅ **HARDENED** |

### 3.2, Specific User ID Check

Even if the main endpoint is blocked, individual user endpoints may be accessible:

```bash
for i in 1 2 3 4 5; do
  curl -s "https://example.com/wp-json/wp/v2/users/$i" | head -100
  echo "---"
done
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| User object returned for specific ID | Individual user enumeration still possible | 🟠 **HIGH** |
| `{"code":"rest_user_invalid_id"}` for all | Properly blocked | ✅ **HARDENED** |

### 3.3, Users Me Endpoint (If Authenticated)

If you have a subscriber-level account or lower, check what restricted endpoints reveal:

```bash
# Requires a valid cookie or nonce, only test if you have a session
curl -s "https://example.com/wp-json/wp/v2/users/me"
```

> 💡 **Interpretation:** An exposed REST API users endpoint is one of the most common findings in WordPress audits. It gives attackers a ready-made list of usernames for brute-force targeting. Mark CRITICAL if users with admin roles are exposed.

---

## 4. Login Response Analysis (Username Validation)

WordPress login responses can reveal whether a username is valid, even on a failed login attempt. Different error messages for "user doesn't exist" vs "wrong password" enable targeted attacks.

### 4.1, Valid Username vs Invalid Username Detection

```bash
# Try a non-existent username
curl -s -L -X POST \
  -d "log=nonexistent_user_xyz&pwd=wrongpassword&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null | \
  grep -oiE '(error|incorrect|invalid|not found|unknown|n\'existe)' | head -10
```

```bash
# Try with "admin" (common existing user)
curl -s -L -X POST \
  -d "log=admin&pwd=wrongpassword&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null | \
  grep -oiE '(error|incorrect|invalid|not found|unknown|n\'existe)' | head -10
```

```bash
# Compare error messages, if they differ, users can be enumerated
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Different error messages for valid vs invalid user (e.g., "Invalid username" vs "The password you entered is incorrect") | Username enumeration via login form | 🟠 **HIGH** |
| Same generic message for all failures (e.g., "Invalid username or password") | Enumerration blocked, generic error | ✅ **HARDENED** |
| Slight timing differences (valid user DB lookup takes 2-3ms longer) | Timing-based enumeration still possible (advanced) | 🔵 **LOW** |

### 4.2, JSON / AJAX Login Response

Some sites use custom login forms that return JSON:

```bash
# WooCommerce or custom login forms
curl -s -X POST \
  -d "log=nonexistent&pwd=wrong" \
  -H "X-Requested-With: XMLHttpRequest" \
  "https://example.com/?customer-login=1" 2>/dev/null

# Check wp-admin AJAX response differences
curl -s -X POST \
  -d "action=login&user=nonexistent&password=wrong" \
  "https://example.com/wp-admin/admin-ajax.php" 2>/dev/null
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| JSON with different `data.message` for valid vs invalid user | Enumeration via API endpoint | 🟠 **HIGH** |
| Identical JSON response structure | Generic error handling | ✅ **HARDENED** |

### 4.3, Login Response Timing Analysis

```bash
# Measure response time for valid vs invalid usernames
time curl -s -o /dev/null -X POST \
  -d "log=nonexistent_xyz_123&pwd=wrong" \
  "https://example.com/wp-login.php" 2>/dev/null

echo "---"

time curl -s -o /dev/null -X POST \
  -d "log=admin&pwd=wrong" \
  "https://example.com/wp-login.php" 2>/dev/null
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Consistent timing (±50ms) | Timing-based enumeration blocked | ✅ **HARDENED** |
| Consistently faster response for invalid users | Password hash verification skipped, timing leak | 🟡 **MEDIUM** |
| Valid users 100ms+ slower (DB lookup) | Timing side-channel, advanced enumeration | 🔵 **LOW** |

> 💡 **Interpretation:** Always use identical error messages for ALL login failures. The message should not reveal whether the username exists. This is OWASP WSTG-ATHN-09 and a basic security hygiene check.

---

## 5. XML-RPC system.multicall Brute-Force Amplification

The WordPress XML-RPC API supports `system.multicall`, which allows **multiple method calls in a single HTTP request**. Attackers can test 1000+ passwords in one request with responses bundled in one response, this bypasses most IP-based rate limiting.

### 5.1, XML-RPC Endpoint Detection

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Content-Type: %{content_type}" \
  "https://example.com/xmlrpc.php"
```

```bash
# Verify it's actually WordPress XML-RPC
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  "https://example.com/xmlrpc.php"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| HTTP 200 + `Content-Type: text/xml` + list of methods returned | XML-RPC fully enabled | 🟠 **HIGH** (before multicall test) |
| HTTP 405 / 403 / 404 | XML-RPC blocked or disabled | ✅ **HARDENED** |
| HTTP 200 but `Content-Type: text/html` (empty/invalid) | Possibly disabled via .htaccess rewrite | ✅ **HARDENED** |

### 5.2, system.multicall Brute-Force Simulation

```bash
# Create the multicall payload, tests 3 passwords against "admin" in one request
cat > /tmp/wp_multicall.xml << 'XMLEOF'
<?xml version="1.0"?>
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
                        <value><string>password3</string></value>
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
</methodCall>
XMLEOF
```

```bash
# Send the multicall
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -d @/tmp/wp_multicall.xml \
  "https://example.com/xmlrpc.php"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Multiple structured responses returned (one per credential pair) | **Multicall enabled**, attacker can test thousands of passwords in one request | 🔴 **CRITICAL** |
| Fault code returned (e.g., "Incorrect password" for each) | Multicall enabled but no valid credentials | 🔴 **CRITICAL** (multicall itself is the vuln) |
| Single fault response about disabled multicall | Multicall disabled, good | ✅ **HARDENED** |
| HTTP 403 / 405 | Properly blocked | ✅ **HARDENED** |

### 5.3, Massive Payload Size Check

Test how large a multicall the endpoint accepts:

```bash
# Generate a 1000-password multicall payload (theoretical test)
# Actual payloads can be 50KB+
curl -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download} | Time: %{time_total}s" \
  -X POST -H "Content-Type: text/xml" \
  -d @/tmp/large_multicall.xml \
  "https://example.com/xmlrpc.php" 2>/dev/null || \
  echo "Need to generate large payload first"
```

> 💡 **Interpretation:** XML-RPC `system.multicall` is arguably the most dangerous WordPress vulnerability for brute-force attacks. It completely bypasses per-request rate limiting because it's ONE request. If enabled, recommend immediate disable: add `add_filter('xmlrpc_enabled', '__return_false');` to `wp-config.php` or block `xmlrpc.php` at the webserver level. If XML-RPC is needed (Jetpack, mobile apps), recommend blocking `system.multicall` specifically.

---

## 6. XML-RPC Pingback Abuse (DDoS + Port Scan)

The XML-RPC `pingback.ping` method can be abused for DDoS amplification and internal port scanning. An attacker sends a pingback request with a target URL, and WordPress fetches that URL to verify the pingback, making the server act as an unwitting DDoS participant.

### 6.1, Pingback Method Detection

```bash
# Check if pingback methods are available
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  "https://example.com/xmlrpc.php" | grep -i "pingback"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| `pingback.ping` appears in method list | Pingback enabled, can be abused for DDoS and port scan | 🟠 **HIGH** |
| `pingback.extensions.getPingbacks` appears | Extension methods also available | 🟠 **HIGH** |
| No pingback methods | Pingback disabled or blocked | ✅ **HARDENED** |

### 6.2, Pingback DDoS Amplification Test

```bash
# Send a pingback to an external URL to verify amplification
# Use a non-existent target (won't actually ping anything)
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>https://nonexistent-target-xyz123.com/test</string></value></param>
    <param><value><string>https://example.com/hello-world/</string></value></param>
  </params>
</methodCall>' \
  "https://example.com/xmlrpc.php"

# For a real source page, substitute "hello-world" with an actual post slug
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Fault code 0 or 16 (source URL doesn't exist / pingback already registered) | Pingback method is **callable**, server can be used as DDoS amplifier | 🔴 **CRITICAL** |
| Fault code 33 (source URL doesn't exist) | Pingback attempted DNS resolution, possible SSRF risk | 🔴 **CRITICAL** |
| HTTP 403 / method disabled | Pingback disabled | ✅ **HARDENED** |

### 6.3, Internal Port Scanning via Pingback

The pingback method can also be used to probe internal network services by using internal IPs and ports as the source URL:

```bash
# Theoretical test, do NOT run against live targets without authorization
# Replace "127.0.0.1" with target's internal IP range
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://127.0.0.1:8080/</string></value></param>
    <param><value><string>https://example.com/hello-world/</string></value></param>
  </params>
</methodCall>' \
  "https://example.com/xmlrpc.php"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Fault code 0 (pingback registered) | Target internal service responded, port open | 🔴 **CRITICAL** |
| Fault code 16 (source URL doesn't exist) | Internal connection made but source not found, port likely open | 🔴 **CRITICAL** |
| Different fault codes for different ports | Port status can be mapped by fault code differences | 🔴 **CRITICAL** |

> 💡 **Interpretation:** If pingback is enabled, the site can be used as a DDoS amplifier (amplification factor ~1× bandwidth but with legitimate origin IP), an internal network scanner, and a SSRF probe. Recommend disabling XML-RPC entirely or blocking `pingback.ping` specifically. A WordPress server with pingback enabled can be weaponized to attack other sites.

---

## 7. Rate Limiting Detection

Rate limiting prevents attackers from testing large numbers of passwords in a short time. Without it, even weak passwords are eventually cracked.

### 7.1, Sequential Failed Login Attempts

```bash
# Attempt 10 rapid failed logins and observe response
for i in $(seq 1 10); do
  result=$(curl -s -L -i -X POST \
    -d "log=admin&pwd=wrongpassword_$i&wp-submit=Log+In" \
    "https://example.com/wp-login.php" 2>/dev/null | head -30)
  echo "Attempt $i: $(echo "$result" | grep -iE 'HTTP/|retry-after|x-ratelimit|429|too many|limit')"
done
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| All 10 attempts succeed (HTTP 200 with error message) | No rate limiting detected | 🔴 **CRITICAL** |
| `Retry-After:` header appears in response | Rate limiting active, server specifies wait time | 🟢 **GOOD** |
| HTTP 429 (Too Many Requests) | Active rate limiting | 🟢 **GOOD** |
| HTTP 403 after N attempts | IP blocked by firewall / WAF | 🟢 **GOOD** |
| Response times increase progressively | Possible adaptive rate limiting (delay-based) | 🟡 **MEDIUM** |

### 7.2, Rate Limiting Header Inspection

```bash
# Full response headers after multiple failed logins
curl -sI -X POST \
  -d "log=admin&pwd=wrong&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null

# Check for any rate-limiting related headers
curl -sD - -X POST \
  -d "log=admin&pwd=wrong&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null | \
  grep -iE '(retry|ratelimit|429|throttle|limit|block|429|too-many)'
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| `Retry-After: 60` | Server wants client to wait 60s | 🟢 **GOOD** |
| `X-RateLimit-Limit: 5` | Max 5 requests allowed | 🟢 **GOOD** |
| `X-RateLimit-Remaining: 0` | Limit reached | 🟢 **GOOD** |
| `X-RateLimit-Reset: 1700000000` | Unix timestamp when limit resets | 🟢 **GOOD** |
| `CF-*` headers (Cloudflare) | CDN-level rate limiting active | 🟢 **GOOD** |
| No rate-limiting headers | No rate limiting or not exposed in headers | 🔴 **CRITICAL** |

### 7.3, CAPTCHA / Challenge Detection

```bash
# Multiple failed attempts may trigger CAPTCHA
for i in $(seq 1 5); do
  body=$(curl -s -L -X POST \
    -d "log=admin&pwd=wrong$i&wp-submit=Log+In" \
    "https://example.com/wp-login.php" 2>/dev/null)
  echo "$body" | grep -oiE '(captcha|recaptcha|turnstile|challenge|verify|hcaptcha|h-captcha)' | head -3
done
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| reCAPTCHA / hCaptcha / Turnstile elements in HTML | CAPTCHA protection active, strong brute-force defense | 🟢 **GOOD** |
| No CAPTCHA elements after 5+ attempts | No CAPTCHA, brute-force protection gap | 🟠 **HIGH** |

> 💡 **Interpretation:** Rate limiting is the SECOND most important defense after strong passwords. If no rate limiting is detected (all 10 attempts pass with no delay, no headers, no CAPTCHA), an attacker can run unlimited password attempts. This is a CRITICAL finding even if passwords are strong, it's only a matter of time before a breach in a related service exposes a reused password.

---

## 8. Login Lockdown Detection

Login lockdown temporarily or permanently blocks an IP after too many failed attempts. This is different from rate limiting, lockdown actually prevents further attempts.

### 8.1, Lockout After Sustained Failure

```bash
# Run 20-30 rapid failures, then look for lockout
for i in $(seq 1 30); do
  curl -s -o /dev/null -X POST \
    -d "log=admin&pwd=wrong$i&wp-submit=Log+In" \
    "https://example.com/wp-login.php" 2>/dev/null
done

# Now attempt a login, check the response
result=$(curl -s -D - -o /tmp/wp_lockout_test -X POST \
  -d "log=admin&pwd=wrong_final&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null)
echo "$result" | head -20

# Check body for lockout messages
grep -oiE '(locked|blocked|too many|limit exceeded|try again|please wait|banned|suspended)' /tmp/wp_lockout_test | head -5
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| HTTP 200 but page says "locked out" or "too many attempts" | Login lockdown plugin active | 🟢 **GOOD** |
| HTTP 200 but CAPTCHA now required | Adaptive protection triggered | 🟢 **GOOD** |
| HTTP 403 after N attempts | IP blocked at server/firewall level | 🟢 **GOOD** |
| No change after 30 attempts | No lockdown, unlimited brute force | 🔴 **CRITICAL** |

### 8.2, Lockout Duration Test

```bash
# Wait 1 minute then try again
sleep 60
curl -s -D - -o /tmp/wp_lockout_recovery \
  -X POST -d "log=admin&pwd=wrong&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null | head -20
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Lockout message persists after 60s | Lockout duration ≥ 1 minute, effective | 🟢 **GOOD** |
| Lockout lasts > 15 minutes | Permanent or long-duration lockout, strong defense | 🟢 **GOOD (LONG)** |
| Lockout cleared after 60s | Short lockout, still effective but attacker waits briefly | 🟡 **MEDIUM** |

> 💡 **Interpretation:** Login lockdown prevents brute-force attacks by making continued attempts impossible after a threshold. Combined with rate limiting, this forms a strong defense-in-depth. Without lockdown, an attacker can script 24/7 password attempts.

---

## 9. 2FA Presence Detection

Two-Factor Authentication (2FA) is the single strongest defense against credential-based attacks. Even if a password is compromised, the attacker can't log in without the second factor.

### 9.1, Asset Fingerprinting (Common 2FA Plugins)

```bash
# Check for common 2FA plugin assets
# WP 2FA / 2FA plugin
curl -s -o /dev/null -w "%{http_code}" \
  "https://example.com/wp-content/plugins/wp-2fa/admin/js/2fa-settings.js"

# Google Authenticator (Wordfence version)
curl -s -o /dev/null -w "%{http_code}" \
  "https://example.com/wp-content/plugins/wordfence/css/wordfence-2fa.css"

# Google Authenticator (miniorange plugin)
curl -s -o /dev/null -w "%{http_code}" \
  "https://example.com/wp-content/plugins/miniorange-2-factor-authentication/includes/js/mo2fa_login.js"

# Two Factor (WP plugin by Plugin Contributors)
curl -s -o /dev/null -w "%{http_code}" \
  "https://example.com/wp-content/plugins/two-factor/providers/class-two-factor-totp.php"

# Google Authenticator (by miniOrange)
curl -s -o /dev/null -w "%{http_code}" \
  "https://example.com/wp-content/plugins/google-authenticator/google-authenticator.php"

# Jetpack 2FA
curl -s -o /dev/null -w "%{http_code}" \
  "https://example.com/wp-content/plugins/jetpack/modules/sso/jetpack-sso-login.js"

# Duo Security
curl -s -o /dev/null -w "%{http_code}" \
  "https://example.com/wp-content/plugins/duo-wordpress/duo_wordpress.css"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| HTTP 200 on ANY 2FA plugin asset | 2FA plugin detected, additional verification needed | 🟢 **GOOD** |
| HTTP 404 on all | No 2FA plugin detected via asset scan | 🟠 **HIGH** (gap) |
| HTTP 403 on all assets but plugin may use other paths | Possible custom/obscure 2FA, needs login form check | 🟡 **MEDIUM** |

### 9.2, Login Page 2FA Form Detection

```bash
# After successful login (semi-auth), check for 2FA challenge page
# This requires valid credentials but stops at the 2FA challenge
curl -s -L -c /tmp/wp_cookies -b /tmp/wp_cookies \
  -X POST -d "log=valid_user&pwd=valid_password&wp-submit=Log+In" \
  "https://example.com/wp-login.php" | \
  grep -oiE '(2fa|two factor|2 factor|otp|one time|authenticator|authentification code|verification code|duo|passcode|token|security code)' | head -5
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| 2FA / OTP / verification code fields in response | 2FA is active, attacker needs second factor | 🟢 **GOOD** |
| Direct login to wp-admin (redirect) | No 2FA challenge, only password required | 🟠 **HIGH** |

### 9.3, Login Page Source Inspection for 2FA Indicators

```bash
# Scan the login page for 2FA-related HTML classes, IDs or data attributes
curl -s "https://example.com/wp-login.php" | \
  grep -oiE '(two-factor|two_factor|2fa|authenticator|duo|otp-field|login-2fa|wfls|wordfence_2fa)' | head -10

# Check for WebAuthn / FIDO2 support
curl -s "https://example.com/wp-login.php" | \
  grep -oiE '(webauthn|fido|passkey|navigator.credentials|public-key)' | head -5
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| 2FA-related HTML classes or IDs found | 2FA integration present | 🟢 **GOOD** |
| WebAuthn / passkey detection | FIDO2 passwordless auth, strongest protection | 🟢 **GOOD (STRONG)** |
| No 2FA indicators | No 2FA, password-only authentication | 🟠 **HIGH** |

> 💡 **Interpretation:** The absence of 2FA is the #1 finding to upsell. Frame it as: "Your password is your only defense. If it's leaked (data breach, phishing, keylogger), your site is immediately compromised. 2FA adds a second layer that prevents 99% of account takeovers." According to Google/Microsoft research, 2FA blocks over 99.9% of automated attacks.

---

## 10. 'admin' Username Presence

The username "admin" is the most commonly targeted username in brute-force attacks. If it exists, the attacker already knows half the credentials.

### 10.1, Check via Author Enumeration

```bash
# If you can enumerate users, check for "admin"
curl -s "https://example.com/wp-json/wp/v2/users" 2>/dev/null | \
  python3 -c "import sys,json; data=json.load(sys.stdin); [print(f'{u[\"id\"]}: {u[\"name\"]} ({u[\"slug\"]})') for u in data]" 2>/dev/null || \
  curl -s "https://example.com/wp-json/wp/v2/users" | \
  grep -oP '"slug":"[^"]+"' | grep -i admin
```

```bash
# Or via ?author= enumeration
curl -s -I "https://example.com/?author=1" | grep -i "location" | grep -oiP "/author/\K[^/]+"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| `"slug":"admin"` or `/author/admin/` | "admin" username exists, **90% of brute-force targets this** | 🟠 **HIGH** |
| No "admin" user found | Admin renamed or didn't use default | ✅ **HARDENED** |
| "admin" found AND is an administrator (user level) | Default admin with elevated privileges | 🔴 **CRITICAL** |

### 10.2, Check via Login Form

```bash
# If different error messages are returned, test for "admin" existence
result_admin=$(curl -s -L -X POST \
  -d "log=admin&pwd=wrong&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null | \
  grep -oiE '(error|incorrect|invalid)' | head -1)

result_nonexist=$(curl -s -L -X POST \
  -d "log=nonexistent_user_xyz&pwd=wrong&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null | \
  grep -oiE '(error|incorrect|invalid)' | head -1)

echo "Admin response: $result_admin"
echo "Non-existent: $result_nonexist"
```

> 💡 **Interpretation:** The username "admin" is the first guess in every automated brute-force tool. If it exists, the attack is already 50% complete (only the password remains). Recommend renaming the admin username or creating a new admin account with a different name and demoting "admin" to "Subscriber" or deleting it.

---

## 11. Application Passwords Exposure via wp-json

WordPress 5.6+ includes an Application Passwords feature that allows users to generate API-specific passwords. If exposed or improperly configured, these bypass 2FA and can be used for persistent access.

### 11.1, Application Passwords Endpoint

```bash
# Check if the endpoint exists (requires authentication for data)
curl -s -o /dev/null -w "HTTP %{http_code}" \
  "https://example.com/wp-json/wp/v2/users/1/application-passwords"

# Check if the endpoint schema is discoverable
curl -s "https://example.com/wp-json/wp/v2/users/1" | \
  grep -oiE '(application.password|application-passwords|application_password)' | head -5
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| HTTP 401 (Unauthorized) | Endpoint exists but requires auth, normal behavior | 🔵 **LOW** (normal) |
| `application-passwords` in schema | Feature is registered, possible attack surface | 🟡 **MEDIUM** |
| HTTP 404 | Application passwords not available or disabled | ✅ **HARDENED** |
| `application-passwords` disabled via filter | Check `wp-config.php` for `define('WP_APPLICATION_PASSWORDS', false);` | ✅ **HARDENED** |

### 11.2, Application Password Creation via REST API (Auth Required)

```bash
# Only run with valid credentials (semi-auth)
# Test if Application Passwords can be created without 2FA challenge
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "X-WP-Nonce: <valid_nonce>" \
  -d '{"name":"Security Test","app_id":"test"}' \
  -b "wordpress_logged_in_<hash>=<valid_cookie>" \
  "https://example.com/wp-json/wp/v2/users/1/application-passwords"
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| JSON with `uuid` and `password` fields | Application password generated, persistent access created | 🟡 **MEDIUM** (feature works as designed) |
| 2FA challenge required before creation | 2FA applied to application passwords too | 🟢 **GOOD** |
| Disabled via filter | Feature disabled by security policy | ✅ **HARDENED** |

### 11.3, Check for Application Passwords in Auth Headers

```bash
# Test if basic auth with app passwords works
curl -s -I -u "admin:app_password_test" \
  "https://example.com/wp-json/wp/v2/posts" 2>/dev/null | head -10
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| HTTP 200 (posts returned) | Application passwords accepted, bypasses 2FA | 🟠 **HIGH** |
| HTTP 401 | Application passwords disabled or invalid | ✅ **HARDENED** |

> 💡 **Interpretation:** Application Passwords are a legitimate feature for API integration, but they bypass 2FA and, if a user account is compromised, provide persistent access. Best practice: disable if not needed (`define('WP_APPLICATION_PASSWORDS', false);`) or ensure they require 2FA re-verification.

---

## 12. Password Reset Poisoning

WordPress password reset emails contain a link with a key that allows the user to set a new password. If the reset URL structure reveals user information or the reset process doesn't properly validate the requester, this can be exploited.

### 12.1, Reset URL Structure Analysis

```bash
# Check the password reset request page
curl -s "https://example.com/wp-login.php?action=lostpassword"
```

```bash
# Submit a password reset request
curl -s -L -X POST \
  -d "user_login=admin&redirect_to=&wp-submit=Get+New+Password" \
  "https://example.com/wp-login.php?action=lostpassword" 2>/dev/null | \
  grep -oiE '(email sent|check your|link|reset|confirmation|password reset)' | head -5
```

```bash
# Analyze the reset link structure, look at headers for redirect URL clues
curl -sD - -X POST \
  -d "user_login=admin&redirect_to=&wp-submit=Get+New+Password" \
  "https://example.com/wp-login.php?action=lostpassword" 2>/dev/null | \
  grep -iE '(location|setp|reset|rp_key)'
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Username revealed in redirect URL (e.g., `rp_login=admin`) | Username sent in URL, potential info leak | 🟠 **HIGH** |
| No user-specific info in URL parameters | Properly sanitized | ✅ **HARDENED** |
| `key` parameter visible in URL | Reset key exposed in URL (logged by proxies, referrers) | 🟡 **MEDIUM** |
| Different response for valid vs invalid username | User enumeration via password reset | 🟠 **HIGH** |

### 12.2, Reset Confirmation Message Analysis

```bash
# Compare reset messages for existing vs non-existing users
echo "=== Existing user (admin) ==="
curl -s -L -X POST \
  -d "user_login=admin&redirect_to=&wp-submit=Get+New+Password" \
  "https://example.com/wp-login.php?action=lostpassword" 2>/dev/null | \
  grep -oiE '(email|sent|check|instructions|confirm|not found|does not exist|unknown)' | head -3

echo "=== Non-existent user ==="
curl -s -L -X POST \
  -d "user_login=nonexistent_user_xyz&redirect_to=&wp-submit=Get+New+Password" \
  "https://example.com/wp-login.php?action=lostpassword" 2>/dev/null | \
  grep -oiE '(email|sent|check|instructions|confirm|not found|does not exist|unknown)' | head -3
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Same message for both (e.g., "Check your email") | Proper, reveals no user info | ✅ **HARDENED** |
| Different messages (e.g., "User not found" vs "Email sent") | User enumeration via password reset | 🟠 **HIGH** |

### 12.3, Reset Key Exposure via Referrer

```bash
# Check if the reset page loads external resources (analytics, fonts) that leak the reset URL
curl -s "https://example.com/wp-login.php?action=rp&key=test123&login=admin" | \
  grep -oiE '(google-analytics|gtag|facebook|pixel|hotjar|clarity|analytics)' | head -5
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| External analytics loaded on reset page | Reset URL (with key) could be leaked via Referer header | 🟡 **MEDIUM** |
| No external resources on reset page | Reset key stays private | ✅ **HARDENED** |

> 💡 **Interpretation:** Password reset is a common attack vector. If the reset process reveals whether a user exists, attackers can build a target list. If analytics track the reset page, the key could be leaked to third parties. OWASP WSTG-ATHN-08 covers this.

---

## 13. Login Page SSL Enforcement

Login credentials must always be transmitted over encrypted connections. If the login page is accessible over HTTP or downgrades from HTTPS to HTTP, credentials can be intercepted.

### 13.1, HTTP to HTTPS Redirect

```bash
# Check if HTTP login redirects to HTTPS
curl -sI "http://example.com/wp-login.php" | grep -i location

# Check the full redirect chain (-L follows redirects; -D shows headers)
curl -sD - "http://example.com/wp-login.php" -o /dev/null 2>/dev/null | \
  grep -iE '(location|http/)'
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| `Location: https://example.com/wp-login.php` | HTTP → HTTPS redirect present | ✅ **HARDENED** |
| HTTP 200 (login form served over HTTP) | Login page accessible over HTTP, credentials sent in plaintext | 🔴 **CRITICAL** |
| `Location: http://example.com/wp-login.php` | HTTPS → HTTP downgrade, critical misconfig | 🔴 **CRITICAL** |

### 13.2, Login Form Action URL

```bash
# Confirm the form submits to HTTPS
curl -s "http://example.com/wp-login.php" | \
  grep -oiP '<form[^>]*action="\K[^"]+' | head -3
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| `https://example.com/wp-login.php` (HTTPS action URL) | Login form submits to secure endpoint | ✅ **HARDENED** |
| `http://example.com/wp-login.php` | Form submits over HTTP, credentials intercepted | 🔴 **CRITICAL** |
| Relative path `wp-login.php` | Form submits to current protocol, safe only if forced HTTPS | 🟡 **MEDIUM** |

### 13.3, HTTPS-Only wp-admin Cookie (secure flag)

```bash
# Check for secure cookie attribute on wp-admin
curl -sI -X POST \
  -d "log=test&pwd=test&wp-submit=Log+In" \
  "https://example.com/wp-login.php" 2>/dev/null | \
  grep -i 'set-cookie' | grep -oiE 'secure|httponly|samesite'

# Also check on wp-admin redirect
curl -sI "https://example.com/wp-admin/" | \
  grep -i 'set-cookie' | grep -oiE 'secure|httponly|samesite'
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Cookies have `Secure` and `HttpOnly` flags | Properly configured | ✅ **HARDENED** |
| Cookies missing `Secure` flag | Auth cookies not marked Secure, can be transmitted over HTTP | 🟠 **HIGH** |
| Cookies missing `HttpOnly` flag | Cookies accessible to JavaScript, XSS can steal session | 🟠 **HIGH** |
| Cookies missing `SameSite` flag | CSRF protection gap on cookie level | 🟡 **MEDIUM** |

> 💡 **Interpretation:** If the login page serves over HTTP or the form action is HTTP, credentials are transmitted in plaintext. This is an immediate CRITICAL finding. Even if the current page is HTTPS, confirm the login form's action attribute goes to HTTPS. The HSTS header (covered in checklist 01-security-headers.md) should also be present to enforce HTTPS for all future requests.

---

## 14. Login Lockout Messages (Generic vs Specific)

The information displayed on lockout pages can aid attackers by revealing lockout duration, number of allowed attempts, or even triggering user enumeration.

### 14.1, Lockout Page Content Analysis

```bash
# After triggering lockout (see section 8), capture the lockout page content
grep -oiE '(too many|attempts|minutes|seconds|hours|IP|locked|blocked|try again|wait)' \
  /tmp/wp_lockout_test | head -10

# Check if the message reveals the lockout duration
grep -oiE '[0-9]+ (minute|second|hour|attempt)' /tmp/wp_lockout_test | head -5
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Generic message: "Too many attempts. Please try again later." | Secure, no specifics | ✅ **HARDENED** |
| "Too many attempts for user 'admin'. Try again in 15 minutes." | Username AND duration revealed, aids attacker planning | 🟠 **HIGH** |
| "Too many attempts from IP 192.168.1.1. Blocked for 30 minutes." | IP address exposed, internal network info leak | 🟠 **HIGH** |
| "5 failed attempts. 3 more allowed." | Attacker knows exactly how many tries remain | 🟡 **MEDIUM** |
| No lockout message (HTTP 403 / 404 instead) | Locked out but no information given | ✅ **HARDENED** |

### 14.2, Lockout Message Enumeration

```bash
# Lockout messages could differ by account, check for user enumeration
# Only possible if you can trigger lockout per user
```

| Expected response | What it means | Severity |
|-------------------|---------------|----------|
| Same lockout message regardless of user | No enumeration via lockout | ✅ **HARDENED** |
| Different lockout message for admin vs subscriber | User enumeration via lockout state | 🟠 **HIGH** |

> 💡 **Interpretation:** Lockout messages should be generic and reveal nothing about: which user triggered the lockout, how many attempts remain, the specific duration, or the user's IP/role. Ideally, the lockout page looks identical regardless of who or what triggered it. Best practice: redirect to a generic error page without any lockout-specific copy.

---

## Quick-Reference Summary Table

| # | Check | Curl / Test Target | Severity if Vulnerable |
|---|-------|--------------------|------------------------|
| 1.1 | Login page detection | `/wp-login.php` | 🔵 LOW (baseline) |
| 1.2 | Custom login URL discovery | `robots.txt`, sitemap, common paths | 🟡 MEDIUM |
| 2.1 | User enumeration (author param) | `/?author=1` ... `/?author=10` | 🔴 **CRITICAL** |
| 2.2 | Author archive access | `/author/admin/` | 🟠 HIGH |
| 3.1 | REST API users endpoint | `/wp-json/wp/v2/users` | 🔴 **CRITICAL** |
| 3.2 | REST API single user | `/wp-json/wp/v2/users/1` | 🟠 HIGH |
| 4.1 | Login error message diff | POST to `wp-login.php` with valid vs invalid user | 🟠 HIGH |
| 4.3 | Login timing analysis | Measure response times for valid vs invalid user | 🔵 LOW |
| 5 | XML-RPC enabled | `/xmlrpc.php` + `system.listMethods` | 🟠 HIGH |
| 5.2 | system.multicall | POST multicall with multiple passwords | 🔴 **CRITICAL** |
| 6 | Pingback DDoS/SSRF | POST `pingback.ping` to XML-RPC | 🔴 **CRITICAL** |
| 7 | Rate limiting | 10 rapid failed logins, check headers | 🔴 **CRITICAL** if absent |
| 8 | Login lockdown | 30 rapid failed logins, check lockout | 🔴 **CRITICAL** if absent |
| 9 | 2FA presence | Check plugin assets + login page | 🟠 HIGH if absent |
| 10 | 'admin' username | Author enumeration or REST API | 🟠 HIGH |
| 11 | Application passwords | REST API check | 🟡 MEDIUM |
| 12 | Password reset poisoning | Reset request message analysis | 🟠 HIGH |
| 13 | SSL enforcement | HTTP login page/form action | 🔴 **CRITICAL** |
| 14 | Lockout message specificity | Lockout page content analysis | 🟠 HIGH |

---

## 🔍 Quick-Start Scan Script: `wp-brute-force-audit.sh`

Save the following as a complete Bash script that checks most of the items in this checklist:

```bash
#!/usr/bin/env bash
#===============================================================================
# WordPress Brute Force & Login Protection Audit
# Remote scan, no login required (some semi-auth if credentials provided)
# Usage: ./wp-brute-force-audit.sh https://target-site.com
#===============================================================================

set -euo pipefail

RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

TARGET="${1%/}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 https://target-site.com"
  exit 1
fi

SUMMARY_CRIT=0
SUMMARY_HIGH=0
SUMMARY_MED=0
SUMMARY_LOW=0

log_critical() { echo -e "${RED}[CRITICAL]${NC} $1"; ((SUMMARY_CRIT++)); }
log_high()    { echo -e "${ORANGE}[HIGH]${NC} $1";     ((SUMMARY_HIGH++)); }
log_medium()  { echo -e "${YELLOW}[MEDIUM]${NC} $1";   ((SUMMARY_MED++)); }
log_low()     { echo -e "${BLUE}[LOW]${NC} $1";        ((SUMMARY_LOW++)); }
log_pass()    { echo -e "${GREEN}[OK]${NC} $1"; }

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  WordPress Brute Force & Login Audit, $TARGET"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# --- 1. Login page detection ---
echo "─── [1] Login Page Detection ───"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/wp-login.php" 2>/dev/null)
if [[ "$CODE" == "200" ]]; then
  log_low "Login page accessible at /wp-login.php (expected)"
else
  log_medium "Login page not at default path (HTTP $CODE), custom URL? Check manually."
fi

# --- 2. Author enumeration ---
echo "─── [2] User Enumeration (?author=N) ───"
for i in 1 2 3; do
  redirect=$(curl -sI "$TARGET/?author=$i" 2>/dev/null | grep -i "location" | sed 's/Location: //I' | tr -d '\r')
  if echo "$redirect" | grep -qP "/author/"; then
    username=$(echo "$redirect" | grep -oP "/author/\K[^/]+")
    log_critical "Author $i → $username (username leaked)"
  fi
done

# --- 3. REST API users ---
echo "─── [3] REST API Users ───"
USERS_RESPONSE=$(curl -s "$TARGET/wp-json/wp/v2/users" 2>/dev/null)
if echo "$USERS_RESPONSE" | grep -q '"slug"'; then
  log_critical "REST API exposes user list at /wp-json/wp/v2/users"
  echo "$USERS_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f'  User {u[\"id\"]}: {u[\"name\"]} (slug: {u[\"slug\"]})') for u in d]" 2>/dev/null || true
elif echo "$USERS_RESPONSE" | grep -q "rest_user_cannot_list"; then
  log_pass "REST API user list properly restricted"
elif echo "$USERS_RESPONSE" | grep -q "rest_no_route"; then
  log_pass "REST API disabled"
else
  log_medium "REST API returned unexpected response, investigate manually"
fi

# --- 4. XML-RPC ---
echo "─── [4] XML-RPC ───"
XMLRPC_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/xmlrpc.php" 2>/dev/null)
if [[ "$XMLRPC_CODE" == "200" ]]; then
  METHODS=$(curl -s -X POST -H "Content-Type: text/xml" \
    -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
    "$TARGET/xmlrpc.php" 2>/dev/null)
  if echo "$METHODS" | grep -q "system.multicall"; then
    log_critical "XML-RPC system.multicall enabled, brute-force amplification possible"
  else
    log_high "XML-RPC enabled but multicall not listed, verify manually"
  fi
  if echo "$METHODS" | grep -q "pingback.ping"; then
    log_critical "XML-RPC pingback.ping enabled, DDoS amplification + SSRF possible"
  fi
else
  log_pass "XML-RPC endpoint blocked (HTTP $XMLRPC_CODE)"
fi

# --- 5. Rate limiting test ---
echo "─── [5] Rate Limiting ───"
RATE_LIMITED=0
for i in $(seq 1 10); do
  response=$(curl -sD - -o /dev/null -X POST \
    -d "log=admin&pwd=wrong$i&wp-submit=Log+In" \
    "$TARGET/wp-login.php" 2>/dev/null | \
    grep -iE '(retry-after|x-ratelimit|429|too many|locked|blocked|cf-))')
  if [[ -n "$response" ]]; then
    RATE_LIMITED=1
    echo "  Rate limiting detected at attempt $i: $response"
    break
  fi
done
if [[ "$RATE_LIMITED" -eq 1 ]]; then
  log_pass "Rate limiting detected"
else
  log_critical "No rate limiting detected, 10 rapid attempts all accepted"
fi

# --- 6. Login error messages ---
echo "─── [6] Login Error Messages ───"
MSG_ADMIN=$(curl -s -L -X POST \
  -d "log=admin&pwd=wrong&wp-submit=Log+In" \
  "$TARGET/wp-login.php" 2>/dev/null | \
  grep -oiP '(error|incorrect|invalid)[^<]*' | head -1)

MSG_FAKE=$(curl -s -L -X POST \
  -d "log=nonexistent_user_xyz_$RANDOM&pwd=wrong&wp-submit=Log+In" \
  "$TARGET/wp-login.php" 2>/dev/null | \
  grep -oiP '(error|incorrect|invalid)[^<]*' | head -1)

if [[ "$MSG_ADMIN" == "$MSG_FAKE" ]]; then
  log_pass "Login error messages are identical, no user enumeration"
else
  log_high "Login error messages differ by user, user enumeration via login form"
  echo "  'admin' response: $MSG_ADMIN"
  echo "  Fake user response: $MSG_FAKE"
fi

# --- 7. 2FA detection ---
echo "─── [7] 2FA Detection ───"
TFA_FOUND=0
for asset in \
  "wp-content/plugins/wp-2fa/admin/js/2fa-settings.js" \
  "wp-content/plugins/wordfence/css/wordfence-2fa.css" \
  "wp-content/plugins/miniorange-2-factor-authentication/includes/js/mo2fa_login.js" \
  "wp-content/plugins/two-factor/providers/class-two-factor-totp.php" \
  "wp-content/plugins/google-authenticator/google-authenticator.php" \
  "wp-content/plugins/jetpack/modules/sso/jetpack-sso-login.js" \
  "wp-content/plugins/duo-wordpress/duo_wordpress.css"; do
  if [[ $(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$asset" 2>/dev/null) == "200" ]]; then
    echo "  ✓ 2FA plugin asset found: $asset"
    TFA_FOUND=1
    log_pass "2FA plugin detected, verify it is enforced for all users"
    break
  fi
done
if [[ "$TFA_FOUND" -eq 0 ]]; then
  log_high "No 2FA plugin detected, password-only authentication"
fi

# --- 8. Login page SSL ---
echo "─── [8] SSL Enforcement ───"
HTTP_URL=$(echo "$TARGET" | sed 's/https:/http:/')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HTTP_URL/wp-login.php" 2>/dev/null)
HTTP_REDIRECT=$(curl -sI "$HTTP_URL/wp-login.php" 2>/dev/null | grep -i "location" | tr -d '\r')
if [[ "$HTTP_CODE" == "200" ]]; then
  log_critical "Login page accessible over HTTP, credentials in plaintext"
elif echo "$HTTP_REDIRECT" | grep -qP "^https://"; then
  log_pass "HTTP login redirects to HTTPS"
else
  log_medium "HTTP login returned HTTP $HTTP_CODE, investigate"
fi

# --- Summary ---
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  AUDIT SUMMARY"
echo "═══════════════════════════════════════════════════════════════"
echo "  🔴 Critical: $SUMMARY_CRIT"
echo "  🟠 High:     $SUMMARY_HIGH"
echo "  🟡 Medium:   $SUMMARY_MED"
echo "  🔵 Low:      $SUMMARY_LOW"
echo "───────────────────────────────────────────────────────────────"
if [[ "$SUMMARY_CRIT" -gt 0 ]] || [[ "$SUMMARY_HIGH" -gt 0 ]]; then
  echo "  ⚠️  Actionable findings detected, review and remediate."
else
  echo "  ✅ No critical or high findings, good security posture."
fi
echo "═══════════════════════════════════════════════════════════════"
echo ""
```

---

## Summary of Tests & Severity

| Severity | Count | Typical Findings |
|----------|-------|-----------------|
| 🔴 **CRITICAL** | 7 | User enumeration, REST API user leak, XML-RPC multicall, pingback DDoS, no rate limiting, no lockdown, HTTP login |
| 🟠 **HIGH** | 5 | No 2FA, 'admin' username, login message diff, reset poisoning, lockout message specificity |
| 🟡 **MEDIUM** | 2 | Custom login URL exposed, Application Passwords, timing diff |
| 🔵 **LOW** | 1 | Default login path exposed |

> **Sales Upsell:** The top 3 most impactful fixes to recommend:
> 1. **2FA** (blocks 99.9% of automated attacks, strongest single defense)
> 2. **Rate limiting + login lockdown** (prevents brute-force at scale)
> 3. **Disable XML-RPC or block system.multicall** (removes the #1 brute-force amplification vector)
