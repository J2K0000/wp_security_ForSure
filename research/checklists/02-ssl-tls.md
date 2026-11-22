# SSL/TLS Audit Checklist, WordPress Sites (Remote)

> **Scope:** All checks are performed remotely, without admin credentials or server shell access.
> **Target:** `https://example.com`, replace with the actual site domain in every command.
> **Format:** Each section contains one or more checks, the exact command(s) to run, what to look for (pass/fail criteria), and a severity rating.

---

## Table of Contents

1. [Certificate Validation](#1-certificate-validation)
2. [Protocol Versions](#2-protocol-versions)
3. [Cipher Suites](#3-cipher-suites)
4. [HSTS (HTTP Strict Transport Security)](#4-hsts-http-strict-transport-security)
5. [Mixed Content Detection](#5-mixed-content-detection)
6. [OCSP Stapling](#6-ocsp-stapling)
7. [Quick Reference, All Commands in One Place](#7-quick-reference)

---

## 1. Certificate Validation

### 1.1 Certificate Expiration, Issuer & Subject

Check how many days until expiry, who issued the cert, and the subject (common name).

```bash
# Full certificate dump, extract expiry, issuer, subject
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -dates -issuer -subject

# More precise: days until expiration
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -enddate \
  | cut -d= -f2 \
  | xargs -I{} date -d "{}" +%s \
  | xargs -I{} sh -c 'echo "Expires on: $(date -d @$1); days left: $(( ($1 - $(date +%s)) / 86400 ))"' -- {}
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| Expiration | ≥ 30 days remaining | ✅ Pass | 🔴 Critical if < 7 days |
| Issuer | Recognised public CA (Let's Encrypt, DigiCert, Sectigo, Cloudflare, etc.) | ✅ Pass | 🔴 High if self-signed |
| Subject CN | Matches `example.com` | ✅ Pass | 🔴 Critical if mismatch |

**Severity:**
- **🔴 Critical:** Certificate expired, expiring within 7 days, CN mismatch, or self-signed
- **🟠 High:** Expiring within 30 days, unknown/untrusted issuer
- **🟡 Medium:** Expiring within 60 days
- **🟢 Low:** > 60 days, trusted issuer, CN matches

---

### 1.2 Subject Alternative Names (SAN)

The CN is mostly deprecated; modern browsers rely on SAN entries. Check that the domain is listed.

```bash
# Extract SAN entries
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| SAN coverage | `example.com` and `www.example.com` present | ✅ Pass | 🔴 Critical if missing |
| Extra domains | Any unexpected domains listed | ⚠️ Investigate | 🟡 Medium |
| Too many SANs | > 100 SAN entries (potential DoS risk) | ⚠️ Flag | 🟡 Medium |

**Severity:**
- **🔴 Critical:** Target domain absent from SAN list
- **🟡 Medium:** Unexpected domains present, excessive SAN count

---

### 1.3 Wildcard Certificate Check

```bash
# Show the CN and SAN to detect wildcard certificates
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName | grep -i 'DNS:'
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| Wildcard present | `DNS:*.example.com` | Information | 🟢 Low |
| Second-level wildcard | `DNS:*.com` or other top-level wildcard | ❌ Fail | 🔴 Critical |
| Wildcard on shared host | `*.sharedhosting.com` serving multiple customers | ⚠️ Flag | 🟡 Medium |

**Severity:**
- **🔴 Critical:** Top-level wildcard (`*.com`, `*.net`)
- **🟡 Medium:** Wildcard shared across unrelated domains
- **🟢 Low:** Single-domain wildcard (`*.example.com`), acceptable but audit records it

---

### 1.4 Certificate Chain Completeness

```bash
# Show the full certificate chain
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null \
  | openssl pkcs7 -print_certs -noout 2>/dev/null

# Alternative, count chain depth
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | grep -c '^[0-9] s:'
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| Chain depth | 2-3 certificates (leaf + intermediate(s) + root) | ✅ Pass | 🟡 Medium if incomplete |
| Missing intermediate | Only 1 certificate (leaf only) | ❌ Fail | 🔴 High |

**Why it matters:** Browsers may show errors if the server doesn't send intermediate certificates, even if the leaf is valid.

---

## 2. Protocol Versions

### 2.1 TLS 1.3 (best)

```bash
openssl s_client -connect example.com:443 -tls1_3 -servername example.com < /dev/null 2>&1
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| TLS 1.3 supported | `New, TLSv1.3` in output | ✅ Pass | 🟢 Low (bonus) |
| Handshake success | `Certificate chain` appears | ✅ Supported | n/a |

---

### 2.2 TLS 1.2 (current baseline)

```bash
openssl s_client -connect example.com:443 -tls1_2 -servername example.com < /dev/null 2>&1
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| TLS 1.2 supported | `New, TLSv1.2` or handshake succeeds | ✅ Pass | ✅ Mandatory |
| Not supported | `handshake failure` or `SSL_ERROR_PROTOCOL_VERSION` | ❌ Fail | 🔴 Critical |

---

### 2.3 TLS 1.1 (deprecated)

```bash
openssl s_client -connect example.com:443 -tls1_1 -servername example.com < /dev/null 2>&1
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| TLS 1.1 enabled | Handshake succeeds | ❌ Fail | 🟠 High |
| TLS 1.1 disabled | `handshake failure` or connection refused | ✅ Pass | n/a |

---

### 2.4 TLS 1.0 (obsolete)

```bash
openssl s_client -connect example.com:443 -tls1 -servername example.com < /dev/null 2>&1
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| TLS 1.0 enabled | Handshake succeeds | ❌ Fail | 🔴 Critical |
| TLS 1.0 disabled | `handshake failure` or connection refused | ✅ Pass | n/a |

---

### 2.5 SSL 3.0 / SSL 2.0 (insecure, legacy check)

```bash
# SSL 3.0
openssl s_client -connect example.com:443 -ssl3 -servername example.com < /dev/null 2>&1

# SSL 2.0
openssl s_client -connect example.com:443 -ssl2 -servername example.com < /dev/null 2>&1
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| SSL 3.0 enabled | Handshake succeeds (rare in 2024+) | ❌ Fail | 🔴 Critical |
| SSL 2.0 enabled | Handshake succeeds (extremely rare) | ❌ Fail | 🔴 Critical |

> **Note:** Modern OpenSSL builds may have SSL 2/3 support compiled out. If you get `unknown option` or `ssl2 is not supported`, that's acceptable, the server can't negotiate them.

---

### Protocol Version Summary Table

| Protocol | Status | Severity if Enabled | Minimum Requirement |
|---|---|---|---|
| TLS 1.3 | ✅ Modern | 🟢 Low (bonus) | Strongly recommended |
| TLS 1.2 | ✅ Baseline | ✅ Mandatory | **Required** |
| TLS 1.1 | ❌ Deprecated (RFC 8996) | 🟠 High | Must disable |
| TLS 1.0 | ❌ Deprecated (RFC 8996) | 🔴 Critical | Must disable |
| SSL 3.0 | ❌ Insecure (POODLE) | 🔴 Critical | Must disable |
| SSL 2.0 | ❌ Insecure | 🔴 Critical | Must disable |

---

## 3. Cipher Suites

### 3.1 List All Supported Ciphers

```bash
# Enumerate all ciphers the server accepts (TLS 1.2)
echo | openssl s_client -connect example.com:443 -cipher 'ALL:COMPLEMENTOFALL' -servername example.com 2>&1 \
  | grep -E '^   [A-Z0-9]|Cipher is '

# For TLS 1.3 (ciphers are negotiated differently)
openssl s_client -connect example.com:443 -tls1_3 -servername example.com < /dev/null 2>&1 \
  | grep -i 'cipher'
```

> **Tip:** For a comprehensive cipher scan, use `sslscan` or `testssl.sh` if available:
> ```bash
> # Install & run sslscan (lightweight)
> sslscan --no-colour example.com:443 2>/dev/null
>
> # Or use testssl.sh for the most thorough test
> ./testssl.sh --quiet --cipher-per-proto example.com
> ```

### 3.2 Weak Cipher Detection

```bash
# Test for NULL ciphers (no encryption)
echo | openssl s_client -connect example.com:443 -cipher 'NULL' -servername example.com 2>&1

# Test for ANON/anon ciphers (no authentication)
echo | openssl s_client -connect example.com:443 -cipher 'aNULL' -servername example.com 2>&1

# Test for EXPORT ciphers (40-bit, broken in the 90s)
echo | openssl s_client -connect example.com:443 -cipher 'EXPORT' -servername example.com 2>&1

# Test for RC4 (broken, biases in first bytes)
echo | openssl s_client -connect example.com:443 -cipher 'RC4' -servername example.com 2>&1

# Test for DES/3DES (56/112-bit, brute-forceable)
echo | openssl s_client -connect example.com:443 -cipher 'DES' -servername example.com 2>&1
```

| Cipher Group | Risk | What success means | Severity |
|---|---|---|---|
| NULL | No encryption | ❌ Fail | 🔴 Critical |
| aNULL (anonymous) | No authentication | ❌ Fail | 🔴 Critical |
| EXPORT (40-bit) | Trivially breakable | ❌ Fail | 🔴 Critical |
| RC4 | Biased output, known attacks | ❌ Fail | 🔴 High |
| DES / 3DES | 56-bit / 112-bit effective | ❌ Fail | 🟠 High |
| SEED / IDEA | 128-bit, outdated | ❌ Fail | 🟡 Medium |

### 3.3 Strong Cipher Requirements (TLS 1.2)

TLS 1.2 cipher suites should use **AEAD** (Authenticated Encryption with Associated Data):

```bash
# Check for ECDHE + AES-GCM (strong, recommended)
echo | openssl s_client -connect example.com:443 -cipher 'ECDHE+AESGCM' -servername example.com 2>&1 \
  | grep -i 'Cipher is'

# Check for DHE + AES-GCM (strong)
echo | openssl s_client -connect example.com:443 -cipher 'DHE+AESGCM' -servername example.com 2>&1 \
  | grep -i 'Cipher is'

# Check for CBC mode ciphers (potential Lucky13, weaker than GCM)
echo | openssl s_client -connect example.com:443 -cipher 'CBC' -servername example.com 2>&1 \
  | grep -i 'Cipher is'
```

| Cipher | Recommendation | Severity |
|---|---|---|
| `TLS_AES_128_GCM_SHA256` (TLS 1.3) | ✅ Strong | 🟢 Low |
| `TLS_AES_256_GCM_SHA384` (TLS 1.3) | ✅ Strong | 🟢 Low |
| `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3) | ✅ Strong | 🟢 Low |
| `ECDHE-ECDSA-AES128-GCM-SHA256` | ✅ Strong | 🟢 Low |
| `ECDHE-RSA-AES128-GCM-SHA256` | ✅ Strong | 🟢 Low |
| `ECDHE-ECDSA-AES256-GCM-SHA384` | ✅ Strong | 🟢 Low |
| `ECDHE-RSA-AES256-GCM-SHA384` | ✅ Strong | 🟢 Low |
| `ECDHE-ECDSA-CHACHA20-POLY1305` | ✅ Strong | 🟢 Low |
| `ECDHE-RSA-CHACHA20-POLY1305` | ✅ Strong | 🟢 Low |
| `DHE-RSA-AES128-GCM-SHA256` | ⚠️ Acceptable (slow key exchange) | 🟢 Low |
| `ECDHE-*AES128-SHA` (CBC) | ❌ Weak | 🟡 Medium |
| `ECDHE-*AES256-SHA` (CBC) | ❌ Weak | 🟡 Medium |
| `AES128-GCM-SHA256` (static RSA) | ❌ No PFS | 🟠 High |
| `AES256-GCM-SHA384` (static RSA) | ❌ No PFS | 🟠 High |
| Any RC4/DES/3DES/NULL/EXPORT | ❌ Insecure | 🔴 Critical |

### 3.4 Perfect Forward Secrecy (PFS)

```bash
# Test if ECDHE is supported
echo | openssl s_client -connect example.com:443 -cipher 'ECDHE' -servername example.com 2>&1 \
  | grep -i 'Cipher is'

# Test if DHE is supported (also provides PFS)
echo | openssl s_client -connect example.com:443 -cipher 'DHE' -servername example.com 2>&1 \
  | grep -i 'Cipher is'
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| ECDHE cipher negotiated | `ECDHE` in cipher name | ✅ Pass | ✅ Recommended |
| DHE cipher negotiated | `DHE` in cipher name | ✅ Pass | ⚠️ Acceptable (slower) |
| Static RSA only (no PFS) | `AES128-GCM-SHA256` (no ECDHE/DHE prefix) | ❌ Fail | 🟠 High |

---

## 4. HSTS (HTTP Strict Transport Security)

### 4.1 HSTS Header Presence & Value

```bash
# Fetch headers (follow redirects)
curl -sI -L https://example.com | grep -i 'strict-transport-security'

# Fetch headers without following redirects (HSTS is sometimes on HTTPS only)
curl -sI https://example.com | grep -i 'strict-transport-security'

# Check HTTP response too (should redirect to HTTPS)
curl -sI http://example.com | grep -i 'strict-transport-security'
curl -sI http://example.com | head -20
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| Header present | `strict-transport-security:` in response | ✅ Pass | ✅ Required |
| Header missing | No HSTS header | ❌ Fail | 🟠 High |
| Only on some pages | Inconsistent header delivery | ⚠️ Partial | 🟡 Medium |

### 4.2 Max-Age Directive

```bash
curl -sI -L https://example.com | grep -i 'strict-transport-security' \
  | sed 's/.*max-age=//i; s/;.*//'
```

| max-age value | Verdict | Severity |
|---|---|---|
| `0` | HSTS disabled (only for testing/rollback) | ❌ Fail | 🟠 High |
| `< 86400` (1 day) | Too low | ❌ Fail | 🟡 Medium |
| `86400` – `2592000` (1–30 days) | Low | ⚠️ Flag | 🟡 Medium |
| `2592000` – `31536000` (1–12 months) | Acceptable | ✅ Pass | 🟡 Low |
| `31536000` (1 year) or more | Recommended | ✅ Pass | 🟢 Low |
| `63072000` (2 years, max recommended by HSTS spec) | Optimal | ✅ Pass | 🟢 Low |

### 4.3 includeSubDomains Directive

```bash
curl -sI -L https://example.com | grep -i 'strict-transport-security' \
  | grep -o 'includeSubDomains'
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| `includeSubDomains` present | `includeSubDomains` in header | ✅ Pass | ✅ Recommended |
| `includeSubDomains` missing | Not present | ⚠️ Flag | 🟡 Medium |

### 4.4 preload Directive

```bash
curl -sI -L https://example.com | grep -i 'strict-transport-security' \
  | grep -o 'preload'
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| `preload` present | `preload` in header | ✅ Pass | ✅ Recommended |
| `preload` missing | Not present | ⚠️ Flag | 🟢 Low |
| Submitted to HSTS preload list | Check at [hstspreload.org](https://hstspreload.org/?domain=example.com) | ✅ Pass if listed | 🟢 Low |

### 4.5 Full HSTS Header Example

```bash
# Show complete HSTS header
curl -sI -L https://example.com | grep -i 'strict-transport-security'
```

Expected format (good):
```
strict-transport-security: max-age=63072000; includeSubDomains; preload
```

---

## 5. Mixed Content Detection

### 5.1 Scan WordPress Page for Mixed Content

```bash
# Fetch the homepage and find insecure (http://) resource references
curl -sL https://example.com \
  | grep -oE 'src="http://[^"]*"|href="http://[^"]*"|srcset="http://[^"]*"|content="http://[^"]*"' \
  | sort -u
```

```bash
# Check for mixed content in wp-content (common WordPress sources)
curl -sL https://example.com \
  | grep -oE 'http://[^"]*\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|webm)"' \
  | sort -u
```

### 5.2 Detect Hardcoded HTTP URLs in WordPress Source

```bash
# Check if the site's canonical URL uses HTTPS properly
curl -sL https://example.com \
  | grep -i 'rel="canonical"' \
  | grep -oE 'https?://[^"]+'

# Check og:url meta tag
curl -sL https://example.com \
  | grep -i 'og:url' \
  | grep -oE 'https?://[^"]+'
```

### 5.3 Active Mixed Content Check (Key Pages)

```bash
# Test critical WordPress URLs for mixed content
for path in / /wp-admin/ /wp-login.php /wp-content/; do
  echo "=== $path ==="
  curl -sL "https://example.com$path" \
    | grep -oE 'http://[^"]*\.(js|css|png|jpg|jpeg|gif|svg)' \
    | sort -u
done
```

### 5.4 Passive Mixed Content Using Content-Security-Policy

```bash
# Check if CSP has upgrade-insecure-requests (mitigates mixed content)
curl -sI -L https://example.com | grep -i 'content-security-policy'
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| `upgrade-insecure-requests` present | CSP header contains this directive | ✅ Pass | 🟢 Low |
| No CSP | No Content-Security-Policy header | ⚠️ Flag | 🟡 Medium |
| No `upgrade-insecure-requests` | CSP exists but missing this directive | ⚠️ Flag | 🟡 Medium |
| Hardcoded `http://` resources found | Insecure resource URLs on HTTPS page | ❌ Fail | 🟠 High |
| Mixed content blocking (active) | Scripts/styles loaded over HTTP | ❌ Fail | 🔴 High (may break site) |
| Mixed content (passive/image) | Images loaded over HTTP | ❌ Fail | 🟡 Medium |

**Severity:**
- **🔴 Critical:** HTTPS page loads active mixed content (scripts, stylesheets, iframes) over HTTP, browser blocks them → site breakage
- **🟠 High:** Any hardcoded `http://` resource on HTTPS page
- **🟡 Medium:** Passive mixed content (images, videos) over HTTP, browser loads but shows warning
- **🟢 Low:** `upgrade-insecure-requests` CSP present, no hardcoded HTTP resources found

---

## 6. OCSP Stapling

### 6.1 Check if OCSP Stapling Is Enabled

```bash
# Full OCSP stapling check
echo | openssl s_client -connect example.com:443 -servername example.com -status 2>&1 \
  | grep -A 20 'OCSP response'
```

```bash
# Quick check, did server send OCSP response?
echo | openssl s_client -connect example.com:443 -servername example.com -status 2>&1 \
  | grep -E 'OCSP Response Status|OCSP Response'
```

| Output | What it means | Verdict | Severity |
|---|---|---|---|
| `OCSP Response Status: successful (0x0)` + `OCSP Response Data:` block | OCSP stapling is working | ✅ Pass | 🟢 Low |
| `OCSP response: no response sent` or empty/no OCSP section | OCSP stapling is **disabled** | ❌ Fail | 🟡 Medium |
| `OCSP Response Status: unknown (0x2)` or other error | OCSP responder error | ⚠️ Investigate | 🟡 Medium |

### 6.2 Verify OCSP Response Details

```bash
# Decode the OCSP response if stapling is present
echo | openssl s_client -connect example.com:443 -servername example.com -status 2>&1 \
  | sed -n '/OCSP response:/,/^---/p'
```

| Criteria | What to look for | Verdict | Severity |
|---|---|---|---|
| Next Update date | OCSP response has a future `nextUpdate` | ✅ Pass | 🟡 Medium if old |
| Certificate status | Status shows `good` | ✅ Pass | 🔴 Critical if `revoked` |
| Stapling vs. OCSP fetch | Without stapling, browser fetches CA's OCSP responder directly (privacy leak, extra latency) | ❌ Without | 🟡 Medium |

**Why OCSP Stapling matters:**
- **Privacy:** Browser doesn't leak the user's browsing history to the CA's OCSP responder
- **Performance:** Saves an extra HTTP round-trip (no separate OCSP fetch)
- **Reliability:** If the CA's OCSP responder is down, stapling still provides cached status

---

## 7. Comprehensive Automation Script

Save the following as a single script for regular audits:

```bash
#!/bin/bash
# ssl-tls-audit.sh, Run against a WordPress site
# Usage: ./ssl-tls-audit.sh example.com

DOMAIN="${1:-example.com}"
echo "=========================================="
echo " SSL/TLS Audit Report for $DOMAIN"
echo " Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================="

echo ""
echo "--- 1. Certificate Info ---"
CERT=$(echo | openssl s_client -connect "$DOMAIN":443 -servername "$DOMAIN" 2>/dev/null)
echo "$CERT" | openssl x509 -noout -dates -issuer -subject 2>/dev/null
echo "$CERT" | openssl x509 -noout -enddate 2>/dev/null

echo ""
echo "--- 2. SAN Entries ---"
echo "$CERT" | openssl x509 -noout -ext subjectAltName 2>/dev/null

echo ""
echo "--- 3. Protocol Support ---"
for proto in tls1_3 tls1_2 tls1_1 tls1 ssl3; do
  echo -n "$proto: "
  echo | openssl s_client -connect "$DOMAIN":443 -"$proto" -servername "$DOMAIN" 2>&1 \
    | grep -q 'New, TLS\|New, SSL\|Cipher is ' \
    && echo "SUPPORTED" || echo "NOT SUPPORTED"
done

echo ""
echo "--- 4. Weak Ciphers ---"
for cipher in NULL aNULL EXPORT RC4 DES; do
  echo -n "$cipher: "
  echo | openssl s_client -connect "$DOMAIN":443 -cipher "$cipher" -servername "$DOMAIN" 2>&1 \
    | grep -q 'Cipher is ' \
    && echo "VULNERABLE (negotiated)" || echo "OK (not supported)"
done

echo ""
echo "--- 5. HSTS Header ---"
curl -sI -L "https://$DOMAIN" | grep -i 'strict-transport-security'

echo ""
echo "--- 6. OCSP Stapling ---"
echo | openssl s_client -connect "$DOMAIN":443 -servername "$DOMAIN" -status 2>&1 \
  | grep -E 'OCSP Response Status|OCSP response:'

echo ""
echo "--- 7. Mixed Content (homepage) ---"
curl -sL "https://$DOMAIN" \
  | grep -oE 'http://[^"]*\.(js|css|png|jpg|jpeg|gif|svg)' \
  | sort -u | head -20
```

---

## 8. SSL Labs API Check (Bonus)

The [Qualys SSL Labs API](https://www.ssllabs.com/ssltest/) provides a comprehensive, free grade (A+ to F).

```bash
# Submit a scan request (returns JSON with grade)
curl -s "https://api.ssllabs.com/api/v3/analyze?host=$DOMAIN&all=done" \
  | jq '.endpoints[] | {ip, grade, serverName}'

# If jq is not installed, use grep
curl -s "https://api.ssllabs.com/api/v3/analyze?host=example.com&all=done" \
  | grep -o '"grade":"[^"]*"'
```

**Note:** The API is rate-limited. Use sparingly, max 1 concurrent scan per IP, ~20 scans per day.

| SSL Labs Grade | Meaning | Verdict |
|---|---|---|
| A+ | Perfect, HSTS preloaded, strong ciphers, no vulns | ✅ Pass |
| A | Strong configuration | ✅ Pass |
| A- | Good but minor issues (e.g., CBC ciphers or short HSTS) | ⚠️ Flag |
| B+ to B | Weak ciphers or protocol downgrades | ❌ Warn |
| C to F | Vulnerable configuration | ❌ Fail |

---

## Severity Reference

| Severity | Meaning | Response |
|---|---|---|
| 🔴 Critical | Immediate exploitation risk | Fix within 24 hours |
| 🟠 High | Significant vulnerability | Fix within 1 week |
| 🟡 Medium | Best-practice deficiency | Fix within 1 month |
| 🟢 Low | Minor improvement | Fix within 3 months |
| ✅ Pass | Compliant | No action needed |

---

## Tools Required

| Tool | Installation | Purpose |
|---|---|---|
| `openssl` | `apt install openssl` (pre-installed on most systems) | Certificate inspection, protocol/cipher testing, OCSP |
| `curl` | `apt install curl` (pre-installed) | HSTS, mixed content, headers |
| `jq` (optional) | `apt install jq` | JSON parsing for SSL Labs API |
| `sslscan` (optional) | `apt install sslscan` | Comprehensive cipher enumeration |
| `testssl.sh` (optional) | `git clone https://github.com/drwetter/testssl.sh.git` | Most thorough SSL/TLS testing suite |

---

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Qualys SSL Labs](https://www.ssllabs.com/ssltest/)
- [HSTS Preload List](https://hstspreload.org/)
- [RFC 8996, TLS 1.0 and 1.1 Deprecation](https://datatracker.ietf.org/doc/rfc8996/)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [WordPress Hardening, SSL/TLS](https://wordpress.org/support/article/administration-over-ssl/)

---

> **Audit Checklist v1.0**, Created for WordPress security audit service. All checks are remote and require no server access.
