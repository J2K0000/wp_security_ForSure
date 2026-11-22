# 10, WordPress Database & Configuration Exposure Audit

> **Classification:** Configuration & Information Disclosure
> **Scope:** Remote, unauthenticated (black-box / grey-box)
> **Goal:** Detect exposed database credentials, configuration files, SQL dumps, phpMyAdmin installations, and error disclosure that could lead to full site compromise.

---

## Severity Reference

| Severity | Colour     | Meaning                                                      |
|----------|------------|--------------------------------------------------------------|
| 🔴 Critical | Red     | Direct credential / data leak, full compromise probable     |
| 🟠 High     | Orange  | Significant information disclosure or attack surface          |
| 🟡 Medium   | Yellow  | Marginal leak, aids further attacks                          |
| 🟢 Low      | Green   | Informational, limited risk alone                            |

---

## 1. wp-config.php Direct Access

A properly configured server **must not** serve `wp-config.php` as plaintext. It should return `403 Forbidden`, `404 Not Found`, or, best, a blank page / empty response. **200 OK with readable PHP/plaintext is a critical finding.**

### Commands

```bash
# Basic check
curl -sI "https://target.com/wp-config.php" | head -20

# Show full body to verify it's not served
curl -s "https://target.com/wp-config.php" | head -80

# Check with User-Agent spoofing (some WAFs whitelist bots)
curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "https://target.com/wp-config.php" | head -80

# Try alternative case variants for case-insensitive bypasses
curl -s "https://target.com/WP-Config.php"
curl -s "https://target.com/wp-config.PHP"
```

### Vulnerable Response
```
HTTP/1.1 200 OK
Content-Type: text/plain   (or text/html with PHP code visible)
...
<?php
/**
 * The base configuration for WordPress
 */
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'SuperSecret123!');
define('DB_HOST', 'localhost');
...
```

### Secure Response
```
HTTP/1.1 403 Forbidden
```
or
```
HTTP/1.1 404 Not Found
```
or
```
HTTP/1.1 200 OK
Content-Length: 0
```

| Severity | Condition                                        |
|----------|--------------------------------------------------|
| 🔴 Critical | 200 OK with readable PHP/plaintext content    |
| 🔴 Critical | 200 OK if status is delivered with PHP content |

---

## 2. wp-config.php Backup / Alternate Paths

Editors, version control, and manual backups often leave copies of `wp-config.php` with different extensions. Any single hit is **Critical**.

### Check List

| Path                        | Origin                                      |
|-----------------------------|---------------------------------------------|
| `wp-config.php.bak`         | Manual backup                               |
| `wp-config.php.old`         | Manual backup / upgrade artifact            |
| `wp-config.php~`            | Emacs / nano swap                           |
| `wp-config.php.save`        | Editor save                                 |
| `wp-config.php.txt`         | Accidental text rename                      |
| `wp-config.php.inc`         | Include-rename mistake                      |
| `wp-config.php.swp`         | Vim swap file (1st)                         |
| `wp-config.php.swo`         | Vim swap file (2nd)                         |
| `wp-config.php.swn`         | Vim swap file (3rd+)                        |
| `wp-config.php.orig`        | Merge conflict / patch backup               |
| `wp-config_backup.php`      | Manual backup                               |
| `wp-config.old.php`         | Alternate naming                            |
| `config.php`                | Generic config in web root                  |
| `config.inc.php`            | Generic include config                      |
| `db.php`                    | Standalone DB config                        |
| `wp-config.php~1~`          | Editor versioning                           |
| `wp-config.php.bkp`         | Manual backup                               |

### Command

```bash
# Check all alternates in one batch
for path in \
  wp-config.php.bak wp-config.php.old wp-config.php~ wp-config.php.save \
  wp-config.php.txt wp-config.php.inc wp-config.php.swp wp-config.php.swo \
  wp-config.php.swn wp-config.php.orig wp-config_backup.php wp-config.old.php \
  config.php config.inc.php db.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
  [ "$code" != "404" ] && echo "[$code] $path"
done
```

### Vulnerable Response
Any HTTP code other than `404` or `403` on these paths. If `200` and the body contains `DB_PASSWORD` or `define(`, it is a **direct credential leak**.

| Severity | Condition                                                 |
|----------|-----------------------------------------------------------|
| 🔴 Critical | 200 OK with `DB_PASSWORD` or `define(` in response body |
| 🟠 High     | 200 OK (empty or non-PHP), potential file info leak     |
| 🟡 Medium   | 301/302 redirect, path exists, possible info             |

---

## 3. SQL Dump Exposure

SQL dumps contain the entire database, user tables, password hashes, session tokens, WooCommerce customer data. They are sometimes left in the web root or inside `wp-content/uploads/` by migration plugins or careless admins.

### Check List

| Path(s)                                       | Notes                              |
|------------------------------------------------|------------------------------------|
| `database.sql`                                 | Common generic name                |
| `db.sql`                                       | Abbreviated                        |
| `backup.sql`                                   | Migration artifact                  |
| `dump.sql`                                     | mysqldump default                   |
| `site.sql`                                     | Generic                             |
| `wordpress.sql`                                | Explicit                           |
| `export.sql`                                   | Export artifact                     |
| `database.sql.gz`                              | Gzipped                            |
| `db.sql.gz`                                    | Gzipped                            |
| `backup.sql.gz`                                | Gzipped                            |
| `dump.sql.gz`                                  | Gzipped                            |
| `wordpress.sql.gz`                             | Gzipped                            |
| `database.sql.zip`                             | Zipped                             |
| `backup.sql.zip`                               | Zipped                             |
| `dump.tar.gz`                                  | Tarred + gzipped                   |
| `wp-content/uploads/database.sql`              | In uploads dir                     |
| `wp-content/uploads/backup.sql`                | In uploads dir                     |
| `wp-content/backup.sql`                        | In wp-content                      |
| `sql/export.sql`                               | Subdirectory                        |
| `backups/db.sql`                               | Backups dir                         |

### Command

```bash
# Quick check common SQL dumps in root
for f in \
  database.sql db.sql backup.sql dump.sql site.sql wordpress.sql export.sql \
  database.sql.gz db.sql.gz backup.sql.gz dump.sql.gz wordpress.sql.gz \
  database.sql.zip backup.sql.zip dump.tar.gz; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$f")
  size=$(curl -s -o /dev/null -w "%{size_download}" "https://target.com/$f")
  [ "$code" != "404" ] && [ "$size" -gt 50 ] && echo "[$code][${size}B] $f"
done

# Check in wp-content/uploads (common for plugins to dump there)
for f in database.sql backup.sql export.sql; do
  curl -sI "https://target.com/wp-content/uploads/$f" | head -5
  echo "---"
done
```

### Vulnerable Response
```
HTTP/1.1 200 OK
Content-Type: application/octet-stream  (or text/plain, application/gzip)
Content-Length: 1048576
...
-- MySQL dump 10.13  Distrib 8.0.33
-- Host: localhost    Database: wordpress
-- Server version	8.0.33
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
...
INSERT INTO `wp_users` VALUES (1,'admin','$P$B...','admin','admin@example.com',...);
```

| Severity | Condition                                              |
|----------|--------------------------------------------------------|
| 🔴 Critical | 200 OK with `INSERT INTO` or `CREATE TABLE` or `DROP TABLE IF EXISTS` in body |
| 🟠 High     | 200 OK with gzip/zip archive that could be a dump     |
| 🟡 Medium   | 301 redirect to a download URL                        |

---

## 4. Plugin-Specific Backup Exposure

Many popular backup/migration plugins expose their backup directories, often unguessable filenames but guessable directory layouts. If directory listing is enabled, an attacker can enumerate all backups.

### Check List

| Plugin                        | Path                                          |
|-------------------------------|-----------------------------------------------|
| All-in-One WP Migration       | `wp-content/ai1wm-backups/`                   |
| All-in-One WP Migration       | `wp-content/plugins/all-in-one-wp-migration/storage/` |
| UpdraftPlus                   | `wp-content/updraft/`                         |
| BackupBuddy                   | `wp-content/uploads/backupbuddy_backups/`     |
| BackWPup                      | `wp-content/backupwp/`                        |
| WP All Export                 | `wp-content/uploads/wp-all-export/exports/`   |
| Duplicator                    | `wp-content/backups-dup-lite/`                |
| Duplicator Pro                | `wp-content/backups-dup-pro/`                 |
| BlogVault                     | `wp-content/uploads/blogvault/`               |
| WPvivid                       | `wp-content/wpvividbackups/`                  |
| Backup Guard                  | `wp-content/uploads/backup-guard/`            |
| Jetpack Backup (VaultPress)   | `wp-content/uploads/vaultpress/`               |

### Commands

```bash
# Check directory listing
curl -s "https://target.com/wp-content/ai1wm-backups/"
curl -s "https://target.com/wp-content/updraft/"
curl -s "https://target.com/wp-content/uploads/backupbuddy_backups/"

# Check with trailing slash
curl -sI "https://target.com/wp-content/ai1wm-backups/" | head -10

# Check without trailing slash (may redirect)
curl -sI "https://target.com/wp-content/ai1wm-backups" | head -10
```

### Vulnerable Response

**Directory listing enabled:**
```
HTTP/1.1 200 OK
...
Index of /wp-content/ai1wm-backups/
[DIR] ..
[FILE] site-20240601-123456.wpress  2024-06-01 12:34  12M
[FILE] site-20240608-123456.wpress  2024-06-08 12:34  12M
```

**Directory listing disabled but path exists (200/403 instead of 404):**
`200 OK` with `Content-Type: text/html` and empty body or generic page, the path is confirmed and attacker can attempt to guess filenames.

| Severity | Condition                                                |
|----------|----------------------------------------------------------|
| 🔴 Critical | Directory listing with downloadable backup files         |
| 🟠 High     | Path confirmed (200/403 not 404), possible brute-force  |
| 🟠 High     | Direct file access if a filename is guessable             |

---

## 5. phpMyAdmin / Database Admin Detection

Exposed database admin tools are a direct path to database compromise, especially if they use default credentials or are outdated.

### Check List

| Path               | Tool                |
|--------------------|---------------------|
| `phpmyadmin/`      | phpMyAdmin          |
| `phpMyAdmin/`      | phpMyAdmin          |
| `pma/`             | phpMyAdmin (alias)  |
| `adminer.php`      | Adminer             |
| `adminer/`         | Adminer             |
| `adminer4.php`     | Adminer v4          |
| `adminer3.php`     | Adminer v3          |
| `dbadmin/`         | phpMyAdmin / generic|
| `MySQLDumper/`     | MySQLDumper         |
| `mysql/`           | Generic             |
| `phpmyadmin2/`     | phpMyAdmin v2       |
| `sql/`             | Generic             |
| `phpmyadmin4/`     | phpMyAdmin v4       |
| `phpPgAdmin/`      | phpPgAdmin          |

### Commands

```bash
# Check each admin path
for path in \
  phpmyadmin phpMyAdmin pma adminer.php adminer adminer4.php \
  adminer3.php dbadmin MySQLDumper mysql phpmyadmin2 sql phpmyadmin4; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
  [ "$code" != "404" ] && echo "[$code] $path"
done

# Confirm by looking for login form content
curl -s "https://target.com/phpmyadmin/" | grep -i "phpmyadmin\|pma_password\|token" | head -5
curl -s "https://target.com/pma/" | grep -i "phpmyadmin\|pma_password" | head -5
curl -s "https://target.com/adminer.php" | grep -i "adminer\|Login\|System" | head -5
```

### Vulnerable Response
```
HTTP/1.1 200 OK
...
<title>phpMyAdmin</title>
...
<form method="post" action="index.php">
  <input type="text" name="pma_username" />
  <input type="password" name="pma_password" />
</form>
```

For Adminer:
```
HTTP/1.1 200 OK
...
<title>Adminer</title>
...
<form action="" method="post">
<select name="auth[driver]">
<option>Server</option>
...
```

| Severity | Condition                                                 |
|----------|-----------------------------------------------------------|
| 🔴 Critical | Adminer accessible (single-file, no auth, full DB access) |
| 🟠 High     | phpMyAdmin login page accessible (brute-force target)    |
| 🟡 Medium   | phpMyAdmin with 302 to login page (path confirmed)        |

---

## 6. Default Table Prefix Detection

Knowing the table prefix (`wp_` by default) helps attackers craft targeted SQL injection and allows them to confirm the CMS is WordPress when other indicators are hidden.

### Detection Vectors

#### a) Cookie Fingerprint
WordPress sets `wordpress_` / `wordpress_logged_in_` cookies using the hashed site URL, but `wp-settings-1` and `wp-settings-time-1` cookie names **directly expose `wp_`** as the table prefix (or a custom one if changed).

```bash
curl -sI "https://target.com/" | grep -i "wp-settings\|wordpress_\|wp_"
```

**Vulnerable Response:**
```
Set-Cookie: wp-settings-1=...
Set-Cookie: wp-settings-time-1=...
```

#### b) REST API wp-json
```bash
curl -s "https://target.com/wp-json/wp/v2/users" | python3 -m json.tool 2>/dev/null | head -20
```

Even if the users endpoint is restricted, the path `/wp-json/` confirms WordPress using `wp_` namespace.

#### c) HTML Comments
```bash
curl -s "https://target.com/" | grep -i "wp-" | head -10
```

WordPress often outputs CSS classes like `wp-block-`, `wp-image-`, etc. These don't directly reveal the table prefix but confirm standard WordPress.

#### d) Direct Prefix Probe (wp-config exposed)
If you already found an exposed config, the prefix is visible:
```php
$table_prefix = 'wp_';
```

#### e) Custom prefix from cookie if changed
```bash
# If cookies show xyz-settings-1 instead of wp-settings-1, the prefix is 'xyz_'
curl -sI "https://target.com/" | grep -i "settings-1"
```

| Severity | Condition                                                   |
|----------|-------------------------------------------------------------|
| 🟡 Medium | Default `wp_` prefix confirmed via cookies or wp-json       |
| 🟢 Low    | Custom prefix leaked (marginal additional info)             |
| 🟢 Low    | WordPress identified via HTML/CSS but no table prefix leak  |

---

## 7. Database Error Disclosure

Improperly configured sites may reveal MySQL error messages containing table names, column names, SQL syntax, and even connection credentials.

### Trigger Commands

```bash
# Malformed query parameter (if the site uses ?s= or ?p=)
curl -s "https://target.com/?p=' OR '1'='1" | grep -i "mysql\|error\|sql\|database\|warning\|fetch\|PDO\|mysqli\|Table " | head -10

# Malformed numeric ID
curl -s "https://target.com/?page_id=1'" | grep -i "mysql\|error\|sql\|warning\|Table\|Column\|at line\|syntax" | head -10

# Try injection in query string
curl -s "https://target.com/?cat=-1'%20UNION%20SELECT%201--" | grep -i "mysql\|error\|sql\|warning" | head -10

# Broken permalink
curl -s "https://target.com/%00wp-admin/" | grep -i "mysql\|error\|sql\|warning" | head -10

# Try in search endpoint
curl -s "https://target.com/?s='&submit=Search" | grep -i "mysql\|error\|sql" | head -10

# REST API with malformed ID
curl -s "https://target.com/wp-json/wp/v2/posts/1'" | grep -i "mysql\|error\|sql\|syntax" | head -10
```

### Vulnerable Response Patterns
```
WordPress database error: [You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near...]
```
```
Fatal error: Uncaught mysqli_sql_exception: Table 'wordpress.wp_posts' doesn't exist
```
```
Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result, boolean given in /var/www/html/wp-includes/wp-db.php on line 1234
```

| Severity | Condition                                                 |
|----------|-----------------------------------------------------------|
| 🟡 Medium | MySQL error message with `table name` and/or `column name` |
| 🟡 Medium | Stack trace revealing server paths (`/var/www/html/...`)    |
| 🟢 Low    | Generic error without SQL details (still an information leak) |

---

## 8. wp-config-sample.php Exposure

`wp-config-sample.php` ships with every WordPress installation. It doesn't contain real credentials, but it exposes:
- The salts/keys structure (can aid key-generation attacks)
- Confirms the WordPress version (via file hash or age)
- Confirms `wp_` as the default prefix

```bash
curl -sI "https://target.com/wp-config-sample.php" | head -10
curl -s "https://target.com/wp-config-sample.php" | head -50
```

### Vulnerable Response
```
HTTP/1.1 200 OK
...
<?php
/**
 * The base configuration for WordPress.
 */
define('DB_NAME', 'database_name_here');
define('DB_USER', 'username_here');
define('DB_PASSWORD', 'password_here');
...
$table_prefix = 'wp_';
...
```

| Severity | Condition                                          |
|----------|----------------------------------------------------|
| 🟡 Medium | 200 OK with PHP content served                    |
| 🟢 Low    | 403 Forbidden, path exists but restricted         |

---

## 9. Installation Not Locked

If `wp-admin/install.php` is accessible and returns the WordPress installation form instead of a redirect, the site has **not been installed** or the installation lock file is missing. An attacker can complete the installation and take over the database.

### Command

```bash
curl -sI "https://target.com/wp-admin/install.php" | head -10
curl -s "https://target.com/wp-admin/install.php" | head -50
```

### Vulnerable Response
```
HTTP/1.1 200 OK
...
<title>WordPress &rsaquo; Installation</title>
...
<h1>Welcome</h1>
<p>Welcome to the famous five-minute WordPress installation process!</p>
...
<form id="setup" method="post" action="?step=1">
  <input type="text" name="weblog_title" />
  ...
```

### Secure Response
```
HTTP/1.1 302 Found
Location: /wp-login.php
```
or
```
HTTP/1.1 302 Found
Location: /wp-admin/
```
or
```
HTTP/1.1 200 OK
Content-Type: text/plain
Already Installed.
```

| Severity | Condition                                                 |
|----------|-----------------------------------------------------------|
| 🔴 Critical | Installation form displayed, anyone can complete setup |
| 🟠 High     | 200 OK but not the installation form (edge case)         |

---

## 10. Environment Files Exposed

Modern WordPress deployments (especially containerised or managed via Bedrock/Trellis) use `.env` files to store database credentials. These are frequently misconfigured and served as plaintext.

### Check List

| Path                     | Notes                              |
|--------------------------|------------------------------------|
| `.env`                   | Laravel / Bedrock style             |
| `.env.local`             | Local overrides                     |
| `.env.production`        | Production env                      |
| `.env.staging`           | Staging env                         |
| `.env.development`       | Dev env                             |
| `env.php`                | PHP-based env                       |
| `.env.example`           | May contain real values             |
| `.env.backup`            | Backup                              |
| `.env.old`               | Old version                         |

### Commands

```bash
# Check each env file
for f in \
  .env .env.local .env.production .env.staging .env.development \
  env.php .env.example .env.backup .env.old; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$f")
  size=$(curl -s -o /dev/null -w "%{size_download}" "https://target.com/$f")
  [ "$code" != "404" ] && echo "[$code][${size}B] $f"
done

# For 200 responses, show content (redact if sensitive)
curl -s "https://target.com/.env"
```

### Vulnerable Response
```
HTTP/1.1 200 OK
Content-Type: application/octet-stream   (or text/plain)
...
DB_NAME=wordpress
DB_USER=root
DB_PASSWORD=SuperSecret123!
DB_HOST=localhost
WP_HOME=https://target.com
AUTH_KEY=...random...
SECURE_AUTH_KEY=...
```

⚠️ **Note:** Most web servers block `.env` by default (Apache uses `<FilesMatch>` in `.htaccess`, nginx uses `location` blocks). A `404` is expected. **Any non-404 response is suspicious.**

| Severity | Condition                                              |
|----------|--------------------------------------------------------|
| 🔴 Critical | 200 OK with `DB_PASSWORD` or `DB_USER` in response   |
| 🟠 High     | 200 OK with readable content (potential credentials)  |
| 🟡 Medium   | Path exists (200/403/301), find content via other means |

---

## Comprehensive Exposure Scanner Script

Save the following as `wp-db-exposure-scanner.sh` and run against any target.

```bash
#!/usr/bin/env bash
#===============================================================================
# WordPress Database & Configuration Exposure Scanner
# Usage: ./wp-db-exposure-scanner.sh <target-url>
# Example: ./wp-db-exposure-scanner.sh https://example.com
#===============================================================================
set -euo pipefail

TARGET="${1%/}"
[ -z "$TARGET" ] && echo "Usage: $0 <target-url>" && exit 1

RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
BOLD='\033[1m'

RESULTS=()

log_critical()  { echo -e "${RED}[CRITICAL]${NC} $1"; RESULTS+=("CRITICAL|$1"); }
log_high()      { echo -e "${ORANGE}[HIGH]${NC} $1";     RESULTS+=("HIGH|$1"); }
log_medium()    { echo -e "${YELLOW}[MEDIUM]${NC} $1";   RESULTS+=("MEDIUM|$1"); }
log_low()       { echo -e "${GREEN}[LOW]${NC} $1";       RESULTS+=("LOW|$1"); }
log_good()      { echo -e "${GREEN}[OK]${NC} $1"; }

check_path() {
  local path="$1"
  local desc="$2"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET/$path" 2>/dev/null || echo "000")
  echo "$code"
}

check_and_content() {
  local path="$1"
  local desc="$2"
  local keyword="$3"  # optional: content to grep for in body
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET/$path" 2>/dev/null || echo "000")
  if [ "$code" != "404" ]; then
    if [ -n "$keyword" ]; then
      local match
      match=$(curl -s --max-time 10 "$TARGET/$path" 2>/dev/null | grep -i "$keyword" | head -1)
      if [ -n "$match" ]; then
        echo "$code|MATCH"
      else
        echo "$code|NO_MATCH"
      fi
    else
      echo "$code|EXISTS"
    fi
  else
    echo "404|"
  fi
}

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  WordPress Database & Configuration Exposure Scanner       ║"
echo "║  Target: $TARGET"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

#-------------------------------------------------------------------------
# 1. wp-config.php direct access
#-------------------------------------------------------------------------
echo -e "${BOLD}──[ 1. wp-config.php Direct Access ]──────────────────────────${NC}"
code=$(check_path "wp-config.php" "Core config")
if [ "$code" = "200" ]; then
  content=$(curl -s --max-time 10 "$TARGET/wp-config.php" 2>/dev/null)
  if echo "$content" | grep -qi "DB_PASSWORD\|define("; then
    log_critical "wp-config.php returned 200 with PHP/DB credentials visible"
  else
    log_high "wp-config.php returned 200 (empty or non-standard content)"
  fi
elif [ "$code" = "403" ]; then
  log_good "wp-config.php → 403 Forbidden (blocked)"
elif [ "$code" = "404" ]; then
  log_good "wp-config.php → 404 Not Found (blocked)"
else
  log_medium "wp-config.php → $code (unexpected status)"
fi

#-------------------------------------------------------------------------
# 2. wp-config.php backup/alternate paths
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 2. wp-config.php Backup / Alternate Paths ]────────────────${NC}"
WP_CONFIG_ALTERNATES=(
  "wp-config.php.bak" "wp-config.php.old" "wp-config.php~" "wp-config.php.save"
  "wp-config.php.txt" "wp-config.php.inc" "wp-config.php.swp" "wp-config.php.swo"
  "wp-config.php.swn" "wp-config.php.orig" "wp-config_backup.php" "wp-config.old.php"
  "config.php" "config.inc.php" "db.php"
)
for path in "${WP_CONFIG_ALTERNATES[@]}"; do
  result=$(check_and_content "$path" "" "DB_PASSWORD\|define(\|database_name_here")
  code="${result%%|*}"
  detail="${result#*|}"
  if [ "$code" != "404" ]; then
    if echo "$detail" | grep -q "MATCH"; then
      log_critical "$path returned $code with DB credentials visible"
    elif [ "$code" = "200" ]; then
      log_high "$path returned 200 (potential config leak)"
    else
      log_medium "$path returned $code (path exists)"
    fi
  fi
done

#-------------------------------------------------------------------------
# 3. SQL dump exposure
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 3. SQL Dump Exposure ]─────────────────────────────────────${NC}"
SQL_DUMPS=(
  "database.sql" "db.sql" "backup.sql" "dump.sql" "site.sql" "wordpress.sql"
  "export.sql" "database.sql.gz" "db.sql.gz" "backup.sql.gz" "dump.sql.gz"
  "wordpress.sql.gz" "database.sql.zip" "backup.sql.zip" "dump.tar.gz"
)
for path in "${SQL_DUMPS[@]}"; do
  result=$(check_and_content "$path" "" "INSERT INTO\|CREATE TABLE\|DROP TABLE\|MySQL dump")
  code="${result%%|*}"
  detail="${result#*|}"
  if [ "$code" != "404" ]; then
    if echo "$detail" | grep -q "MATCH"; then
      log_critical "$path returned $code with SQL dump content"
    elif [ "$code" = "200" ]; then
      size=$(curl -s -o /dev/null -w "%{size_download}" --max-time 10 "$TARGET/$path" 2>/dev/null)
      log_high "$path returned 200 (${size}B), potential SQL dump"
    else
      log_medium "$path returned $code (potential SQL dump)"
    fi
  fi
done

# Also check in wp-content/uploads/
for path in "database.sql" "backup.sql" "export.sql"; do
  result=$(check_and_content "wp-content/uploads/$path" "" "INSERT INTO\|CREATE TABLE\|MySQL dump")
  code="${result%%|*}"
  detail="${result#*|}"
  if [ "$code" != "404" ] && [ "$code" != "403" ]; then
    if echo "$detail" | grep -q "MATCH"; then
      log_critical "wp-content/uploads/$path returned $code with SQL dump content"
    else
      log_high "wp-content/uploads/$path returned $code"
    fi
  fi
done

#-------------------------------------------------------------------------
# 4. Plugin-specific backup exposure
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 4. Plugin-Specific Backup Exposure ]───────────────────────${NC}"
PLUGIN_BACKUPS=(
  "wp-content/ai1wm-backups/" "wp-content/plugins/all-in-one-wp-migration/storage/"
  "wp-content/updraft/" "wp-content/uploads/backupbuddy_backups/"
  "wp-content/backupwp/" "wp-content/uploads/wp-all-export/exports/"
  "wp-content/backups-dup-lite/" "wp-content/backups-dup-pro/"
  "wp-content/uploads/blogvault/" "wp-content/wpvividbackups/"
  "wp-content/uploads/backup-guard/" "wp-content/uploads/vaultpress/"
)
for path in "${PLUGIN_BACKUPS[@]}"; do
  code=$(check_path "$path" "Plugin backup dir")
  if [ "$code" = "200" ]; then
    # Check if directory listing is enabled
    listing=$(curl -s --max-time 10 "$TARGET/$path" 2>/dev/null)
    if echo "$listing" | grep -qi "Index of\|<title>Index\|\.wpress\|\.sql\|\.zip\|\.gz"; then
      log_critical "$path, directory listing with backup files"
    else
      log_high "$path returned 200 (backup dir exposure)"
    fi
  elif [ "$code" != "404" ] && [ "$code" != "000" ]; then
    log_medium "$path returned $code (path exists)"
  fi
done

#-------------------------------------------------------------------------
# 5. phpMyAdmin / Database Admin Detection
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 5. phpMyAdmin / Database Admin Detection ]─────────────────${NC}"
DB_ADMIN_PATHS=(
  "phpmyadmin/" "phpMyAdmin/" "pma/" "adminer.php" "adminer/" "adminer4.php"
  "adminer3.php" "dbadmin/" "MySQLDumper/" "mysql/" "phpmyadmin2/" "sql/" "phpmyadmin4/"
)
for path in "${DB_ADMIN_PATHS[@]}"; do
  result=$(check_and_content "$path" "" "phpMyAdmin\|pma_password\|Adminer\|Login\|MySQLDumper")
  code="${result%%|*}"
  detail="${result#*|}"
  if [ "$code" != "404" ]; then
    if echo "$detail" | grep -q "MATCH"; then
      log_critical "$path returned $code with DB admin login form"
    elif [ "$code" = "200" ]; then
      log_high "$path returned 200 (potential DB admin tool)"
    else
      log_medium "$path returned $code (DB admin path exists)"
    fi
  fi
done

#-------------------------------------------------------------------------
# 6. Default table prefix detection
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 6. Default Table Prefix Detection ]────────────────────────${NC}"
cookies=$(curl -sI --max-time 10 "$TARGET/" 2>/dev/null | grep -i "^Set-Cookie:" || true)
if echo "$cookies" | grep -qi "wp-settings-"; then
  log_medium "Table prefix detected via cookies: $(echo "$cookies" | grep -io "wp-settings-\|\([a-z0-9]*\)_settings-" | head -1 | tr -d '\n')"
fi
if curl -sI --max-time 10 "$TARGET/wp-json/" 2>/dev/null | grep -qi "application/json"; then
  log_low "WordPress REST API confirmed (wp-json accessible)"
fi

#-------------------------------------------------------------------------
# 7. Database error disclosure
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 7. Database Error Disclosure ]─────────────────────────────${NC}"
db_errors=$(curl -s --max-time 10 "$TARGET/?p=1'" 2>/dev/null | grep -oi "mysql\|error\|sql\|database\|warning\|fetch\|mysqli\|Table \|syntax\|at line" | head -5)
if [ -n "$db_errors" ]; then
  log_medium "Database error strings found on malformed input (p=1'): $db_errors"
else
  log_good "No database error disclosure detected on basic probe"
fi

# Additional probes
for probe in "?cat=-1'" "?page_id=1'" "?s='"; do
  found=$(curl -s --max-time 10 "$TARGET/$probe" 2>/dev/null | grep -oi "mysql\|error\|sql\|database\|syntax\|at line\|mysqli" | head -3)
  if [ -n "$found" ]; then
    log_medium "Error strings found on probe: $probe → $found"
    break
  fi
done

#-------------------------------------------------------------------------
# 8. wp-config-sample.php exposure
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 8. wp-config-sample.php Exposure ]─────────────────────────${NC}"
result=$(check_and_content "wp-config-sample.php" "" "database_name_here\|table_prefix\|AUTH_KEY")
code="${result%%|*}"
detail="${result#*|}"
if [ "$code" != "404" ]; then
  if echo "$detail" | grep -q "MATCH"; then
    log_medium "wp-config-sample.php returned $code with sample config content"
  else
    log_low "wp-config-sample.php returned $code (path exists)"
  fi
else
  log_good "wp-config-sample.php → 404 (blocked)"
fi

#-------------------------------------------------------------------------
# 9. Installation not locked
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 9. Installation Not Locked ]───────────────────────────────${NC}"
result=$(check_and_content "wp-admin/install.php" "" "WordPress.*Installation\|Welcome.*five-minute\|weblog_title")
code="${result%%|*}"
detail="${result#*|}"
if [ "$code" != "404" ]; then
  if echo "$detail" | grep -q "MATCH"; then
    log_critical "wp-admin/install.php returned $code with installation form, site is NOT installed/locked"
  elif [ "$code" = "302" ] || [ "$code" = "301" ]; then
    loc=$(curl -sI --max-time 10 "$TARGET/wp-admin/install.php" 2>/dev/null | grep -i "^Location:" | head -1)
    log_good "wp-admin/install.php → $code $loc (locked)"
  else
    log_high "wp-admin/install.php returned $code (unexpected)"
  fi
else
  log_good "wp-admin/install.php → 404 (locked, potentially removed)"
fi

#-------------------------------------------------------------------------
# 10. Environment files
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──[ 10. Environment Files Exposure ]───────────────────────────${NC}"
ENV_FILES=(
  ".env" ".env.local" ".env.production" ".env.staging" ".env.development"
  "env.php" ".env.example" ".env.backup" ".env.old"
)
for path in "${ENV_FILES[@]}"; do
  result=$(check_and_content "$path" "" "DB_PASSWORD\|DB_USER\|DB_NAME\|AUTH_KEY\|WP_HOME")
  code="${result%%|*}"
  detail="${result#*|}"
  if [ "$code" != "404" ]; then
    if echo "$detail" | grep -q "MATCH"; then
      log_critical "$path returned $code with environment credentials visible"
    elif [ "$code" = "200" ]; then
      log_high "$path returned 200 (potential env file leak)"
    else
      log_medium "$path returned $code (env file path exists)"
    fi
  fi
done

#-------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  SCAN SUMMARY                                              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

critical=$(printf "%s\n" "${RESULTS[@]}" | grep -c "^CRITICAL" || true)
high=$(printf "%s\n" "${RESULTS[@]}" | grep -c "^HIGH" || true)
medium=$(printf "%s\n" "${RESULTS[@]}" | grep -c "^MEDIUM" || true)
low=$(printf "%s\n" "${RESULTS[@]}" | grep -c "^LOW" || true)

echo "  🔴 Critical: $critical"
echo "  🟠 High:     $high"
echo "  🟡 Medium:   $medium"
echo "  🟢 Low:      $low"
echo ""

if [ "$critical" -gt 0 ] || [ "$high" -gt 0 ]; then
  echo -e "${RED}ACTION REQUIRED: Critical or High findings detected.${NC}"
  echo ""
  echo "Priority remediation (in order):"
  echo "  1. Block wp-config.php access (web server rules)"
  echo "  2. Remove/secure all wp-config.php backup files"
  echo "  3. Remove SQL dumps from web root and wp-content/"
  echo "  4. Secure or remove plugin backup directories"
  echo "  5. Remove or password-protect phpMyAdmin / Adminer"
  echo "  6. Lock WordPress installation (add wp-content/install.php)"
  echo "  7. Block .env files in web server configuration"
  echo "  8. Disable WP_DEBUG and WP_DEBUG_DISPLAY in production"
  echo "  9. Change table prefix from default wp_ if possible"
fi

exit $((critical > 0 ? 1 : 0))
```

---

## Remediation Summary (Quick Reference)

| #  | Issue                            | Fix Command / Action                                                     | Priority |
|----|----------------------------------|--------------------------------------------------------------------------|----------|
| 1  | wp-config.php exposed            | Add to `.htaccess`: `<Files wp-config.php> Require all denied </Files>`   | 🔴 |
| 2  | Backup config files              | Delete all backup/swap copies from web root                               | 🔴 |
| 3  | SQL dumps                        | Delete files; move backups outside `public_html/`                         | 🔴 |
| 4  | Plugin backup dirs               | Disable directory listing; move backups outside web root                 | 🟠 |
| 5  | phpMyAdmin / Adminer             | Remove or restrict by IP / HTTP auth                                      | 🟠 |
| 6  | Default prefix                   | Change via `$table_prefix` in `wp-config.php` (requires DB update too)    | 🟡 |
| 7  | DB error disclosure              | Set `WP_DEBUG_DISPLAY` to `false` in `wp-config.php`                      | 🟡 |
| 8  | wp-config-sample.php exposed     | Delete the file from web root                                             | 🟡 |
| 9  | Install not locked               | Add `define('WP_INSTALLING', false);` to `wp-config.php` or remove `install.php` | 🔴 |
| 10 | .env files exposed               | Block with web server config; never store `.env` inside `public_html/`    | 🔴 |

---

## Changelog

| Date       | Author | Changes           |
|------------|--------|-------------------|
| 2026-07-16 | Hermes | Initial creation  |
