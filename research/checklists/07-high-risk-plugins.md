# 🛡️ High-Risk WordPress Plugins, Deep-Dive Checklist (Remote, No Login)

**Audit Type:** Black-Box (Remote, Unauthenticated)  
**Target:** WordPress Plugin Vulnerability Assessment  
**Last Updated:** July 2026  
**Plugins Covered:** 16 (including premium add-ons)  
**Methodology:** NVD API v2.0, WPScan, Wordfence Threat Intelligence, MITRE CVE, OWASP WSTG

---

## Table of Contents

1. [Introduction & Methodology](#introduction--methodology)
2. [Plugin Fiches](#plugin-fiches)
   - [1. Elementor (+ Elementor Pro, Essential Addons)](#1-elementor--elementor-pro-essential-addons)
   - [2. WooCommerce](#2-woocommerce)
   - [3. Contact Form 7](#3-contact-form-7)
   - [4. Jetpack](#4-jetpack)
   - [5. Yoast SEO](#5-yoast-seo)
   - [6. Wordfence Security](#6-wordfence-security)
   - [7. WPBakery / Visual Composer](#7-wpbakery--visual-composer)
   - [8. Slider Revolution](#8-slider-revolution)
   - [9. Gravity Forms](#9-gravity-forms)
   - [10. WPML](#10-wpml)
   - [11. All-in-One WP Migration](#11-all-in-one-wp-migration)
   - [12. UpdraftPlus](#12-updraftplus)
   - [13. Really Simple SSL](#13-really-simple-ssl)
   - [14. Advanced Custom Fields (ACF)](#14-advanced-custom-fields-acf)
   - [15. Rank Math SEO](#15-rank-math-seo)
   - [16. WP Rocket](#16-wp-rocket)
3. [Version Detection Reference](#version-detection-reference)
4. [CVE Watchlist Summary Table](#cve-watchlist-summary-table)
5. [Risk Scoring Matrix](#risk-scoring-matrix)
6. [Master Detection Script](#master-detection-script)

---

## Introduction & Methodology

### Why Remote (No-Login) Auditing?

- **Client onboarding**, assess a prospect's site before signing a maintenance contract
- **Pre-acquisition due diligence**, evaluate plugin hygiene without admin credentials
- **Bug bounty reconnaissance**, map the attack surface non-intrusively
- **Competitive intelligence**, benchmark competitors' security posture

### Detection Techniques

| Technique | What It Reveals | Reliability |
|-----------|----------------|-------------|
| `readme.txt` scraping | Exact plugin version | ⭐⭐⭐⭐⭐ |
| `style.css` header parsing | Version string (themes/layout plugins) | ⭐⭐⭐⭐ |
| Asset URL fingerprinting | Version in query string (e.g. `?ver=3.1.4`) | ⭐⭐⭐⭐ |
| REST API endpoints | Plugin presence + partial version info | ⭐⭐⭐ |
| HTML comments / generator tags | Plugin name, sometimes version | ⭐⭐ |
| Known file checksums | Version fingerprint via file hash | ⭐⭐⭐⭐⭐ |

---

## Plugin Fiches

---

### 1. Elementor (+ Elementor Pro, Essential Addons)

#### Overview

- **Slug:** `elementor`
- **Active Installs (WPScan):** 7M+
- **Pro Slug:** `elementor-pro`
- **Essential Addons Slug:** `essential-addons-for-elementor-lite`
- **WPScan Vulnerabilities:** 50+ (Elementor core), 30+ (Essential Addons)

#### Version Detection

```bash
# Elementor Free, readme.txt
curl -s "https://TARGET/wp-content/plugins/elementor/readme.txt" | grep -i "stable tag"

# Elementor Free, asset version query string
curl -s "https://TARGET/wp-content/plugins/elementor/assets/js/frontend.js?ver=" 2>/dev/null
curl -sI "https://TARGET/wp-content/plugins/elementor/assets/js/frontend.min.js" | grep -i "ver="

# Elementor Pro
curl -s "https://TARGET/wp-content/plugins/elementor-pro/readme.txt" | grep -i "stable tag"

# Essential Addons
curl -s "https://TARGET/wp-content/plugins/essential-addons-for-elementor-lite/readme.txt" | grep -i "stable tag"
curl -s "https://TARGET/wp-content/plugins/essential-addons-elementor/readme.txt" | grep -i "stable tag"

# Generator meta tag (all versions)
curl -s "https://TARGET/" | grep -i "generator.*elementor"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Discovered |
|-----|------|------|-------------------|------------|------------|
| CVE-2020-7109 | 9.8 (CRITICAL) | RCE / Unauthenticated | < 2.8.4 | 2.8.4 | 2020-01 |
| CVE-2021-24175 | 9.8 (CRITICAL) | Auth Bypass (Plus Addons) | < 4.1.7 | 4.1.7 | 2021-04 |
| CVE-2020-13126 | 9.9 (CRITICAL) | Arbitrary File Upload (Pro) | < 2.9.4 | 2.9.4 | 2020-05 |
| CVE-2022-0320 | 9.8 (CRITICAL) | LFI → RCE (Essential Addons) | < 5.0.5 | 5.0.5 | 2022-02 |
| CVE-2023-32243 | 9.8 (CRITICAL) | Privilege Escalation (Essential) | 5.4.0 – 5.7.1 | 5.7.1 | 2023-05 |
| CVE-2023-5360 | 9.8 (CRITICAL) | Arbitrary File Upload (Royal Addons) | < 1.3.79 | 1.3.79 | 2023-10 |
| CVE-2023-0329 | 7.2 (HIGH) | SQL Injection | < 3.12.2 | 3.12.2 | 2023-05 |
| CVE-2023-3124 | 8.8 (HIGH) | Missing Auth (Pro) | ≤ 3.11.6 | 3.11.6+ | 2023-06 |
| CVE-2024-3018 | 8.8 (HIGH) | PHP Object Injection (Essential) | ≤ 5.9.13 | 5.9.14 | 2024-03 |
| CVE-2020-13125 | 6.5 (MEDIUM) | Stored XSS (Ultimate Addons) | < 1.24.2 | 1.24.2 | 2020-05 |

#### Wordfence Status

- **Elementor:** 75+ vulnerabilities recorded. Frequently targeted.
- **Elementor Pro:** Premium plugin; vulnerabilities reported via Wordfence team regularly.
- **Essential Addons:** 30+ vulnerabilities; CVE-2022-0320 (LFI) and CVE-2023-32243 (PE) actively exploited in the wild.

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🔴 **Critical** | 100+ widgets, file uploads, dynamic content |
| Historical Exploitation | 🔴 **Critical** | Multiple 9.8 CVEs exploited in the wild (2020, 2021, 2022, 2023) |
| Version Detection Difficulty | 🟢 **Easy** | readme.txt accessible for free version |
| Remediation Urgency | 🟡 **High** | Patches available, but sites on old versions are common |

---

### 2. WooCommerce

#### Overview

- **Slug:** `woocommerce`
- **Active Installs (WPScan):** 7M+
- **WPScan Vulnerabilities:** 127
- **Repository:** https://wordpress.org/plugins/woocommerce/

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/woocommerce/readme.txt" | grep -i "stable tag"

# Version in asset URL
curl -sI "https://TARGET/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.min.js" | grep -i "ver="

# REST API exposes version
curl -s "https://TARGET/wp-json/wc/v2" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('system_status',{}).get('environment',{}).get('version','N/A'))" 2>/dev/null
# Or via WooCommerce REST API index
curl -s "https://TARGET/wp-json/wc/v3" 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -i "version"

# Helper/package.json
curl -s "https://TARGET/wp-content/plugins/woocommerce/package.json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('version','N/A'))" 2>/dev/null
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2021-32790 | 4.9 (MEDIUM) | SQL Injection | 3.3.0 – 3.3.6 | 3.3.6 | Authenticated but high impact |
| CVE-2018-20714 | ? | File Deletion | < 3.4.6 | 3.4.6 | Privilege escalation vector |
| CVE-2017-18356 | ? | Privilege Escalation | < 3.2.4 | 3.2.4 | Shop manager → admin |
| CVE-2017-17058 | 7.5 (HIGH) | Directory Traversal | ≤ 3.x | 3.2+ | `/templates/emails/plain/` path |
| (2026-03) | 7.5 (HIGH) | CSRF → Admin Creation | < 10.5.3 (multiple branches) | 10.5.3, 8.9.5, 7.3.1, etc. | Branch-specific patching, check all |
| CVE-2019-9168 | ? | XSS (Photoswipe) | < 3.5.5 | 3.5.5 | Stored XSS in media caption |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🔴 **Critical** | Payment processing, user data, order management, REST API |
| Historical Exploitation | 🟡 **High** | Fewer RCE vulnerabilities, but privilege escalation is common |
| Version Detection Difficulty | 🟢 **Easy** | Multiple reliable detection paths |
| Remediation Urgency | 🟡 **High** | Critical business plugin, patching is non-negotiable |

---

### 3. Contact Form 7

#### Overview

- **Slug:** `contact-form-7`
- **Active Installs (WPScan):** 5M+
- **WPScan Vulnerabilities:** 40+
- **Repository:** https://wordpress.org/plugins/contact-form-7/

#### Version Detection

```bash
# readme.txt, primary method
curl -s "https://TARGET/wp-content/plugins/contact-form-7/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/contact-form-7/includes/js/scripts.js" | grep -i "ver="
curl -sI "https://TARGET/wp-content/plugins/contact-form-7/includes/css/styles.css" | grep -i "ver="

# Plugin directory detection
curl -s "https://TARGET/wp-content/plugins/contact-form-7/" 2>/dev/null | head -5
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2020-35489 | 10.0 (CRITICAL) | Unrestricted File Upload → RCE | < 5.3.2 | 5.3.2 | **Actively exploited.** Special chars in filename bypass sanitization |
| CVE-2021-24159 | 8.8 (HIGH) | Stored XSS (Custom CSS) | < 5.3.2 (CF7 Style addon) | 5.3.2 | No nonce on custom CSS |
| CVE-2021-36885 | 6.1 (MEDIUM) | Unauthenticated Stored XSS (CFDB7) | ≤ 1.2.6.1 | 1.2.6.2 | DB addon leakage |
| CVE-2023-2701 | 6.1 (MEDIUM) | Reflected XSS | < 2.7.5 | 2.7.5 | Generated URLs in attributes |
| CVE-2022-29408 | 4.7 (MEDIUM) | Persistent XSS (Advanced CF7 DB) | ≤ 1.8.7 | 1.8.8 | |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🔴 **Critical** | File uploads, email sending, form data storage |
| Historical Exploitation | 🔴 **Critical** | CVE-2020-35489 widely exploited; RCE via file upload |
| Version Detection Difficulty | 🟢 **Easy** | readme.txt always accessible |
| Remediation Urgency | 🔴 **Immediate** | 10.0 CVSS speaks for itself |

---

### 4. Jetpack

#### Overview

- **Slug:** `jetpack`
- **Active Installs (WPScan):** 5M+
- **WPScan Vulnerabilities:** 30+
- **Repository:** https://wordpress.org/plugins/jetpack/
- **Developer:** Automattic (WordPress.com)

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/jetpack/readme.txt" | grep -i "stable tag"

# Version in asset URL
curl -sI "https://TARGET/wp-content/plugins/jetpack/jetpack.php" | grep -i "ver="

# Generator tag
curl -s "https://TARGET/" | grep -i "jetpack"

# Package detection
curl -s "https://TARGET/wp-content/plugins/jetpack/_inc/jetpack.css" | head -5
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2024-4392 | 6.4 (MEDIUM) | Stored XSS (wpvideo shortcode) | ≤ 13.3.1 | 13.3.2 | Shortcode XSS vector |
| CVE-2023-2996 | 8.8 (HIGH) | Arbitrary File Deletion | < 12.1.1 | 12.1.1 | Author+ role, file manipulation |
| CVE-2021-24374 | 5.3 (MEDIUM) | Information Disclosure (Carousel) | < 9.8 | 9.8 | Comment data exposure |
| CVE-2016-10705 | ? | XSS (Likes module) | < 4.0.4 | 4.0.4 | Stored XSS |
| CVE-2014-0173 | ? | Multiple vulns | Multiple branches | Various | Series of issues in WordPress.com connection |
| CVE-2022-4497 | 5.4 (MEDIUM) | Stored XSS (Jetpack CRM) | < 5.5 | 5.5 | Shortcode attribute XSS |
| CVE-2022-3342 | 7.5 (HIGH) | PHAR Deserialization (CRM) | ≤ 5.3.1 | 5.3.2 | CRM-specific |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟡 **High** | Large module surface, many features disabled by default |
| Historical Exploitation | 🟡 **High** | Less exploited than Elementor, but Jetpack Scan team actively finds vulns in other plugins |
| Version Detection Difficulty | 🟢 **Easy** | Multiple detection paths |
| Remediation Urgency | 🟢 **Medium** | Core Jetpack has fewer critical CVEs; CRM and specific modules are riskier |

---

### 5. Yoast SEO

#### Overview

- **Slug:** `wordpress-seo`
- **Active Installs (WPScan):** 5M+
- **WPScan Vulnerabilities:** 25+
- **Repository:** https://wordpress.org/plugins/wordpress-seo/

#### Version Detection

```bash
# readme.txt, primary
curl -s "https://TARGET/wp-content/plugins/wordpress-seo/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/wordpress-seo/js/dist/yoastseo.min.js" | grep -i "ver="

# Generator meta
curl -s "https://TARGET/" | grep -i "yoast"

# Admin bar detection (if logged out, may still expose via CSS)
curl -s "https://TARGET/wp-content/plugins/wordpress-seo/css/dist/yoast-seo-adminbar-*.css" 2>/dev/null | head -1
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2024-4041 | 6.1 (MEDIUM) | Reflected XSS | ≤ 22.5 | 22.6 | URL-based XSS via insufficient sanitization |
| CVE-2024-4984 | 6.4 (MEDIUM) | Stored XSS (display_name) | ≤ 22.6 | 22.7 | Author meta stored XSS |
| CVE-2019-13478 | 9.8 (CRITICAL) | Unfiltered HTML | < 11.6-RC5 | 11.6 | Unrestricted HTML in term descriptions |
| CVE-2018-19370 | ? | Race Condition → RCE | < 9.2.0 | 9.2.0 | SEO Manager can execute commands via import |
| CVE-2021-25118 | 5.3 (MEDIUM) | Information Disclosure | 16.7 – 17.2 | 17.2 | Full internal path disclosure |
| CVE-2015-2292 | ? | SQL Injection | < 1.5.7 / < 1.6.4 / < 1.7.4 | 1.5.7+ | Bulk editor SQLi |
| CVE-2017-16842 | ? | XSS (GSC table) | < 5.8.0 | 5.8.0 | Google Search Console XSS |

#### Wordfence Status

Wordfence has flagged multiple Yoast SEO XSS vulnerabilities over the years. The plugin is widely deployed and regularly patched.

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟡 **High** | Admin-facing but with REST API exposure |
| Historical Exploitation | 🟡 **High** | CVE-2019-13478 reached 9.8; SQL injection in older versions |
| Version Detection Difficulty | 🟢 **Easy** | readme.txt always accessible |
| Remediation Urgency | 🟢 **Medium** | Recent CVEs are XSS, not RCE, but path disclosure aids attackers |

---

### 6. Wordfence Security

#### Overview

- **Slug:** `wordfence`
- **Active Installs (WPScan):** 4M+
- **WPScan Vulnerabilities:** 5+
- **Note:** Wordfence is a security plugin but has its own vulnerability surface

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/wordfence/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/wordfence/css/wordfenceBox.css" | grep -i "ver="

# Distinctive Wordfence files
curl -s "https://TARGET/wp-content/plugins/wordfence/waf.php" -o /dev/null -w "%{http_code}"
curl -s "https://TARGET/?_wflogin=1" -o /dev/null -w "%{http_code}"

# License check page
curl -s "https://TARGET/wp-content/plugins/wordfence/tmp/" -o /dev/null -w "%{http_code}"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2022-3144 | 4.4 (MEDIUM) | Stored XSS | ≤ 7.6.0 | 7.6.1 | Settings page stored XSS (admin) |
| CVE-2014-4664 | ? | XSS (whoisval) | < 5.1.4 | 5.1.4 | Reflected XSS via whois lookup |
| CVE-2014-4932 | ? | XSS (whois.php val) | < 5.1.5 | 5.1.5 | Similar whois endpoint XSS |
| CVE-2019-9669 | *DISPUTED* | XSS (disputed) | 7.2.3 | N/A | Declined by vendor as invalid |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟢 **Low** | Minimal exposure; most features require authentication |
| Historical Exploitation | 🟢 **Low** | Very few CVEs; mostly XSS in admin-facing tools |
| Version Detection Difficulty | 🟢 **Easy** | readme.txt normally available |
| Remediation Urgency | 🟢 **Low** | No critical CVEs reported; plugin is defensive, not an attack vector itself |

> **⚠️ Irony Factor:** Wordfence has very few vulnerabilities compared to the plugins it protects. However, running outdated Wordfence is worse than no Wordfence because it gives a false sense of security.

---

### 7. WPBakery / Visual Composer

#### Overview

- **Slug:** `js_composer` (WPBakery), varies for Visual Composer
- **Active Installs:** 1M+ (Premium only, no WordPress.org repository)
- **WPScan Vulnerabilities:** 15+
- **Note:** Premium plugin; version detection is harder because `readme.txt` is often removed

#### Version Detection

```bash
# readme.txt (if present)
curl -s "https://TARGET/wp-content/plugins/js_composer/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/js_composer/assets/js/js_composer_front.js" | grep -i "ver="

# Generator tag
curl -s "https://TARGET/" | grep -i "visual composer\|wpbakery\|js_composer"

# Known asset path
curl -s "https://TARGET/wp-content/plugins/js_composer/assets/css/js_composer.min.css" | head -5

# Visual Composer (alternative slug)
curl -s "https://TARGET/wp-content/plugins/visualcomposer/readme.txt" | grep -i "stable tag"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2024-5709 | 8.8 (HIGH) | Local File Inclusion | ≤ 7.7 | 7.7+ | Via `layout_name` parameter; authenticated+ |
| CVE-2024-5265 | 6.4 (MEDIUM) | Stored XSS (link attribute) | ≤ 7.6 | 7.6+ | `vc_single_image` shortcode |
| CVE-2024-5708 | 6.4 (MEDIUM) | Stored XSS (link parameter) | ≤ 7.7 | 7.7+ | Insufficient sanitization |
| CVE-2023-1274 | 6.5 (MEDIUM) | Path Traversal → LFI | < 3.0 (pricing tables addon) | 3.0 | Shortcode → include path |
| CVE-2023-0367 | 5.4 (MEDIUM) | Reflected XSS | < 3.0 (pricing tables addon) | 3.0 | Shortcode attribute |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟡 **High** | Large number of shortcodes, layout parameters, file includes |
| Historical Exploitation | 🟡 **High** | LFI (CVE-2024-5709) is concerning; XSS vectors are common |
| Version Detection Difficulty | 🟡 **Medium** | Premium plugin, readme.txt often stripped by pirates |
| Remediation Urgency | 🟡 **High** | Obsolete page builders should be replaced, not just patched |

---

### 8. Slider Revolution

#### Overview

- **Slug:** `revslider`
- **Active Installs:** 1M+ (Premium only)
- **WPScan Vulnerabilities:** 20+
- **Notoriety:** One of the most historically exploited premium plugins

#### Version Detection

```bash
# readme.txt (may be removed for premium)
curl -s "https://TARGET/wp-content/plugins/revslider/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/revslider/public/assets/js/rs-front-end.js" | grep -i "ver="

# CSS version
curl -s "https://TARGET/wp-content/plugins/revslider/public/assets/css/rs6.css" | head -3

# JS version, look for version string in JS
curl -s "https://TARGET/wp-content/plugins/revslider/public/assets/js/rs-front-end.min.js" 2>/dev/null | grep -oP "version:\"[^\"]+\"" | head -1

# Known path: backup DB
curl -s "https://TARGET/wp-content/plugins/revslider/install/revslider_backup.zip" -o /dev/null -w "%{http_code}"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2014-9734 | ? | Directory Traversal (File Read) | < 4.2 | 4.2 | **Classic attack**, read any file via `img` param |
| CVE-2014-9735 | ? | Arbitrary AJAX Access | < 3.0.96 | 3.0.96 | Unauthenticated AJAX admin operations |
| CVE-2015-5151 | ? | XSS | 4.2.2 | 4.2.3 | client_action parameter |
| CVE-2023-2359 | 8.8 (HIGH) | Arbitrary File Upload → RCE | ≤ 6.6.12 | 6.6.13 | **Actively exploited**, no image validation on import |
| CVE-2023-6528 | 8.8 (HIGH) | PHP Object Injection → RCE | < 6.6.19 | 6.6.19 | Author+ roles can unserialize arbitrary content |
| CVE-2024-4092 | 6.4 (MEDIUM) | Stored XSS (htmltag) | ≤ 6.7.7 | 6.7.8 | Shortcode parameter XSS |
| CVE-2024-8107 | 6.4 (MEDIUM) | Stored XSS (SVG upload) | ≤ 6.7.18 | 6.7.19 | SVG upload XSS |
| CVE-2025-9217 | 6.5 (MEDIUM) | Path Traversal | ≤ 6.7.36 | 6.7.37 | `used_svg`/`used_images` parameters |
| CVE-2026-6692 | 8.8 (HIGH) | Arbitrary File Upload | 7.0.0 – 7.0.10 | 7.0.11 | File validation bypass |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🔴 **Critical** | File import, SVG upload, AJAX handlers, slider data |
| Historical Exploitation | 🔴 **Critical** | Multiple 8.8+ CVEs, exploited in the wild for over a decade |
| Version Detection Difficulty | 🟡 **Medium** | Premium plugin; readme may be missing |
| Remediation Urgency | 🔴 **Immediate** | Consider replacing entirely, track record is terrible |

---

### 9. Gravity Forms

#### Overview

- **Slug:** `gravityforms` (Premium)
- **Active Installs:** 500K+ (Premium only)
- **WPScan Vulnerabilities:** 20+
- **Repository:** gravityforms.com (not WordPress.org)
- **Notes:** Premium form builder by Rocketgenius

#### Version Detection

```bash
# readme.txt (may be missing)
curl -s "https://TARGET/wp-content/plugins/gravityforms/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/gravityforms/js/gravityforms.min.js" | grep -i "ver="

# CSS version
curl -sI "https://TARGET/wp-content/plugins/gravityforms/css/formsmain.css" | grep -i "ver="

# Distinctive path
curl -s "https://TARGET/wp-content/plugins/gravityforms/gravityforms.php" -o /dev/null -w "%{http_code}"

# Gravity Forms API endpoint (if exposed)
curl -s "https://TARGET/wp-json/gf/v2" -o /dev/null -w "%{http_code}"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2025-12352 | 9.8 (CRITICAL) | Arbitrary File Upload | ≤ 2.9.20 | 2.9.21 | `copy_post_image()` missing type validation |
| CVE-2025-12974 | 8.1 (HIGH) | Arbitrary File Upload | ≤ 2.9.21.1 | 2.9.21.2 | Legacy chunked upload bypass |
| CVE-2024-13377 | 7.2 (HIGH) | Stored XSS (alt parameter) | ≤ 2.9.1.3 | 2.9.1.4 | Image alt text XSS |
| CVE-2020-13764 | 7.5 (HIGH) | Password Hash Leakage | < 2.4.9 | 2.4.9 | `user_pass` not treated as special in `$current_user->get()` |
| CVE-2025-8593 | 8.8 (HIGH) | Auth Bypass (GSheetConnector) | ≤ 1.3.27 | 1.3.28 | Missing capability check |
| CVE-2023-2701 | 6.1 (MEDIUM) | Reflected XSS | < 2.7.5 | 2.7.5 | URLs in attributes |
| CVE-2024-13845 | 5.5 (MEDIUM) | SSRF (WebHooks) | ≤ 1.6.0 | 1.6.1 | Server-Side Request Forgery |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🔴 **Critical** | File uploads, webhooks, API endpoints, user data |
| Historical Exploitation | 🔴 **Critical** | CVE-2025-12352 is 9.8 file upload RCE |
| Version Detection Difficulty | 🟡 **Medium** | Premium plugin; readme may be stripped |
| Remediation Urgency | 🔴 **Immediate** | Recent critical file upload CVEs; must patch immediately |

---

### 10. WPML

#### Overview

- **Slug:** `sitepress-multilingual-cms` (Premium)
- **Active Installs:** 500K+ (Premium only)
- **WPScan Vulnerabilities:** 10+
- **Developer:** OnTheGoSystems
- **Note:** Critical for multilingual sites; often overlooked in security audits

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/sitepress-multilingual-cms/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/sitepress-multilingual-cms/res/js/sitepress.js" | grep -i "ver="

# Generator tag (visible on frontend)
curl -s "https://TARGET/" | grep -i "wpml"

# Language cookie
curl -sI "https://TARGET/" | grep -i "_icl_current_language\|wpml"

# Distinctive path
curl -s "https://TARGET/wp-content/plugins/sitepress-multilingual-cms/inc/constants.php" -o /dev/null -w "%{http_code}"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2015-2314 | ? | SQL Injection | < 3.1.9 | 3.1.9 | SQLi via `lang` in HTTP Referer header |
| CVE-2015-2315 | ? | XSS | < 3.1.9 | 3.1.9 | `target` parameter in reminder_popup |
| CVE-2022-38461 | 5.4 (MEDIUM) | Broken Access Control | ≤ 4.5.10 | 4.5.11 | Subscriber+ can change plugin settings |
| CVE-2022-45071 | 5.4 (MEDIUM) | CSRF | ≤ 4.5.13 | 4.5.14 | Multiple CSRF vectors |
| CVE-2022-38974 | 4.3 (MEDIUM) | Broken Access Control | ≤ 4.5.10 | 4.5.11 | Subscribers can change translation job status |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟡 **High** | Database queries, cookie manipulation, language switching |
| Historical Exploitation | 🟡 **Medium** | Fewer CVEs, but SQL injection (2015) was serious |
| Version Detection Difficulty | 🟡 **Medium** | Premium; readme.txt may be present |
| Remediation Urgency | 🟡 **High** | Broken access control in recent versions is concerning |

---

### 11. All-in-One WP Migration

#### Overview

- **Slug:** `all-in-one-wp-migration`
- **Active Installs (WPScan):** 5M+
- **WPScan Vulnerabilities:** 15+
- **Repository:** https://wordpress.org/plugins/all-in-one-wp-migration/
- **Note:** Essential for site migration but exposes full site data during backups

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/all-in-one-wp-migration/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/javascript/backups.min.js" | grep -i "ver="

# Known paths (backup directory exposure)
curl -s "https://TARGET/wp-content/plugins/all-in-one-wp-migration/storage/" -o /dev/null -w "%{http_code}"
curl -s "https://TARGET/wp-content/ai1wm-backups/" -o /dev/null -w "%{http_code}"

# Export endpoint detection
curl -s "https://TARGET/wp-content/plugins/all-in-one-wp-migration/lib/view/export/" -o /dev/null -w "%{http_code}"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2024-9162 | 7.2 (HIGH) | PHP Code Injection (Export) | ≤ 7.86 | 7.87 | Missing file type validation during export |
| CVE-2024-10942 | 7.5 (HIGH) | PHP Object Injection | ≤ 7.89 | 7.90 | Deserialization in `replace_serialize()` |
| CVE-2022-1476 | 6.6 (MEDIUM) | Arbitrary File Deletion | < 7.42 | 7.42 | Directory traversal in backups model |
| CVE-2024-8852 | 5.3 (MEDIUM) | Sensitive Info Exposure | ≤ 7.86 | 7.87 | Log files exposed publicly |
| CVE-2021-24216 | 7.2 (HIGH) | Arbitrary File Upload | < 7.41 | 7.41 | Admins can upload PHP files (multisite too) |
| CVE-2022-2546 | 4.7 (MEDIUM) | XSS (Export response) | < 7.63 | 7.63 | Wrong content type, missing escaping |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🔴 **Critical** | Full database export, file system access, backup storage |
| Historical Exploitation | 🟡 **High** | PHP Object Injection (7.5) and Code Injection (7.2) |
| Version Detection Difficulty | 🟢 **Easy** | Free on WordPress.org, readme available |
| Remediation Urgency | 🟡 **High** | Exposed backups = full site compromise |

---

### 12. UpdraftPlus

#### Overview

- **Slug:** `updraftplus`
- **Active Installs (WPScan):** 3M+
- **WPScan Vulnerabilities:** 20+
- **Repository:** https://wordpress.org/plugins/updraftplus/
- **Premium:** `updraftplus-premium`

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/updraftplus/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/updraftplus/js/updraftplus-admin.js" | grep -i "ver="

# Known paths
curl -s "https://TARGET/wp-content/updraft/" -o /dev/null -w "%{http_code}"

# Backup log exposure
curl -s "https://TARGET/wp-content/updraft/log.XXXXXX.txt" -o /dev/null -w "%{http_code}"

# Plugin info
curl -s "https://TARGET/wp-content/plugins/updraftplus/updraftplus.php" 2>/dev/null | grep -i "version"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2024-10957 | 8.8 (HIGH) | PHP Object Injection | 1.23.8 – 1.24.11 | 1.24.12 | Deserialization in `recursive_` functions |
| CVE-2026-10795 | 8.1 (HIGH) | Authentication Bypass | ≤ 1.26.4 | 1.26.5 | Remote Communications V2 |
| CVE-2023-32960 | 7.1 (HIGH) | CSRF → XSS | ≤ 1.23.3 | 1.23.4 | CSRF leads to sitewide XSS |
| CVE-2017-16871 | ? | Race Condition → RCE | ≤ 1.13.12 | 1.13.13 | `plupload_action()` race condition |
| CVE-2022-0633 | 6.5 (MEDIUM) | Missing Authorization | Free < 1.22.3 / Premium < 2.22.3 | 1.22.3 | Backup nonce access by any user |
| CVE-2021-25022 | 6.1 (MEDIUM) | Reflected XSS | < 1.16.66 | 1.16.66 | Backup parameters not sanitized |
| CVE-2017-16870 | ? | SSRF | ≤ 1.13.12 | 1.13.13 | `httpget` subaction SSRF |
| CVE-2023-5982 | 5.4 (MEDIUM) | CSRF | ≤ 1.23.10 | 1.23.11 | Missing nonce on AJAX actions |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🔴 **Critical** | Backup files contain entire site data; remote storage connections |
| Historical Exploitation | 🟡 **High** | RCE via race condition, auth bypass, object injection |
| Version Detection Difficulty | 🟢 **Easy** | Free on WordPress.org |
| Remediation Urgency | 🔴 **Immediate** | Exposed backup directory = site compromise; auth bypass is critical |

---

### 13. Really Simple SSL

#### Overview

- **Slug:** `really-simple-ssl`
- **Active Installs (WPScan):** 5M+
- **WPScan Vulnerabilities:** 10+
- **Repository:** https://wordpress.org/plugins/really-simple-ssl/
- **Note:** Active on most SSL-enabled WordPress sites

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/really-simple-ssl/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/really-simple-ssl/assets/css/main.css" | grep -i "ver="

# SSL test endpoint (if enabled)
curl -s "https://TARGET/wp-content/plugins/really-simple-ssl/ssl-test-page.php" -o /dev/null -w "%{http_code}"

# Plugin file
curl -s "https://TARGET/wp-content/plugins/really-simple-ssl/really-simple-ssl.php" 2>/dev/null | grep -i "version"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2026-48970 | 8.1 (HIGH) | Unauthenticated Broken Authentication | ≤ 9.5.10 | 9.5.11 | Unauthenticated auth bypass |
| CVE-2026-48969 | 6.5 (MEDIUM) | Subscriber Broken Access Control | ≤ 9.5.9 | 9.5.10 | ACL bypass for subscribers |
| CVE-2024-31229 | 5.5 (MEDIUM) | SSRF | ≤ 7.2.3 | 7.2.4 | Server-Side Request Forgery |
| CVE-2025-24623 | 4.3 (MEDIUM) | CSRF | ≤ ? | ? | Cross-Site Request Forgery |
| CVE-2026-32461 | 4.3 (MEDIUM) | Missing Authorization | ≤ ? | ? | Incorrect ACL configuration |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟢 **Low** | Mostly configuration, minimal file handling |
| Historical Exploitation | 🟡 **Medium** | Recent auth bypass (CVE-2026-48970, 8.1) is concerning |
| Version Detection Difficulty | 🟢 **Easy** | Free plugin, readme available |
| Remediation Urgency | 🟡 **High** | Auth bypass on a plugin installed on 5M+ sites |

---

### 14. Advanced Custom Fields (ACF)

#### Overview

- **Slug:** `advanced-custom-fields`
- **Active Installs (WPScan):** 2M+
- **WPScan Vulnerabilities:** 15+
- **Repository:** https://wordpress.org/plugins/advanced-custom-fields/
- **Pro:** `advanced-custom-fields-pro`
- **Note:** ACF Extended (`acf-extended`) also has vulnerabilities

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/advanced-custom-fields/readme.txt" | grep -i "stable tag"

# Pro version
curl -s "https://TARGET/wp-content/plugins/advanced-custom-fields-pro/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/advanced-custom-fields/assets/build/js/acf.min.js" | grep -i "ver="

# REST API field exposure (detect if ACF is active)
curl -s "https://TARGET/wp-json/acf/v3/options/..." -o /dev/null -w "%{http_code}"

# Generator tag
curl -s "https://TARGET/" | grep -i "advanced custom fields\|acf"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2026-8382 | 5.3 (MEDIUM) | Authorization Bypass | ≤ 6.8.1 | 6.8.2 | Unverified user permissions |
| CVE-2026-8809 | 9.8 (CRITICAL) | Privilege Escalation (ACF Extended) | ≤ 0.9.2.5 | 0.9.2.6 | Validation bypass |
| CVE-2026-4812 | 5.3 (MEDIUM) | Missing Authorization | ≤ 6.7.0 | 6.7.1 | Arbitrary post/page disclosure via AJAX |
| CVE-2024-49593 | 5.3 (MEDIUM) | Field Editor Code Execution | < 6.3.9 | 6.3.9 | Using Field Group editor can result in code execution |
| CVE-2025-60208 | 8.8 (HIGH) | CSRF → Object Injection | ACF: CPT Options Pages | Patched | CSRF leads to object injection |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟡 **High** | Field data, custom queries, REST API exposure |
| Historical Exploitation | 🟡 **Medium** | Mostly authorization issues; recent CVEs are concerning |
| Version Detection Difficulty | 🟢 **Easy** | Free version on WordPress.org |
| Remediation Urgency | 🟡 **High** | ACF Extended PE (9.8) requires immediate action if used |

---

### 15. Rank Math SEO

#### Overview

- **Slug:** `seo-by-rank-math`
- **Active Installs (WPScan):** 3M+
- **WPScan Vulnerabilities:** 25+
- **Repository:** https://wordpress.org/plugins/seo-by-rank-math/
- **Pro:** `rank-math-pro`
- **Note:** Rapidly adopted; vulnerabilities being discovered at a steady pace

#### Version Detection

```bash
# readme.txt
curl -s "https://TARGET/wp-content/plugins/seo-by-rank-math/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/seo-by-rank-math/assets/front/js/rank-math.js" | grep -i "ver="

# REST API
curl -s "https://TARGET/wp-json/rankmath/v1" -o /dev/null -w "%{http_code}"

# Generator tag
curl -s "https://TARGET/" | grep -i "rank math"

# Admin bar CSS detection
curl -s "https://TARGET/wp-content/plugins/seo-by-rank-math/assets/admin/css/rank-math-admin.css" | head -3
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2019-14786 | 6.5 (MEDIUM) | Settings Reset | 1.0.27 | 1.0.28 | Non-admin can reset all settings |
| CVE-2022-36376 | 6.8 (MEDIUM) | SSRF | ≤ 1.0.95 | 1.0.96 | Server-Side Request Forgery |
| CVE-2023-23888 | 7.6 (HIGH) | Path Traversal | ≤ 1.0.107 | 1.0.108 | Path Traversal |
| CVE-2023-32800 | 7.1 (HIGH) | Reflected XSS (Pro) | ≤ 3.0.35 | 3.0.36 | Unauth reflected XSS |
| CVE-2024-2536 | 6.4 (MEDIUM) | Stored XSS (HowTo block) | ≤ 1.0.214 | 1.0.215 | Block attribute XSS |
| CVE-2024-9314 | 7.2 (HIGH) | PHP Object Injection | ≤ 1.0.228 | 1.0.229 | Deserialization vulnerability |
| CVE-2024-11620 | 7.2 (HIGH) | Code Injection | ≤ 1.0.228 | 1.0.229 | Code injection via generator |
| CVE-2024-9161 | 6.5 (MEDIUM) | Missing Authorization | All versions | 1.0.229 | `update_metadata()` missing capability check |
| CVE-2026-34892 | 6.5 (MEDIUM) | Broken Access Control | ≤ 1.0.271 | 1.0.272 | Subscriber ACL bypass |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟡 **High** | REST API, meta data handling, schema generation |
| Historical Exploitation | 🟡 **High** | PHP object injection, code injection, SSRF |
| Version Detection Difficulty | 🟢 **Easy** | Free on WordPress.org |
| Remediation Urgency | 🟡 **High** | Object injection (7.2) and code injection (7.2) are serious |

---

### 16. WP Rocket

#### Overview

- **Slug:** `wp-rocket` (Premium only)
- **Active Installs:** 1M+ (Premium only)
- **WPScan Vulnerabilities:** 5+
- **Developer:** WP Media
- **Note:** Caching plugin, fewer vulnerabilities but notable history

#### Version Detection

```bash
# readme.txt (may be present)
curl -s "https://TARGET/wp-content/plugins/wp-rocket/readme.txt" | grep -i "stable tag"

# Asset version
curl -sI "https://TARGET/wp-content/plugins/wp-rocket/assets/js/wpr-css.min.js" | grep -i "ver="

# Generator tag, distinctive
curl -s "https://TARGET/" | grep -i "rocket"

# Known paths
curl -s "https://TARGET/wp-content/plugins/wp-rocket/inc/functions/" -o /dev/null -w "%{http_code}"

# Cache directory exposure
curl -s "https://TARGET/wp-content/cache/wp-rocket/" -o /dev/null -w "%{http_code}"
```

#### Critical CVE Watchlist

| CVE | CVSS | Type | Affected Versions | Patched In | Notes |
|-----|------|------|-------------------|------------|-------|
| CVE-2017-11658 | ? | LFI (Insufficient Traversal Strip) | 2.9.3 | 2.9.4 | LFI mitigation bypass, trim() is not enough |
| CVE-2023-49842 | 5.9 (MEDIUM) | Stored XSS (Maintenance Mode) | ? | ? | Rocket Maintenance Mode plugin |
| CVE-2026-28044 | 5.9 (MEDIUM) | Stored XSS | ≤ 3.19.4 | 3.19.5 | Stored XSS in WP Rocket core |

#### Risk Assessment

| Factor | Score | Notes |
|--------|-------|-------|
| Attack Surface | 🟢 **Low** | Caching engine, minimal user input processing |
| Historical Exploitation | 🟢 **Low** | Very few CVEs; LFI in 2017 was the most notable |
| Version Detection Difficulty | 🟡 **Medium** | Premium plugin; readme may be absent |
| Remediation Urgency | 🟢 **Low** | No critical CVEs; patching timeline is forgiving |

---

## Version Detection Reference

| Plugin | Slug(s) | Detection Method | Reliability | readme.txt Accessible |
|--------|---------|-----------------|-------------|----------------------|
| Elementor | `elementor` | readme.txt, asset ver, generator | ⭐⭐⭐⭐⭐ | ✅ |
| Elementor Pro | `elementor-pro` | readme.txt, asset ver | ⭐⭐⭐⭐ | ✅ (usually) |
| Essential Addons | `essential-addons-for-elementor-lite` | readme.txt, asset ver | ⭐⭐⭐⭐⭐ | ✅ |
| WooCommerce | `woocommerce` | readme.txt, asset ver, REST API, package.json | ⭐⭐⭐⭐⭐ | ✅ |
| Contact Form 7 | `contact-form-7` | readme.txt, asset ver | ⭐⭐⭐⭐⭐ | ✅ |
| Jetpack | `jetpack` | readme.txt, generator, asset ver | ⭐⭐⭐⭐⭐ | ✅ |
| Yoast SEO | `wordpress-seo` | readme.txt, generator, asset ver | ⭐⭐⭐⭐⭐ | ✅ |
| Wordfence | `wordfence` | readme.txt, distinct files | ⭐⭐⭐⭐⭐ | ✅ |
| WPBakery | `js_composer` | readme.txt (if present), generator, asset ver | ⭐⭐⭐ | ⚠️ Often stripped |
| Slider Revolution | `revslider` | readme.txt (if present), JS version string | ⭐⭐⭐ | ⚠️ Often stripped |
| Gravity Forms | `gravityforms` | readme.txt (if present), asset ver | ⭐⭐⭐ | ⚠️ Sometimes stripped |
| WPML | `sitepress-multilingual-cms` | readme.txt, generator, cookie | ⭐⭐⭐⭐ | ✅ (usually) |
| All-in-One WP Migration | `all-in-one-wp-migration` | readme.txt, asset ver | ⭐⭐⭐⭐⭐ | ✅ |
| UpdraftPlus | `updraftplus` | readme.txt, asset ver | ⭐⭐⭐⭐⭐ | ✅ |
| Really Simple SSL | `really-simple-ssl` | readme.txt, asset ver | ⭐⭐⭐⭐⭐ | ✅ |
| ACF | `advanced-custom-fields` | readme.txt, asset ver, REST API | ⭐⭐⭐⭐⭐ | ✅ |
| Rank Math SEO | `seo-by-rank-math` | readme.txt, generator, REST API | ⭐⭐⭐⭐⭐ | ✅ |
| WP Rocket | `wp-rocket` | readme.txt (if present), generator | ⭐⭐⭐ | ⚠️ Often stripped |

---

## Risk Scoring Matrix

### Scoring Methodology

Each plugin is scored on a 5-point scale per factor:

| Score | Label | Meaning |
|-------|-------|---------|
| 5 | 🔴 Critical | Multiple 9.0+ CVEs, actively exploited |
| 4 | 🟡 High | 8.0+ CVEs, regular vulnerabilities |
| 3 | 🟠 Medium | 6.0-7.9 CVEs, occasional issues |
| 2 | 🟢 Low | < 6.0 CVEs, mostly admin-facing |
| 1 | ⚪ Minimal | Very few or no relevant CVEs |

### Final Risk Matrix

| Plugin | Attack Surface | Historical Exploitation | Detection Difficulty | Remediation Urgency | **Overall Risk** |
|--------|---------------|------------------------|---------------------|-------------------|:---:|
| Elementor (Core) | 5 | 5 | 1 (easy) | 4 | **🔴 5** |
| Elementor Pro | 5 | 5 | 2 (medium) | 5 | **🔴 5** |
| Essential Addons | 5 | 5 | 1 (easy) | 5 | **🔴 5** |
| WooCommerce | 5 | 4 | 1 (easy) | 4 | **🔴 4.5** |
| Contact Form 7 | 5 | 5 | 1 (easy) | 5 | **🔴 5** |
| Jetpack | 4 | 3 | 1 (easy) | 3 | **🟡 3.5** |
| Yoast SEO | 4 | 4 | 1 (easy) | 3 | **🟡 4** |
| Wordfence | 2 | 1 | 1 (easy) | 1 | **🟢 1.5** |
| WPBakery | 4 | 4 | 3 (hard) | 4 | **🟡 4** |
| Slider Revolution | 5 | 5 | 3 (hard) | 5 | **🔴 5** |
| Gravity Forms | 5 | 5 | 3 (hard) | 5 | **🔴 5** |
| WPML | 4 | 3 | 3 (hard) | 4 | **🟡 3.5** |
| All-in-One WP Migration | 5 | 4 | 1 (easy) | 4 | **🔴 4.5** |
| UpdraftPlus | 5 | 4 | 1 (easy) | 5 | **🔴 4.5** |
| Really Simple SSL | 2 | 3 | 1 (easy) | 4 | **🟡 3** |
| ACF | 4 | 3 | 1 (easy) | 4 | **🟡 3.5** |
| Rank Math SEO | 4 | 4 | 1 (easy) | 4 | **🟡 4** |
| WP Rocket | 3 | 2 | 3 (hard) | 2 | **🟢 2.5** |

---

## CVE Watchlist Summary Table

All CVEs ≥ 8.8 or with active exploitation history relevant to remote (no-login) auditing:

| CVE | CVSS | Plugin | Type | Remote? |
|-----|------|--------|------|:-------:|
| CVE-2020-35489 | 10.0 | Contact Form 7 | Unrestricted File Upload → RCE | ✅ |
| CVE-2020-13126 | 9.9 | Elementor Pro | Arbitrary File Upload | ⚠️ (Subscriber+) |
| CVE-2020-7109 | 9.8 | Elementor | RCE | ✅ |
| CVE-2021-24175 | 9.8 | Elementor (Plus Addons) | Auth Bypass | ✅ |
| CVE-2022-0320 | 9.8 | Essential Addons for Elementor | LFI → RCE | ✅ |
| CVE-2023-32243 | 9.8 | Essential Addons for Elementor | Privilege Escalation | ✅ |
| CVE-2023-5360 | 9.8 | Royal Elementor Addons | Arbitrary File Upload | ✅ |
| CVE-2026-8809 | 9.8 | ACF Extended | Privilege Escalation | ✅ |
| CVE-2025-12352 | 9.8 | Gravity Forms | Arbitrary File Upload | ✅ |
| CVE-2025-14344 | 9.8 | Gravity Forms (Multi Uploader) | Arbitrary File Deletion | ✅ |
| CVE-2026-10580 | 9.8 | WooCommerce (Hippoo App) | Auth Bypass → Admin Takeover | ✅ |
| CVE-2019-13478 | 9.8 | Yoast SEO | Unfiltered HTML | ✅ |
| CVE-2021-24228 | 9.6 | Jetpack (Patreon) | Reflected XSS | ✅ |
| CVE-2021-24229 | 9.6 | Jetpack (Patreon) | Reflected XSS | ✅ |
| CVE-2020-13125 | 6.5 | Elementor (Ultimate Addons) | Stored XSS (exploited with 9.9) | ✅ |
| CVE-2021-32790 | 4.9 | WooCommerce | SQL Injection | ⚠️ (Shop Manager+) |
| CVE-2023-2359 | 8.8 | Slider Revolution | Arbitrary File Upload → RCE | ⚠️ (Author+) |
| CVE-2023-6528 | 8.8 | Slider Revolution | PHP Object Injection → RCE | ⚠️ (Author+) |
| CVE-2026-6692 | 8.8 | Slider Revolution | Arbitrary File Upload | ⚠️ |
| CVE-2024-5709 | 8.8 | WPBakery | Local File Inclusion | ⚠️ (Auth+) |
| CVE-2024-10957 | 8.8 | UpdraftPlus | PHP Object Injection | ⚠️ |
| CVE-2025-12974 | 8.1 | Gravity Forms | Arbitrary File Upload | ✅ |
| CVE-2025-8593 | 8.8 | Gravity Forms (GSheet) | Auth Bypass | ⚠️ |
| CVE-2025-60208 | 8.8 | ACF (CPT Options) | CSRF → Object Injection | ⚠️ |
| CVE-2017-18356 | ? | WooCommerce | Privilege Escalation | ⚠️ (Shop Manager+) |
| CVE-2024-3018 | 8.8 | Essential Addons | PHP Object Injection | ⚠️ |
| CVE-2026-10795 | 8.1 | UpdraftPlus | Authentication Bypass | ✅ |
| CVE-2026-48970 | 8.1 | Really Simple SSL | Unauthenticated Broken Auth | ✅ |

---

## Master Detection Script

Below is the master bash script that checks all 16 plugins at once with automatic version detection. It can be run against any WordPress target site.

> **⚠️ Script Location:** The script is also saved to: `scripts/07-high-risk-plugins-check.sh` alongside this file.

```bash
#!/bin/bash
# ==============================================================================
# WordPress High-Risk Plugins, Remote Version Detection & Vulnerability Scan
# ==============================================================================
# Usage:
#   ./07-high-risk-plugins-check.sh <target-url>
#
# Example:
#   ./07-high-risk-plugins-check.sh https://example.com
#
# Output:
#   - Scans all 16 high-risk plugins for version presence
#   - Highlights known-vulnerable version ranges
#   - Outputs CVSS ≥ 8.8 CVEs for matching versions
# ==============================================================================

TARGET="${1%/}"
TARGET="${TARGET:-https://example.com}"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  WordPress High-Risk Plugins Audit, Remote Version Detection${NC}"
echo -e "${CYAN}  Target: ${TARGET}${NC}"
echo -e "${CYAN}  Date:   $(date -u '+%Y-%m-%d %H:%M UTC')${NC}"
echo -e "${CYAN}================================================================================${NC}"
echo ""

# ------------------------------------------------------------------------------
# Helper function: get version from readme.txt
# ------------------------------------------------------------------------------
get_readme_version() {
    local slug="$1"
    local url="${TARGET}/wp-content/plugins/${slug}/readme.txt"
    local version
    version=$(curl -s --max-time 10 "$url" 2>/dev/null | grep -i "stable tag" | head -1 | grep -oP '\d+\.\d+(\.\d+)?')
    echo "$version"
}

# ------------------------------------------------------------------------------
# Helper function: get version from asset query string
# ------------------------------------------------------------------------------
get_asset_version() {
    local url="$1"
    local version
    version=$(curl -sI --max-time 10 "$url" 2>/dev/null | grep -i "ver=" | head -1 | sed 's/.*ver=\([^"]*\).*/\1/' | tr -d ' \r\n')
    echo "$version"
}

# ------------------------------------------------------------------------------
# Helper function: check if plugin directory exists
# ------------------------------------------------------------------------------
plugin_exists() {
    local slug="$1"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/wp-content/plugins/${slug}/" 2>/dev/null)
    # 200, 301, 302, 403 all indicate the directory exists
    if [[ "$code" == "200" ]] || [[ "$code" == "301" ]] || [[ "$code" == "302" ]] || [[ "$code" == "403" ]]; then
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
# Helper function: version comparison (returns 0 if $1 < $2)
# ------------------------------------------------------------------------------
version_lt() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

version_gte() {
    [ "$1" = "$2" ] || [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" != "$1" ]
}

# ------------------------------------------------------------------------------
# Print plugin header
# ------------------------------------------------------------------------------
print_plugin() {
    local name="$1" slug="$2" version="$3" critical_cves="$4"
    echo -e "${YELLOW}[+] ${name}${NC} (slug: ${slug})"
    echo "    Installed: ${version:----not found----}"
    if [ -n "$version" ]; then
        echo -e "    ${CYAN}Version detected via:${NC} readme.txt / asset query string"
        if [ -n "$critical_cves" ]; then
            echo -e "    ${RED}⚠ Critical CVEs affecting versions like this:${NC}"
            echo "$critical_cves" | sed 's/^/      /'
        fi
    fi
    echo ""
}

echo -e "${GREEN}Scanning ${TARGET}...${NC}"
echo ""

# ==============================================================================
# 1. Elementor
# ==============================================================================
ELEM_VER=$(get_readme_version "elementor")
[ -z "$ELEM_VER" ] && ELEM_VER=$(get_asset_version "${TARGET}/wp-content/plugins/elementor/assets/js/frontend.min.js")
ELEM_CVES=""
if [ -n "$ELEM_VER" ] && version_lt "$ELEM_VER" "3.12.2"; then
    ELEM_CVES="CVE-2023-0329 (SQLi, 7.2), fixed in 3.12.2"
fi
if [ -n "$ELEM_VER" ] && version_lt "$ELEM_VER" "2.8.5"; then
    ELEM_CVES="${ELEM_CVES} | CVE-2020-7109 (RCE, 9.8), fixed in 2.8.4"
fi
print_plugin "Elementor" "elementor" "$ELEM_VER" "$ELEM_CVES"

# ==============================================================================
# 2. Elementor Pro
# ==============================================================================
ELEMP_VER=$(get_readme_version "elementor-pro")
[ -z "$ELEMP_VER" ] && ELEMP_VER=$(get_asset_version "${TARGET}/wp-content/plugins/elementor-pro/assets/js/frontend.min.js")
ELEMP_CVES=""
if [ -n "$ELEMP_VER" ] && version_lt "$ELEMP_VER" "2.9.4"; then
    ELEMP_CVES="CVE-2020-13126 (File Upload, 9.9), fixed in 2.9.4"
fi
if [ -n "$ELEMP_VER" ] && version_lt "$ELEMP_VER" "3.11.7"; then
    ELEMP_CVES="${ELEMP_CVES} | CVE-2023-3124 (Missing Auth, 8.8), fixed in 3.11.7"
fi
print_plugin "Elementor Pro" "elementor-pro" "$ELEMP_VER" "$ELEMP_CVES"

# ==============================================================================
# 3. Essential Addons for Elementor
# ==============================================================================
EA_VER=$(get_readme_version "essential-addons-for-elementor-lite")
[ -z "$EA_VER" ] && EA_VER=$(get_asset_version "${TARGET}/wp-content/plugins/essential-addons-for-elementor-lite/assets/front/js/essential-addons.min.js")
EA_CVES=""
if [ -n "$EA_VER" ] && version_lt "$EA_VER" "5.0.5"; then
    EA_CVES="CVE-2022-0320 (LFI→RCE, 9.8), fixed in 5.0.5"
fi
if [ -n "$EA_VER" ] && version_gte "$EA_VER" "5.4.0" && version_lt "$EA_VER" "5.7.2"; then
    EA_CVES="${EA_CVES} | CVE-2023-32243 (PE, 9.8), fixed in 5.7.2"
fi
if [ -n "$EA_VER" ] && version_lt "$EA_VER" "5.9.14"; then
    EA_CVES="${EA_CVES} | CVE-2024-3018 (Object Injection, 8.8), fixed in 5.9.14"
fi
print_plugin "Essential Addons for Elementor" "essential-addons-for-elementor-lite" "$EA_VER" "$EA_CVES"

# ==============================================================================
# 4. WooCommerce
# ==============================================================================
WC_VER=$(get_readme_version "woocommerce")
[ -z "$WC_VER" ] && WC_VER=$(get_asset_version "${TARGET}/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.min.js")
# Try package.json as fallback
if [ -z "$WC_VER" ]; then
    WC_VER=$(curl -s --max-time 10 "${TARGET}/wp-content/plugins/woocommerce/package.json" 2>/dev/null | grep -oP '"version":\s*"\K[^"]+')
fi
WC_CVES=""
if [ -n "$WC_VER" ] && version_gte "$WC_VER" "3.3.0" && version_lt "$WC_VER" "3.3.6"; then
    WC_CVES="CVE-2021-32790 (SQLi, 4.9)"
fi
if [ -n "$WC_VER" ] && version_lt "$WC_VER" "3.5.5"; then
    WC_CVES="${WC_CVES} | CVE-2019-9168 (XSS)"
fi
if [ -n "$WC_VER" ] && version_lt "$WC_VER" "10.5.3"; then
    WC_CVES="${WC_CVES} | CSRF→Admin Creation (7.5, 2026), fixed in 10.5.3"
fi
print_plugin "WooCommerce" "woocommerce" "$WC_VER" "$WC_CVES"

# ==============================================================================
# 5. Contact Form 7
# ==============================================================================
CF7_VER=$(get_readme_version "contact-form-7")
[ -z "$CF7_VER" ] && CF7_VER=$(get_asset_version "${TARGET}/wp-content/plugins/contact-form-7/includes/js/scripts.js")
CF7_CVES=""
if [ -n "$CF7_VER" ] && version_lt "$CF7_VER" "5.3.2"; then
    CF7_CVES="CVE-2020-35489 (File Upload→RCE, 10.0), CRITICAL, fixed in 5.3.2"
fi
print_plugin "Contact Form 7" "contact-form-7" "$CF7_VER" "$CF7_CVES"

# ==============================================================================
# 6. Jetpack
# ==============================================================================
JET_VER=$(get_readme_version "jetpack")
[ -z "$JET_VER" ] && JET_VER=$(get_asset_version "${TARGET}/wp-content/plugins/jetpack/jetpack.php")
JET_CVES=""
if [ -n "$JET_VER" ] && version_lt "$JET_VER" "12.1.1"; then
    JET_CVES="CVE-2023-2996 (File Deletion, 8.8), fixed in 12.1.1"
fi
if [ -n "$JET_VER" ] && version_lt "$JET_VER" "13.3.2"; then
    JET_CVES="${JET_CVES} | CVE-2024-4392 (Stored XSS, 6.4), fixed in 13.3.2"
fi
print_plugin "Jetpack" "jetpack" "$JET_VER" "$JET_CVES"

# ==============================================================================
# 7. Yoast SEO
# ==============================================================================
YOAST_VER=$(get_readme_version "wordpress-seo")
[ -z "$YOAST_VER" ] && YOAST_VER=$(get_asset_version "${TARGET}/wp-content/plugins/wordpress-seo/js/dist/yoastseo.min.js")
YOAST_CVES=""
if [ -n "$YOAST_VER" ] && version_lt "$YOAST_VER" "22.5"; then
    YOAST_CVES="CVE-2024-4041 (Reflected XSS, 6.1), fixed in 22.5"
fi
if [ -n "$YOAST_VER" ] && version_lt "$YOAST_VER" "22.7"; then
    YOAST_CVES="${YOAST_CVES} | CVE-2024-4984 (Stored XSS, 6.4), fixed in 22.7"
fi
print_plugin "Yoast SEO" "wordpress-seo" "$YOAST_VER" "$YOAST_CVES"

# ==============================================================================
# 8. Wordfence Security
# ==============================================================================
WF_VER=$(get_readme_version "wordfence")
[ -z "$WF_VER" ] && WF_VER=$(get_asset_version "${TARGET}/wp-content/plugins/wordfence/css/wordfenceBox.css")
WF_CVES=""
if [ -n "$WF_VER" ] && version_lt "$WF_VER" "7.6.1"; then
    WF_CVES="CVE-2022-3144 (Stored XSS, 4.4), fixed in 7.6.1"
fi
print_plugin "Wordfence Security" "wordfence" "$WF_VER" "$WF_CVES"

# ==============================================================================
# 9. WPBakery / Visual Composer
# ==============================================================================
WPB_VER=$(get_readme_version "js_composer")
[ -z "$WPB_VER" ] && WPB_VER=$(get_asset_version "${TARGET}/wp-content/plugins/js_composer/assets/js/js_composer_front.min.js")
WPB_CVES=""
if [ -n "$WPB_VER" ] && version_lt "$WPB_VER" "7.7"; then
    WPB_CVES="CVE-2024-5709 (LFI, 8.8), fixed in 7.7"
fi
if [ -n "$WPB_VER" ] && version_lt "$WPB_VER" "7.6"; then
    WPB_CVES="${WPB_CVES} | CVE-2024-5265 (Stored XSS, 6.4), fixed in 7.6"
fi
print_plugin "WPBakery / Visual Composer" "js_composer" "$WPB_VER" "$WPB_CVES"

# Also check visualcomposer slug
VC_VER=$(get_readme_version "visualcomposer")
if [ -z "$WPB_VER" ] && [ -n "$VC_VER" ]; then
    print_plugin "Visual Composer (alternative slug)" "visualcomposer" "$VC_VER" ""
fi

# ==============================================================================
# 10. Slider Revolution
# ==============================================================================
RS_VER=$(get_readme_version "revslider")
[ -z "$RS_VER" ] && RS_VER=$(get_asset_version "${TARGET}/wp-content/plugins/revslider/public/assets/js/rs-front-end.min.js")
RS_CVES=""
if [ -n "$RS_VER" ] && version_lt "$RS_VER" "6.6.13"; then
    RS_CVES="CVE-2023-2359 (File Upload→RCE, 8.8), fixed in 6.6.13"
fi
if [ -n "$RS_VER" ] && version_lt "$RS_VER" "6.6.19"; then
    RS_CVES="${RS_CVES} | CVE-2023-6528 (Object Injection→RCE, 8.8), fixed in 6.6.19"
fi
if [ -n "$RS_VER" ] && version_lt "$RS_VER" "6.7.19"; then
    RS_CVES="${RS_CVES} | CVE-2024-8107 (SVG XSS, 6.4), fixed in 6.7.19"
fi
print_plugin "Slider Revolution" "revslider" "$RS_VER" "$RS_CVES"

# ==============================================================================
# 11. Gravity Forms
# ==============================================================================
GF_VER=$(get_readme_version "gravityforms")
[ -z "$GF_VER" ] && GF_VER=$(get_asset_version "${TARGET}/wp-content/plugins/gravityforms/js/gravityforms.min.js")
GF_CVES=""
if [ -n "$GF_VER" ] && version_lt "$GF_VER" "2.9.21"; then
    GF_CVES="CVE-2025-12352 (File Upload→RCE, 9.8), fixed in 2.9.21"
fi
if [ -n "$GF_VER" ] && version_lt "$GF_VER" "2.9.21.2"; then
    GF_CVES="${GF_CVES} | CVE-2025-12974 (File Upload, 8.1), fixed in 2.9.21.2"
fi
print_plugin "Gravity Forms" "gravityforms" "$GF_VER" "$GF_CVES"

# ==============================================================================
# 12. WPML
# ==============================================================================
WPML_VER=$(get_readme_version "sitepress-multilingual-cms")
[ -z "$WPML_VER" ] && WPML_VER=$(get_asset_version "${TARGET}/wp-content/plugins/sitepress-multilingual-cms/res/js/sitepress.js")
WPML_CVES=""
if [ -n "$WPML_VER" ] && version_lt "$WPML_VER" "4.5.11"; then
    WPML_CVES="CVE-2022-38461 (Broken ACL, 5.4), fixed in 4.5.11"
fi
if [ -n "$WPML_VER" ] && version_lt "$WPML_VER" "4.5.14"; then
    WPML_CVES="${WPML_CVES} | CVE-2022-45071 (CSRF, 5.4), fixed in 4.5.14"
fi
print_plugin "WPML" "sitepress-multilingual-cms" "$WPML_VER" "$WPML_CVES"

# ==============================================================================
# 13. All-in-One WP Migration
# ==============================================================================
AI1WM_VER=$(get_readme_version "all-in-one-wp-migration")
[ -z "$AI1WM_VER" ] && AI1WM_VER=$(get_asset_version "${TARGET}/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/javascript/backups.min.js")
AI1WM_CVES=""
if [ -n "$AI1WM_VER" ] && version_lt "$AI1WM_VER" "7.87"; then
    AI1WM_CVES="CVE-2024-9162 (Code Injection, 7.2), fixed in 7.87"
fi
if [ -n "$AI1WM_VER" ] && version_lt "$AI1WM_VER" "7.90"; then
    AI1WM_CVES="${AI1WM_CVES} | CVE-2024-10942 (Object Injection, 7.5), fixed in 7.90"
fi
print_plugin "All-in-One WP Migration" "all-in-one-wp-migration" "$AI1WM_VER" "$AI1WM_CVES"

# ==============================================================================
# 14. UpdraftPlus
# ==============================================================================
UD_VER=$(get_readme_version "updraftplus")
[ -z "$UD_VER" ] && UD_VER=$(get_asset_version "${TARGET}/wp-content/plugins/updraftplus/js/updraftplus-admin.js")
UD_CVES=""
if [ -n "$UD_VER" ] && version_gte "$UD_VER" "1.23.8" && version_lt "$UD_VER" "1.24.12"; then
    UD_CVES="CVE-2024-10957 (Object Injection, 8.8), fixed in 1.24.12"
fi
if [ -n "$UD_VER" ] && version_lt "$UD_VER" "1.26.5"; then
    UD_CVES="${UD_CVES} | CVE-2026-10795 (Auth Bypass, 8.1), fixed in 1.26.5"
fi
print_plugin "UpdraftPlus" "updraftplus" "$UD_VER" "$UD_CVES"

# ==============================================================================
# 15. Really Simple SSL
# ==============================================================================
RSSSL_VER=$(get_readme_version "really-simple-ssl")
[ -z "$RSSSL_VER" ] && RSSSL_VER=$(get_asset_version "${TARGET}/wp-content/plugins/really-simple-ssl/assets/css/main.css")
RSSSL_CVES=""
if [ -n "$RSSSL_VER" ] && version_lt "$RSSSL_VER" "7.2.4"; then
    RSSSL_CVES="CVE-2024-31229 (SSRF, 5.5), fixed in 7.2.4"
fi
if [ -n "$RSSSL_VER" ] && version_lt "$RSSSL_VER" "9.5.11"; then
    RSSSL_CVES="${RSSSL_CVES} | CVE-2026-48970 (Auth Bypass, 8.1), fixed in 9.5.11"
fi
print_plugin "Really Simple SSL" "really-simple-ssl" "$RSSSL_VER" "$RSSSL_CVES"

# ==============================================================================
# 16. Advanced Custom Fields (ACF)
# ==============================================================================
ACF_VER=$(get_readme_version "advanced-custom-fields")
[ -z "$ACF_VER" ] && ACF_VER=$(get_asset_version "${TARGET}/wp-content/plugins/advanced-custom-fields/assets/build/js/acf.min.js")
ACF_CVES=""
if [ -n "$ACF_VER" ] && version_lt "$ACF_VER" "6.3.9"; then
    ACF_CVES="CVE-2024-49593 (Field Editor Code Execution, 5.3), fixed in 6.3.9"
fi
if [ -n "$ACF_VER" ] && version_lt "$ACF_VER" "6.8.2"; then
    ACF_CVES="${ACF_CVES} | CVE-2026-8382 (Auth Bypass, 5.3), fixed in 6.8.2"
fi
print_plugin "Advanced Custom Fields (ACF)" "advanced-custom-fields" "$ACF_VER" "$ACF_CVES"

# ==============================================================================
# 17. Rank Math SEO
# ==============================================================================
RM_VER=$(get_readme_version "seo-by-rank-math")
[ -z "$RM_VER" ] && RM_VER=$(get_asset_version "${TARGET}/wp-content/plugins/seo-by-rank-math/assets/front/js/rank-math.js")
RM_CVES=""
if [ -n "$RM_VER" ] && version_lt "$RM_VER" "1.0.229"; then
    RM_CVES="CVE-2024-9314 (Object Injection, 7.2), fixed in 1.0.229"
    RM_CVES="${RM_CVES} | CVE-2024-11620 (Code Injection, 7.2), fixed in 1.0.229"
fi
if [ -n "$RM_VER" ] && version_lt "$RM_VER" "1.0.272"; then
    RM_CVES="${RM_CVES} | CVE-2026-34892 (Broken ACL, 6.5), fixed in 1.0.272"
fi
print_plugin "Rank Math SEO" "seo-by-rank-math" "$RM_VER" "$RM_CVES"

# ==============================================================================
# 18. WP Rocket
# ==============================================================================
WPR_VER=$(get_readme_version "wp-rocket")
[ -z "$WPR_VER" ] && WPR_VER=$(get_asset_version "${TARGET}/wp-content/plugins/wp-rocket/assets/js/wpr-css.min.js")
WPR_CVES=""
if [ -n "$WPR_VER" ] && version_lt "$WPR_VER" "3.19.5"; then
    WPR_CVES="CVE-2026-28044 (Stored XSS, 5.9), fixed in 3.19.5"
fi
print_plugin "WP Rocket" "wp-rocket" "$WPR_VER" "$WPR_CVES"

# ==============================================================================
# Summary
# ==============================================================================
echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  Scan Complete${NC}"
echo ""
echo -e "  Plugins detected with versions: ${GREEN}(see above)${NC}"
echo -e "  Plugins with known CVEs flagged: ${RED}(noted in scan)${NC}"
echo ""
echo -e "  ${YELLOW}Recommended actions:${NC}"
echo -e "  1. Update ALL plugins to latest versions"
echo -e "  2. Replace Slider Revolution with a maintained alternative"
echo -e "  3. Remove unused plugins entirely"
echo -e "  4. Disable XML-RPC if not needed"
echo -e "  5. Remove readme.txt and other version-leaking files in production"
echo ""
echo -e "${CYAN}================================================================================${NC}"
```

---

## Quick-Start Commands

### Single-line Audit (all plugins)

```bash
./07-high-risk-plugins-check.sh https://victim-site.com
```

### Just Check readme.txt Versions

```bash
for plugin in elementor elementor-pro essential-addons-for-elementor-lite woocommerce contact-form-7 jetpack wordpress-seo wordfence js_composer revslider gravityforms sitepress-multilingual-cms all-in-one-wp-migration updraftplus really-simple-ssl advanced-custom-fields seo-by-rank-math wp-rocket; do
    ver=$(curl -s "https://TARGET/wp-content/plugins/$plugin/readme.txt" 2>/dev/null | grep -i "stable tag" | grep -oP '\d+\.\d+(\.\d+)?')
    [ -n "$ver" ] && echo "$plugin: $ver" || echo "$plugin: NOT FOUND"
done
```

### Check Vulnerable Backup File Exposure

```bash
# Check for exposed backup files
curl -s -o /dev/null -w "%{http_code}" "https://TARGET/wp-content/ai1wm-backups/"
curl -s -o /dev/null -w "%{http_code}" "https://TARGET/wp-content/updraft/"
curl -s -o /dev/null -w "%{http_code}" "https://TARGET/wp-content/cache/wp-rocket/"
```

---

## Disclaimer

This document is intended for **professional security auditing** with proper authorization. Scanning websites without permission may violate applicable laws. Always obtain written authorization before conducting any security assessment.

---

*Generated using NVD API v2.0, WPScan, Wordfence Threat Intelligence, and MITRE CVE database.*  
*Last updated: July 2026*
