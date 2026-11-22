# WordPress Multisite Security Audit Checklist

> **Context:** Remote audit, no login, no admin access. Only applicable **after** multisite has been detected.
> **Severity levels:** 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low

---

## Detection: Is This a Multisite?

Before running any multisite-specific checks, confirm the target runs a WordPress Multisite (WPMU) network. No single check is 100% conclusive, combine multiple signals.

### 1.1, Check `/wp-signup.php` (Multisite Landing Page)

| Field | Value |
|---|---|
| **Detection** | The file `wp-signup.php` only exists in Multisite. On a single-site install it returns 404 or redirects. A 200 response with "Create a New Site" or registration form is a strong multisite indicator. |
| **Curl Command** | `curl -sL -o /dev/null -w "%{http_code}" "https://target.com/wp-signup.php"` |
| **Severity** | 🔵 Low (detection signal only) |
| **Note** | Returns 200 even if registration is disabled (shows "Registration has been disabled" message). |

### 1.2, Check REST API: `/wp/v2/sites` Endpoint

| Field | Value |
|---|---|
| **Detection** | The `/wp/v2/sites` namespace is **multisite-only**. A single-site install routes this to a 404 or returns an empty array. A 200 response with site data confirms multisite. |
| **Curl Command** | `curl -sL "https://target.com/wp-json/wp/v2/sites" \| jq '.'` |
| **Severity** | 🔵 Low (detection signal only) |
| **Note** | Requires `show_in_rest` on the site object. Some hardened multisites disable this. Empty response (`[]`) does not rule out multisite. |

### 1.3, Check REST API Namespace: `/wp/v2/sites/` in Headers

| Field | Value |
|---|---|
| **Detection** | Look for `X-WP-Total` or `X-WP-TotalPages` headers specific to site endpoints. Single-site installs have no sites controller. |
| **Curl Command** | `curl -sI "https://target.com/wp-json/wp/v2/sites"` |
| **Severity** | 🔵 Low (detection signal only) |

### 1.4, Check for Multisite Cookies

| Field | Value |
|---|---|
| **Detection** | Multisite sets **two session cookie names**: `wordpress_logged_in_*` (hashed by site ID) and a network-level cookie. Presence of these in login forms is a clue. Also check for `wp-settings-time-*` and `wp-settings-*`. |
| **Curl Command** | `curl -sIc "/wp-login.php" "https://target.com/wp-login.php" \| grep -i "wordpress_"` |
| **Severity** | 🔵 Low (detection signal only) |

### 1.5, Check for `/wp-sites.php`

| Field | Value |
|---|---|
| **Detection** | A rarely-removed admin file from older WPMU installations. Accessible remotely even if not hardened. |
| **Curl Command** | `curl -sL -o /dev/null -w "%{http_code}" "https://target.com/wp-sites.php"` |
| **Severity** | 🟡 Medium (legacy exposure if 200) |
| **Note** | Removed in newer WP. A 200 response on modern WP means custom/legacy plugin. |

### 1.6, Check `wp-json` Namespace for Multisite Signals

| Field | Value |
|---|---|
| **Detection** | Compare `/wp/v2/users` response for `X-WP-Total`, in multisite, the user list often shows network-wide users rather than just site-local ones (depends on `wp_rest_user_enum` setup). |
| **Curl Command** | `curl -sI "https://target.com/wp-json/wp/v2/users?per_page=1"` |
| **Severity** | 🔵 Low (detection signal only) |

### 1.7, Check Source HTML for Multisite Patterns

| Field | Value |
|---|---|
| **Detection** | Look for `wpmu` or `ms-files` in page source, admin bar links pointing to `wp-admin/network/`, or `site_id` in REST API responses. |
| **Curl Command** | `curl -sL "https://target.com/" \| grep -oiE "(wpmu|ms-files|network/sites|/sites/|site_id)"` |
| **Severity** | 🔵 Low (detection signal only) |

---

## Checklist Items (Run Only If Multisite Confirmed)

---

### ① Network-Wide User Enumeration

**Risk:** In Multisite, the REST API `/wp/v2/users` endpoint may leak **all network users** (all subsites) instead of only users of the current site. This massively expands the enumeration surface.

| Field | Value |
|---|---|
| **Detection** | Call the users endpoint and check the `X-WP-Total` header. If the number far exceeds what a single site would have, network-wide enumeration is possible. Compare against a known site user count. |
| **Curl Command** | `curl -sI "https://target.com/wp-json/wp/v2/users?per_page=1"` then `curl -s "https://target.com/wp-json/wp/v2/users?per_page=100" \| jq '.[].slug' \| wc -l` |
| **Severity** | 🟠 High |
| **Risk** | Username harvesting for brute-force attacks on any site in the network. Author slugs reveal user IDs across subsites. |
| **Mitigation** | Disable REST API user endpoint via filter, or restrict `wp_rest_user_enum`. Use a plugin like "Disable REST API" or "Disable Users REST API". |

---

### ② Cross-Site Contamination (Subsite → Main Site)

**Risk:** In a Multisite network, a compromised subsite (e.g., a vulnerable plugin or theme on one site) can potentially **escalate to the network admin** via:
- Shared `wp-config.php` containing database credentials
- Shared `wp_users` table (network-wide user list accessible from any subsite)
- SQL injection on one subsite → all sites share the same database
- File inclusion across subsites

| Field | Value |
|---|---|
| **Detection** | Probe if subsites run different plugin/theme versions. Look for outdated plugins on any subsite. Check if domain-mapped subsites share the same document root. Verify if `DISALLOW_FILE_EDIT` and `DISALLOW_FILE_MODS` are defined. |
| **Curl Command** | Check plugin version mismatch across subsites: `curl -sL "https://subsite1.target.com/wp-json/wp/v2/plugins"` vs `curl -sL "https://subsite2.target.com/wp-json/wp/v2/plugins"` (requires auth). For unauthenticated checks, probe theme stylesheet version strings: `curl -sL "https://subsite1.target.com/wp-content/themes/..."` |
| **Severity** | 🔴 Critical |
| **Risk** | Full network takeover from a single compromised subsite. |
| **Mitigation** | Enforce `DISALLOW_FILE_MODS` network-wide. Isolate file permissions. Use `define('WP_ALLOW_MULTISITE', false);` in subsite contexts? No, proper hardening involves `define('DISALLOW_FILE_EDIT', true);` and `define('DISALLOW_FILE_MODS', true);` in `wp-config.php`. Enable `FORCE_SSL_ADMIN`. |

---

### ③ Signup Option Enabled (Anyone Can Create a Site)

| Field | Value |
|---|---|
| **Detection** | Visit `/wp-signup.php`. If the page shows a **registration form** allowing new site creation, signups are enabled. If it says "Registration has been disabled" or redirects, they are disabled. |
| **Curl Command** | `curl -sL "https://target.com/wp-signup.php" \| grep -iE "(create a new site|register a new site|get your own)" \| head -5` |
| **Severity** | 🟠 High |
| **Risk** | Anyone can register a site on the network, leading to spam, phishing subdomains, and resource exhaustion. |
| **Mitigation** | Disable "Allow new registrations" in Network Settings → Settings. Or set to "Registration is disabled". For legitimate needs, restrict to user accounts only (no new sites). |

---

### ④ New Site Verification Disabled (Instant Site Creation)

| Field | Value |
|---|---|
| **Detection** | In Multisite, the admin can bypass email verification for new sites (`NOBLOGREDIRECT` or registration settings). Check the signup flow, if a site is **created immediately** without email confirmation, verification is disabled. |
| **Curl Command** | `curl -sL "https://target.com/wp-signup.php" \| grep -iE "(email|verify|confirm|activate)"`, absence of confirmation/activation language suggests verification is off. Also test by attempting registration. |
| **Severity** | 🟠 High |
| **Risk** | Automated abuse: bots can create thousands of sites instantly without any email validation, used for spam SEO farms and phishing. |
| **Mitigation** | Enable "Registration notification" and email activation in Network Settings. Set `add_new_users_to_blog` carefully. Verify `get_site_option('registration')` value, should be 'none' or 'user' (not 'blog' or 'all'). |

---

### ⑤ Upload Space Check (Site Upload Quota)

| Field | Value |
|---|---|
| **Detection** | In Multisite, super admins can set upload space quotas per site. If **unlimited**, a compromised or malicious subsite can fill the disk. Check via REST API for site settings, or probe file upload capabilities. |
| **Curl Command** | `curl -sL "https://target.com/wp-json/wp/v2/settings" \| jq '.blog_upload_space'`, if returns `null` or absent, check: `curl -sL "https://target.com/wp-json/better-rest-api-endpoints/v1/site-info"` (plugin-dependent). For black-box: upload a test file via media endpoint and check for space errors. |
| **Severity** | 🟡 Medium |
| **Risk** | Disk exhaustion, denial of service via upload flood, abuse of storage for phishing/file hosting. |
| **Mitigation** | Set reasonable upload space quotas per site in Network Admin → Sites → Edit Site → Settings. Monitor disk usage network-wide. Enable `upload_space_check()` via disabling "Site upload space check" or setting explicit limits. |

---

### ⑥ Domain Mapping Check (Subdirectories, Subdomains, or Custom Domains)

| Field | Value |
|---|---|
| **Detection** | Multisite uses one of three URL schemes. The scheme affects the attack surface: **Custom domains** add the most complexity (DNS, SSL, cookie scope). |
| **Curl Command** | **Subdirectory check:** `curl -sI "https://target.com/site1/" \| grep -i "200\|301\|302"`, if a subdirectory returns content, it's subdirectory-based. **Subdomain check:** `curl -sI "https://site1.target.com/" \| grep -i "200"`, if it loads, it's subdomain-based. **Custom domain check:** `curl -sI "https://someotherdomain.com/"`, if it loads the same WordPress, custom domain mapping is active. Also check: `curl -sL "https://target.com/wp-json/" \| jq '.namespaces'` and look for domain-mapping plugin namespaces. |
| **Severity** | 🟡 Medium (varies by scheme) |
| **Risk** | **Subdirectory:** Minimal, cookie visibility is per-path. **Subdomain:** Medium, cookies can be scoped to `.target.com` if misconfigured, allowing cross-subsite session hijacking. **Custom domains:** High, wildcard SSL issues, DNS hijacking risk, cookie leakage across entirely different domain names if not properly scoped. |
| **Mitigation** | For subdomains: use `COOKIE_DOMAIN` with per-site cookie scope. For custom domains: validate domain ownership, use Let's Encrypt for all mapped domains, configure `SUNRISE` and domain mapping carefully. Disable wildcard SSL unless necessary. |

---

### ⑦ Network Admin URL Exposure (wp-admin/network/)

| Field | Value |
|---|---|
| **Detection** | The network admin is normally restricted to super admins, but the URL path `/wp-admin/network/` should not be discoverable by regular users. Check if it leaks information or shows a login form with different wording. |
| **Curl Command** | `curl -sL -o /dev/null -w "%{http_code}" "https://target.com/wp-admin/network/"`, if 200 (shows login form for network admin) vs single-site `/wp-admin/` (200 shows regular login), you can detect multisite. If the response body contains "Get a new password" or "Network Admin" text, it's exposed. Also: `curl -sL "https://target.com/wp-admin/network/" \| grep -iE "(network admin|super admin|manage sites)"` |
| **Severity** | 🟠 High (if response differs from regular admin login) |
| **Risk** | Attackers can distinguish multisite from single-site, target super admin accounts specifically, and brute-force the network-level login. The network admin login is a high-value target. |
| **Mitigation** | Hide /wp-admin/network/ behind IP whitelist or VPN. Use a security plugin to rename or protect admin paths. Monitor failed login attempts targeting `/wp-admin/network/`. |

---

### ⑧ Super Admin Enumeration

| Risk: | In Multisite, the `super_admin` role exists network-wide. Super admins can be enumerated if the REST API exposes user roles with `is_super_admin` flags, or through ID bruteforcing on `/wp/v2/users`, users with ID 1 are often the network super admin. |
|---|---|

| Field | Value |
|---|---|
| **Detection** | Check if user IDs expose role information. Users with `ID=1` are typically the network super admin. Check the author archives for high-value user IDs. |
| **Curl Command** | `curl -s "https://target.com/wp-json/wp/v2/users/1" \| jq '.roles, .slug, .name'`, check if role info leaks. Compare across subsites: `curl -s "https://subsite1.target.com/wp-json/wp/v2/users/1" \| jq '.id, .name'` and `curl -s "https://subsite2.target.com/wp-json/wp/v2/users/1" \| jq '.id, .name'`, if the same user appears on all subsites, they may be a super admin. |
| **Severity** | 🟠 High |
| **Risk** | Identifying super admins gives attackers a high-value target for spear-phishing, credential stuffing, and social engineering. The user ID 1 is always a known attack target. |
| **Mitigation** | Change user ID 1 (create a new admin user, delete old ID 1). Restrict REST API user output via `rest_user_query` filter. Enable IP restrictions on super admin accounts. Use `define('WP_HTTP_BLOCK_EXTERNAL', true);` to limit outbound connections. |

---

### ⑨ Common Multisite Plugins Vulnerabilities

| Risk: | Multisite introduces attack surface through network-active plugins. A vulnerability in any network-active plugin instantly affects **all sites**. Common vulnerable plugin categories include: |
|---|---|

| Plugin Category | Example Plugins | Known Issues |
|---|---|---|
| **Domain Mapping** | WordPress MU Domain Mapping, WordPress.com Domain Mapping | SQL injection in domain validation, XSS in mapped domain fields |
| **Multisite Management** | Multisite Toolbar Addon, Multisite Enhancements, NS Cloner | Privilege escalation, stored XSS, SQL injection |
| **User Management** | Multisite User Management, Network Users Extended | Mass assignment, unauthorized role elevation |
| **Site Cloning** | WP Bulk Delete, NS Cloner, WP Reset (Multisite mode) | IDOR allowing cross-site data access |
| **Membership** | Multisite Members, Network Subsite Manager | Broken access controls |
| **Performance** | W3 Total Cache (multisite mode) | Cache poisoning sites across network |

| Field | Value |
|---|---|
| **Detection** | Identify plugin versions from readme files, stylesheet comments, or REST API (if authenticated). Cross-reference versions against WPScan vulnerability database. |
| **Curl Command** | Probe plugin readme files for version info: `curl -sL "https://target.com/wp-content/plugins/multisite-enhancements/readme.txt" \| grep -iE "(stable tag|version)"` or check CSS: `curl -sL "https://target.com/wp-content/plugins/ns-cloner/ns-cloner.css" \| head -20` (may contain version comments). For REST API (authenticated): `curl -s "https://target.com/wp-json/wp/v2/plugins" \| jq '.[].plugin'` |
| **Severity** | 🔴 Critical (for actively exploited plugins) |
| **Risk** | A single vulnerable network-active plugin compromises the entire network. **Unlike single-site, any subsite user can trigger a network plugin's vulnerability.** |
| **Mitigation** | Maintain plugin inventory network-wide. Use `must-use` (MU) plugins for critical network functionality. Disable plugins that are not needed network-wide, activate them per-site instead. Run WPScan network-wide. Subscribe to WPScan API for vulnerability feeds. |

---

### ⑩ Site Archiving / Suspended Sites Exposure

| Risk: | In Multisite, archived or suspended sites are often **still publicly accessible** via their URL, they just don't appear in network site lists. The content remains online. Additionally, "deleted" sites may leave behind databases and files. |
|---|---|

| Field | Value |
|---|---|
| **Detection** | Check if archived/suspended sites still respond with 200 (content visible) vs 410 (gone). Check if the REST API lists archived sites. Check `/wp-json/wp/v2/sites` for archived status fields. |
| **Curl Command** | `curl -sL "https://target.com/suspended-site/" \| head -20`, if content is still served, it's only "administratively" archived but publicly accessible. Check REST API: `curl -s "https://target.com/wp-json/wp/v2/sites" \| jq '.[] \| select(.archived==true)'`, reveals archived sites and their URLs. |
| **Severity** | 🟡 Medium (archived sites may have outdated plugins/content) |
| **Risk** | Archived sites rarely get security updates. An archived site with outdated plugins is an **easy entry point** into the shared database and potentially the entire network. Suspended sites may still serve malicious content. |
| **Mitigation** | Hard-archive: change document root or return 410 for archived sites. Delete sites entirely (not just mark as archived). Regularly audit all sites including archived. Disable REST API `sites` endpoint exposure. Use `wp site archive --hard` or custom redirect rules. |

---

### ⑪ Network-Wide Plugin & Theme Update Status

| Risk: | In multisite, plugins/themes are **stored once** but may have **per-site activation status**. An outdated plugin present but inactive on subsite A but active on subsite B creates a vulnerability on subsite B that can still affect the network database. |
|---|---|

| Field | Value |
|---|---|
| **Detection** | Check if common vulnerable plugins are present. If the plugin exists anywhere in `/wp-content/plugins/`, check activation timestamps or version strings across subsites. |
| **Curl Command** | Probe multiple subsites for the same plugin's readme: `for sub in site1 site2 site3; do curl -sL "https://$sub.target.com/wp-content/plugins/vulnerable-plugin/readme.txt" \| grep -i "stable tag"; done` |
| **Severity** | 🟠 High |
| **Risk** | Old plugin versions on any subsite can be exploited via direct file access or REST API, compromising the shared database. |
| **Mitigation** | Automate network-wide updates. Use `wp plugin update --all --network` regularly. Remove unused plugins entirely from the filesystem. Enable auto-updates for all plugins network-wide. |

---

## Summary: Multisite-Specific Attack Chains

```
1. Detect multisite → Enumerate all network users via REST API
   → Credential stuffing on super admin → Full network takeover
   
2. Find outdated plugin on archived subsite → Exploit via direct access
   → SQL injection on shared DB → Extract hashes, escalate to super admin
   
3. Signup enabled → Create spam site on target's subdomain
   → Host phishing pages → Reputation damage to main domain
   
4. Domain mapping misconfiguration → SSL/TLS downgrade on mapped domain
   → MITM between subsite and users → Session cookie theft
   
5. Super admin ID=1 → Targeted brute-force on /wp-admin/network/
   → Network admin access → Deploy malicious MU plugin → All sites compromised
```

---

## Quick Reference: All Curl Commands

```bash
# Detection
curl -sL -o /dev/null -w "%{http_code}" "https://target.com/wp-signup.php"
curl -sL -o /dev/null -w "%{http_code}" "https://target.com/wp-sites.php"
curl -sL "https://target.com/wp-json/wp/v2/sites"
curl -sI "https://target.com/wp-json/wp/v2/sites"

# User Enumeration
curl -sI "https://target.com/wp-json/wp/v2/users?per_page=1"
curl -s "https://target.com/wp-json/wp/v2/users?per_page=100" | jq '.[].slug'

# Signup & Registration
curl -sL "https://target.com/wp-signup.php" | grep -iE "(create a new site|register)"

# Network Admin
curl -sL -o /dev/null -w "%{http_code}" "https://target.com/wp-admin/network/"
curl -sL "https://target.com/wp-admin/network/" | grep -iE "(network admin|super admin)"

# Super Admin Enumeration
curl -s "https://target.com/wp-json/wp/v2/users/1" | jq '.roles, .slug, .name'

# Domain Mapping
curl -sI "https://subsite.target.com/"
curl -sI "https://target.com/subsite/"
curl -sL "https://target.com/wp-json/" | jq '.namespaces'

# Plugin Version Probing
curl -sL "https://target.com/wp-content/plugins/PLUGIN-NAME/readme.txt" | grep -iE "(stable tag|version)"

# Archived Sites
curl -sL "https://target.com/wp-json/wp/v2/sites" | jq '.[] | select(.archived==true)'
```

---

## References

- [WordPress Multisite Network Administration](https://wordpress.org/documentation/article/create-a-network/)
- [WPScan Vulnerability Database](https://wpscan.com/)
- [OWASP WordPress Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
- [WordPress REST API Handbook, Users Reference](https://developer.wordpress.org/rest-api/reference/users/)
- [Sucuri Blog, Hardening WordPress Multisite](https://blog.sucuri.net/)
