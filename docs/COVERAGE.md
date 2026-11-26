# Coverage map: WordPress and PHP vulnerabilities

[Version française](COUVERTURE.md)

This page goes through the classes of vulnerabilities and misconfigurations of a WordPress site and its PHP
stack, and says for each one what wp_security_ForSure sees. The tool is meant for owners auditing their own
site, read-only. It replays no attack: see "Who it is for, and what it is not" in the [README](../README.md).

Snapshot of 24 November 2026, built from the sources listed at the bottom. 50 classes in total:

- **tested** (11): the tool reports a finding when the flaw shows from outside, with no option;
- **partly tested** (15): only part of it shows, the check needs `--authorized`, the tool only sees clues,
  or it abstains by design (C11);
- **invisible from outside** (10): they need server or admin access. A read-only server mode is planned;
- **active only** (14): testing them means attacking. The tool does not; it reports what makes them
  possible and what to check.

`--authorized` marks a check that guesses unlinked paths: only use it on a site you have written permission
to audit.

"Tested" means the tool looks for that signal: an audit without findings does not prove the flaw is
absent. The map only holds the classes that the sources below name.

## Tested

| # | Class | What the tool does | What you check | Sources |
|---|---|---|---|---|
| C01 | Outdated WordPress core | Version found (generator tag, feeds, core files), status published by wordpress.org, known CVEs and active exploitation (CISA KEV): `fingerprint`, `core_branch`, `vulnerability_scan` | Automatic updates on | WP-H, OWASP A03, PS-2026 |
| C02 | Plugins and themes with a known vulnerable version | Visible slugs and versions matched against published CVEs: `fingerprint`, `vulnerability_scan`; `readme.txt` of unlinked plugins with `--authorized` | Update, delete what is unused | PS-2026, PS-2025, WF-2024, OWASP A03 |
| C03 | Abandoned or closed plugins | wordpress.org directory status (closed, no update for 2 years), maintenance tools left in production: `plugin_status` | Replace the plugin | PS-2026, PS-2025, WF-2024, OWASP A03 |
| C04 | End-of-life PHP branch | `X-Powered-By` version compared with php.net's support cycle: `php_runtime` | Move to a supported branch | PHP-SV, PHP-EOL, OWASP A03 |
| C07 | Displayed PHP errors, path disclosure | PHP and database errors printed in the pages read: `php_runtime`, `database_exposure` | `display_errors` off, `WP_DEBUG_DISPLAY` false | WP-ERR, OWASP A02, A10 |
| C12 | Sample files left online | `readme.html`, `license.txt`: `file_exposure` | Remove what is unused | OWASP A02, WF-2024 |
| C13 | Missing security headers | CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`...: `security_headers` | Send them from the server or CDN | OWASP A02, A06 |
| C15 | Cookies without Secure, HttpOnly or SameSite | Attributes of cookies set by public pages: `cookies_sessions` | HTTPS and `FORCE_SSL_ADMIN` | OWASP A02, A01, WP-CONN |
| C16 | Missing or incomplete HTTPS | Certificate, protocols and cipher suites (when `openssl` is installed, otherwise a partial audit is reported), HSTS: `ssl_tls`; HTTP to HTTPS redirect of the login page: `brute_force_login` | Valid certificate, redirect, HSTS | OWASP A04, WP-HTTPS |
| C17 | Technical information disclosure | `Server` and `X-Powered-By` headers, published versions: `server_security`, `fingerprint` | Hide them, as a complement only | OWASP A01, WF-2024, CWE |
| C19 | Account enumeration, "admin" username | Author archives, REST users API, oEmbed, author sitemap; risky names (`admin`, `test`, the site's name): `rest_api`, `brute_force_login` | No `admin` username, no test account | OWASP A07, WP-H, WP-BF |

## Partly tested

| # | Class | What the tool sees, and what escapes it | What you check | Sources |
|---|---|---|---|---|
| C08 | Sensitive files served | With `--authorized` only: `wp-config.php` copies, `debug.log`, `.env`, `.git/`, SQL dumps, `.user.ini`, exposed `phpinfo()`, phpMyAdmin and Adminer: `file_exposure`, `database_exposure`. To spot a `phpinfo()` or a database tool, a few guessed PHP files at the root are requested (`info.php`, `phpinfo.php`, `test.php`, `adminer.php`...): a HEAD or GET runs them | Remove them from the web root | OWASP A01, A09, WF-2024, WP-H |
| C10 | Installation or setup left open | With `--authorized` only: `wp-admin/install.php` and every screen of `wp-admin/setup-config.php` (language choice, step 0 welcome, database form at step 1): `database_exposure` | No installation leftovers | WF-2024 |
| C20 | Application passwords open without need | The application passwords endpoint is queried without authentication and must refuse: `rest_api`, `wp_features`. Whether the feature is needed cannot be seen | Turn them off if unused | WP-AP |
| C50 | Already compromised site (spam, redirects, injected scripts) | What the site serves: injected code, SEO spam, cloaking, ClickFix fake CAPTCHA, EtherHiding loaders, compared visitor profiles, Chromium pass with `--render`, unknown `auto_prepend_file` in `.user.ini` (`--authorized`): `malware_detection`, `cloaking_seo_spam`, `visit_profiles`, `client_injection`, `browser_render`, `file_exposure`. An infection that does not show, or that sorts its visitors, escapes the audit | Server-side integrity check, backups | PS-2025, PS-2026, WP-H, WF-2024 |
| C05 | Outdated server software | A version in the `Server` header is reported as disclosed, but its age is not judged: `server_security` | A host that maintains its versions | WP-H, OWASP A03 |
| C06 | Components from untrusted sources | Third-party scripts without `integrity`, scripts from suspicious domains, nulled plugins (`--authorized`): `third_party_scripts`, `nulled_plugins`. A backdoor inside a plugin stays invisible | Components from wordpress.org or known vendors | OWASP A03, A08, WP-H, PS-2026 |
| C09 | Directory listing | Index pages of `wp-content/`, `uploads/` and similar, only with `--authorized`: `file_exposure`, `server_security` | Listing turned off on the server | OWASP A01, A02 |
| C14 | Permissive CORS policy | `Access-Control-Allow-*` headers of the REST API: `rest_api` | Restrict allowed origins | OWASP A01, A02 |
| C18 | XML-RPC on without need | Response of `xmlrpc.php` to a GET. Checking `system.multicall` would need a POST, out of scope: `wp_features`, `brute_force_login` | Turn it off if unused | WP-BF |
| C23 | Admin area without an extra layer | Exposure of `wp-login.php` and of the `/wp-admin` redirect: `brute_force_login`. Server authentication (401) is not qualified separately | Targeted protection on `wp-login.php` and `xmlrpc.php` | WP-H, WP-BF |
| C35 | Data exposed by a plugin | Data served by public REST routes over GET: `rest_api` | Update | PS-2025, WF-2024, CWE |
| C40 | Memory bugs in the PHP interpreter | Only through the PHP branch (C04) | Supported branch | CWE, PHP-SV |
| C46 | No web application firewall | A WAF or CDN detected from its headers and cookies; its effectiveness can only be measured by attacking: `waf_cdn` | Edge or WordPress firewall | WP-H, WP-BF, PS-2026, WF-2024 |
| C11 | Include files callable directly | Not tested, by design: requesting a PHP file runs it on the server | Server rules that block them | WP-H |
| C21 | Login without rate limiting | Clues only: visible protection plugins, CAPTCHA or 2FA, exposed XML-RPC: `brute_force_login`. Actual limiting can only be checked by chaining attempts | Login attempt limits, two-factor authentication, firewall | WP-BF, OWASP A07, WF-2024 |

## Invisible from outside

They need server access or an administrator account. Reports list them in their permanent recommendations;
a read-only server mode is planned for several of them.

| # | Class | What you check | Sources |
|---|---|---|---|
| C22 | Weak passwords, no two-factor authentication | Strong unique passwords, 2FA on every administrator | WP-H, WP-BF, WP-2FA, OWASP A07 |
| C24 | Broken session management | Up-to-date core and authentication plugins | OWASP A07 |
| C41 | Dashboard file editor on | `DISALLOW_FILE_EDIT` in `wp-config.php` | WP-H |
| C42 | File permissions too broad | 755 for directories, 644 for files, 400 or 440 for `wp-config.php` | WP-H |
| C43 | Database: excessive rights, default prefix | One database and user per site, a prefix other than `wp_` | WP-H |
| C44 | Missing or never-restored backups | Copies off the server, restore tested | WP-H, WP-SAUV, WP-BF |
| C45 | Insufficient logging and monitoring | Logs, file change tracking, external monitoring | OWASP A09, WP-H, WP-SURV |
| C47 | Administrator's computer, plain FTP | Up-to-date computer, SFTP instead of FTP | WP-H, OWASP A04 |
| C48 | Poorly isolated shared hosting | Ask the host how sites are isolated | WP-H |
| C49 | Insecure design | Maintained components, code review | OWASP A06, A10 |

## Active only

Testing them means attacking: the tool does not, not even as an option. For each one it reports the passive
clue that makes it likely, almost always a known vulnerable version (`vulnerability_scan`, with the CISA KEV
catalogue of actively exploited flaws). Actual resistance is measured by a penetration test under a signed
contract.

| # | Class | Clue reported by the tool | What you do | Sources |
|---|---|---|---|---|
| C25 | Cross-site scripting (XSS) | Known vulnerable version | Update, limit privileged accounts, firewall | PS-2025, PS-MI25, PS-2026, WF-2024, CWE, OWASP A05 |
| C26 | Broken access control, missing authorization | Known vulnerable version | Update quickly, virtual patching | PS-2026, PS-2025, WF-2024, CWE, OWASP A01 |
| C27 | Cross-site request forgery (CSRF) | Known vulnerable version | Update, firewall | PS-2025, PS-MI25, WF-2024, CWE, OWASP A01 |
| C28 | SQL injection | Known vulnerable version; displayed SQL errors (C07) | Update, database user with limited rights | PS-2025, PS-2026, WF-2024, CWE, OWASP A05 |
| C29 | Arbitrary file upload | Known vulnerable version; exposed upload forms (`forms_upload`) | Update, no PHP in `uploads/` | PS-2025, PS-2026, WF-2024, CWE, OWASP A06 |
| C30 | File inclusion, path traversal | Known vulnerable version | Update, firewall | PS-2025, PS-MI25, PS-2026, WF-2024, CWE, OWASP A05 |
| C31 | PHP object injection | Known vulnerable version | Update, firewall | PS-2025, PS-2026, WF-2024, CWE, OWASP A08 |
| C32 | Server-side request forgery (SSRF) | REST routes known to accept a URL (`ssrf_endpoints`); vulnerable version | Update | PS-2025, CWE, OWASP A01 |
| C33 | Privilege escalation, broken authentication | Known vulnerable version; conditional bypasses spotted without exploiting them (`auth_bypass_state`) | Update quickly | PS-2025, PS-2026, WF-2024, CWE, OWASP A07 |
| C34 | Code execution, command injection | Known vulnerable version; REST API batch exposure (`rest_batch`) | Update, `DISALLOW_FILE_EDIT` | PS-2025, PS-2026, CWE, OWASP A05 |
| C36 | Open redirect | Known vulnerable version | Update | PS-2025, OWASP A01 |
| C37 | Arbitrary file deletion or download | Known vulnerable version; reopened setup wizard (C10) | Update, tested backups | PS-2025, WF-2024 |
| C38 | Denial of service | None: a load test is an attack | Edge rate limiting and firewall | PS-2025, CWE, OWASP A10 |
| C39 | XML external entity (XXE) | Known vulnerable version | Update | PS-2025, OWASP A02 |

## Sources

| Code | Document | Date |
|---|---|---|
| OWASP | [OWASP Top 10:2025](https://top10.owasp.org/2025/) | 2025 edition, publication date not shown |
| WP-H | [Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/) | modified 14 October 2026 |
| WP-ERR | [Display Errors](https://developer.wordpress.org/advanced-administration/security/hardening/display-errors/) | modified 14 October 2026 |
| WP-BF | [Brute Force Attacks](https://developer.wordpress.org/advanced-administration/security/brute-force/) | modified 14 October 2026 |
| WP-HTTPS | [HTTPS](https://developer.wordpress.org/advanced-administration/security/https/) | modified 14 October 2026 |
| WP-SAUV | [Backups](https://developer.wordpress.org/advanced-administration/security/backup/) | modified 28 October 2026 |
| WP-2FA | [Two Step Authentication](https://developer.wordpress.org/advanced-administration/security/mfa/) | modified 14 October 2026 |
| WP-SURV | [Monitoring](https://developer.wordpress.org/advanced-administration/security/monitoring/) | modified 14 October 2026 |
| WP-CONN | [Logging In](https://developer.wordpress.org/advanced-administration/security/logging-in/) | modified 14 October 2026 |
| WP-AP | [Application Passwords](https://developer.wordpress.org/advanced-administration/security/application-passwords/) | modified 14 October 2026 |
| PHP-SV | [PHP Supported Versions](https://www.php.net/supported-versions.php) | read 24 November 2026 |
| PHP-EOL | [PHP Unsupported Branches](https://www.php.net/eol.php) | read 24 November 2026 |
| PS-2026 | [Patchstack, State of WordPress Security in 2026](https://patchstack.com/whitepaper/state-of-wordpress-security-in-2026/) | 25 February 2026 |
| PS-2025 | [Patchstack, State of WordPress Security in 2025](https://patchstack.com/whitepaper/state-of-wordpress-security-in-2025/) | 14 March 2025 |
| PS-MI25 | [Patchstack, 2025 mid-year vulnerability report](https://patchstack.com/whitepaper/2025-mid-year-vulnerability-report/) | 22 July 2025 |
| WF-2024 | [Wordfence, 2024 Annual WordPress Security Report](https://www.wordfence.com/wp-content/uploads/2025/04/2024-Annual-WordPress-Security-Report-by-Wordfence.pdf) | 8 April 2025 |
| CWE | [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) | 15 December 2025 |

Think a class is missing or misplaced? Open an issue with its source: see [CONTRIBUTING.md](../CONTRIBUTING.md).
