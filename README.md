# wp_security_ForSure

An external security audit for WordPress sites that cannot change the site it audits.
It sends ordinary read requests, the kind a browser or a WordPress client sends, and maps what
an outside attacker can learn: exposed versions and components, known vulnerabilities, leaked files,
risky configuration, injected scripts.

[Version française](README.fr.md) · Status: alpha (0.1.0) · License: Apache-2.0

## Who it is for, and what it is not

- **For site owners** and the people they mandate (agencies, freelancers, hosts): run it on your own
  WordPress site to see what an outside attacker can learn and which known flaws apply to it.
- **Not an attack tool.** It does not try to break in, does not exploit the vulnerabilities it
  reports, and is not meant for sites you have no right to audit.
- **Its main limit: active attacks are not tested.** Attackers brute-force logins, replay leaked
  passwords, exploit vulnerable plugins, upload files and inject code. Testing those means attacking,
  which this tool refuses to do, even as an option. It reports what makes them possible (an exposed
  login page and XML-RPC, enumerable accounts, vulnerable versions) and tells you what to check
  yourself: two-factor authentication on every administrator, a limit on login attempts, a web
  application firewall, updates, deleting unused plugins. Resistance to active attacks is measured
  by a penetration test under a signed contract.
- [docs/COVERAGE.md](docs/COVERAGE.md) maps WordPress and PHP vulnerability classes one by one:
  tested, partly tested, invisible from outside, or active only.

## Why another scanner

Most WordPress scanners mix discovery with attack: they post forms, try passwords, send injection
strings or guess thousands of paths. That is fine in a penetration test with a signed contract.
It is a problem everywhere else, and in France it can fall under article 323-1 of the Penal Code.

This tool takes the opposite position and enforces it in code, not in documentation:

| Guarantee | How it is enforced |
|---|---|
| Read-only | The HTTP client refuses every method except `GET`, `HEAD` and `OPTIONS` (`PassivityViolation`). No form is submitted, no login is attempted, no file is uploaded. |
| No attack payloads | `tests/test_passivity.py` runs the whole engine against a simulated site, records every request and fails on any other method or on payloads such as `<script`, `' OR '`, `../` or internal addresses. It runs in CI on every change. |
| Nothing executed on the target | Guessed `.php` files under `wp-content/` (uploads, must-use plugins, drop-ins) and presumed web shell names are never requested, because a `GET` would run them. `wp-cron.php` and Site Health diagnostics are never called. Exception, with `--authorized` only: a few guessed files at the root (`info.php`, `phpinfo.php`, `test.php`, `adminer.php`...) are requested to spot an exposed `phpinfo()` or database tool, and three core files (`wp-admin/install.php`, `wp-admin/setup-config.php`, `wp-config-sample.php`) to check that installation is closed. A request runs them. |
| Graduated access | By default the tool only requests the home page, what it references, and standard public WordPress endpoints (REST API index, feeds, `xmlrpc.php` with `GET`, `wp-login.php`, sitemaps). Guessing unlinked paths (backups, `.env`, `.git/`, plugin slugs) needs `--authorized`, which you should only use with the owner's written permission. Without it, those parts are reported as not performed. |
| The target cannot turn the scanner against you | Every outgoing request is resolved first and refused if it points to a private, loopback, link-local or reserved address. Redirects are followed by hand, at most 5 hops, only within the target's host and its `www.` variant. Each audit has a request budget. |
| Secrets stay out of reports | A password, key or salt found in an exposed file is masked at the source and again before any report is written. |
| Identifiable traffic | Requests carry a user agent that names the tool and links to this repository. Two documented exceptions, because injections hide from tools: visitor profiles present a browser or Googlebot, and the cloaking check presents Googlebot, on the home page and at most two pages it links. |
| The browser pass follows the same rules | `--render` is off by default. In Chromium, only `GET`, `HEAD` and `OPTIONS` leave; other methods, blockchain RPC nodes, navigation to another site, WebSockets, downloads and private addresses are blocked and recorded. The clipboard is intercepted, never written. Chromium's sandbox is required: without it the pass does not start. |
| Polite to the host | Requests to the audited site are spaced: 1 second apart, 2 seconds for guessed paths (`--delay` or `request_delay` to change it). A dropped connection is retried once, then the check says its result is partial. The audit stops at the first sign that the site blocks it (HTTP 429, a hosting provider's ban page, a Cloudflare challenge, or a home page that turns to 403 after a run of refusals), sends nothing more, and reports itself incomplete. Shared hosting bans fast audits: the first real run of this tool, at full speed, got its address banned in ten seconds. |
| Errors are not hidden | A check that fails is reported as "not performed", the verdict says the audit is incomplete, and the exit code is `3`. |

## Install

Python 3.10 or later.

```bash
pip install "git+https://github.com/J2K0000/wp_security_ForSure"
```

The optional browser pass needs Playwright and Chromium:

```bash
pip install "wp-security-forsure[render] @ git+https://github.com/J2K0000/wp_security_ForSure"
python -m playwright install chromium
```

A PyPI package (`wp-security-forsure`) will follow.

## Use

```bash
wp-security-forsure list
wp-security-forsure audit https://example.com
wp-security-forsure audit https://example.com --output report.html
wp-security-forsure audit https://example.com --checks fingerprint,vulnerability_scan --format json
wp-security-forsure audit https://example.com --authorized   # only with the owner's written permission
wp-security-forsure audit https://example.com --render       # also run pages in a sandboxed Chromium
wp-security-forsure audit https://example.com --delay 3      # slower, for a fragile shared host
wp-security-forsure refresh-kev    # download the CISA KEV catalogue (network, on request only)
wp-security-forsure refresh-epss   # download EPSS scores (network, on request only)
```

Reports come as terminal text, JSON or a standalone HTML page. Report text is written in French.
Every report ends with what the audit cannot see, account hardening advice (two-factor authentication
on every administrator) and an incident response procedure, moved to the top when a finding points to a
compromise. In JSON they sit under `audit_limits`, `recommendations` and `incident_response`.
Usernames found during the audit are masked (`ju***`) unless they are themselves the finding
(`admin`, `test`...); set `mask_usernames: false` in the configuration to see them.

| Exit code | Meaning |
|---|---|
| 0 | Complete audit, no confirmed critical finding |
| 1 | At least one confirmed critical finding (takes precedence over 3) |
| 2 | Usage error: bad argument, unknown check, unreadable configuration |
| 3 | Incomplete audit: target unreachable, blocked the audit, or at least one check failed |

Each finding carries a confidence level. `confirmed` means the evidence is deterministic;
`potential` means it has to be checked by hand. The tool never upgrades a guess to a certainty.

## What it checks

`wp-security-forsure list` prints the current catalogue with descriptions. Checks are grouped by
what an attacker gains:

- Client-side injections: the home page and up to two pages it links, fetched under eight visitor
  profiles (click from Google, mobile, another language, two direct visits, an invalid WordPress login
  cookie, a returning visitor, Googlebot). Scripts, iframes and redirects that only some profiles get
  are reported; a difference only counts if the page does not already vary between two direct visits.
  Scripts served to visitors (inline, `data:` URLs decoded, the site's `.js` files, a few unknown
  third-party scripts) are matched against published ClickFix and EtherHiding signatures, listed with
  their sources in `wp_security_forsure/signatures/injection_signatures.yaml`. With `--render`, the pages run
  in Chromium: clipboard writes, blockchain calls, JavaScript redirects and fake CAPTCHA overlays are
  recorded. Under a full-screen fake CAPTCHA or keyboard instructions, one element whose label mentions a
  verification is clicked once to reveal the command the page copies.
- Takeover and intrusion: component and version fingerprint, known CVEs (raised to critical when listed
  in the CISA Known Exploited Vulnerabilities catalogue), a core version that wordpress.org marks insecure
  or that lags behind its branch, plugins closed on wordpress.org or not updated for 2 years (the tool's
  threshold), maintenance tools left in production (database reset, file managers, SQL consoles),
  risky account names (`admin`, `test`, the site's own name), REST API batch exposure
  (wp2shell), plugin REST routes that accept a user URL, nulled plugins, notable plugin attack surface,
  login exposure and user enumeration, WordPress features (XML-RPC, oEmbed, application passwords),
  exposed files and database dumps (with `--authorized`, a readable `.user.ini` whose
  `auto_prepend_file` points to an unknown file, and an open `wp-admin/setup-config.php`), signs of injected code, cloaking and SEO spam, open
  comments on an article.
- Data exposure: REST API content and users, cookies and sessions, third-party scripts,
  TLS configuration, email authentication (SPF, DKIM, DMARC), webhook receivers.
- Hardening: an end-of-life PHP branch (from `X-Powered-By`, against php.net's support cycle), PHP errors
  displayed in pages, security headers, server configuration, WAF and CDN detection (a CAPTCHA alone is not
  read as a WAF: a fake one would pass for a protection), subdomain takeover,
  cache plugins, multisite.

## What it does not see

A black-box, read-only audit has limits. The report states them instead of reporting "clean".

- **Active attacks** (brute force, leaked password reuse, exploitation, uploads, injection): see
  "Who it is for, and what it is not" above.
- **A site that is already compromised.** A backdoor in a theme's `functions.php`, a must-use plugin,
  a drop-in, the database or a scheduled task is invisible from outside. Answering "am I already
  hacked?" needs server access: `wp core verify-checksums`, `wp plugin verify-checksums`, a review of
  `wp-content/mu-plugins/`, drop-ins, administrators and options.
- **Part of the injections served to some visitors only.** Visitor profiles cover the referer, the
  device, the language, the login cookie and a second visit. They cannot trigger cloaking that checks
  Googlebot's IP address, nor targeting by country or by visitor IP: every visit leaves from your
  address. Without `--render`, conditions evaluated in JavaScript (localStorage, automation
  detection) are not seen.
- **Hidden versions.** When a site masks every version signal, CVE matching cannot rely on it.
  No version found is not proof of no vulnerability.
- **Anything behind authentication**, and Google Search Console's security and manual action reports,
  which have no API. Check them in your Search Console property.
- **Backups.** Whether a copy exists off the server and has been restored once cannot be seen from
  outside. Exposed backup files can.

## Network traffic

Besides the target, an audit contacts:

| Host | Why | When |
|---|---|---|
| `www.wpvulnerability.net` | Known vulnerabilities for each detected component | For each component not in the local cache or cached more than 7 days ago |
| `api.wordpress.org` | Core release status (`stable-check`, `version-check`) | Every audit, cached 24 hours |
| `api.wordpress.org` | Plugin information: closed, abandoned, nulled copies | For each detected plugin, cached 7 days |
| Hosts referenced by the home page | Dangling third-party services (takeover check) | Every audit (DNS and `GET`, same guards) |
| Third-party script hosts | Content of up to 10 unknown scripts referenced by the audited pages (well-known services and blockchain libraries excluded) | Every audit |
| Hosts the pages load (scripts, fonts, iframes) | What a visitor's browser loads, in Chromium, `GET` only | Only with `--render` (`render_third_party: false` blocks them) |
| Your DNS resolver | SPF, DKIM and DMARC records | Every audit |
| `crt.sh` | Subdomain enumeration | Only with `takeover_enum: true` in the configuration |
| EPSS data file | Exploit prediction scores | Only when you run `wp-security-forsure refresh-epss` |
| `www.cisa.gov` | Known Exploited Vulnerabilities catalogue | Only when you run `wp-security-forsure refresh-kev` |

The CVE cache, the EPSS and KEV snapshots and the wordpress.org cache live in your user cache folder
(`%LOCALAPPDATA%\wp_security_forsure` on Windows, `~/.cache/wp_security_forsure` elsewhere),
or in `WP_SECURITY_FORSURE_CACHE_DIR` if set. Reports state where their vulnerability data came
from and how old it is.

## Responsible use

Run it on sites you own or are mandated to audit. Read [docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md)
before using `--authorized` or `--render`. Usernames and email addresses found during an audit are personal data:
keep reports private and delete them when the engagement ends.

## Data sources

- Vulnerability data: [WPVulnerability](https://www.wpvulnerability.net/), queried at run time.
- Exploit prediction: [EPSS by FIRST](https://www.first.org/epss/), downloaded on request.
- Active exploitation: [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), downloaded on request.
- Core and plugin status: the public [WordPress.org API](https://api.wordpress.org/).
- Injection signatures: indicators published by Microsoft Threat Intelligence, Google Threat
  Intelligence, Trend Micro and Rapid7, with their sources cited in
  `wp_security_forsure/signatures/injection_signatures.yaml`.

## Roadmap

- A read-only authenticated mode for integrity checks (checksums, drop-ins, mu-plugins, administrators).
- SARIF output and a `diff` between two reports.
- An offline WPVulnerability snapshot, and watched plugin lists fed by CVE data.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities in the tool privately, as described in
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
WordPress is a trademark of the WordPress Foundation. This project is not affiliated with or endorsed by it.
