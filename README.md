# wp_security_ForSure

An external security audit for WordPress sites that cannot change the site it audits.
It sends ordinary read requests, the kind a browser or a WordPress client sends, and maps what
an outside attacker can learn: exposed versions and components, known vulnerabilities, leaked files,
risky configuration, injected scripts.

[Version française](README.fr.md) · Status: alpha (0.1.0) · License: Apache-2.0

## Why another scanner

Most WordPress scanners mix discovery with attack: they post forms, try passwords, send injection
strings or guess thousands of paths. That is fine in a penetration test with a signed contract.
It is a problem everywhere else, and in France it can fall under article 323-1 of the Penal Code.

This tool takes the opposite position and enforces it in code, not in documentation:

| Guarantee | How it is enforced |
|---|---|
| Read-only | The HTTP client refuses every method except `GET`, `HEAD` and `OPTIONS` (`PassivityViolation`). No form is submitted, no login is attempted, no file is uploaded. |
| No attack payloads | `tests/test_passivity.py` runs the whole engine against a simulated site, records every request and fails on any other method or on payloads such as `<script`, `' OR '`, `../` or internal addresses. It runs in CI on every change. |
| Nothing executed on the target | Guessed `.php` files under `wp-content/` (uploads, must-use plugins, drop-ins) and presumed web shell names are never requested, because a `GET` would run them. `wp-cron.php` and Site Health diagnostics are never called. |
| Graduated access | By default the tool only requests the home page, what it references, and standard public WordPress endpoints (REST API index, feeds, `xmlrpc.php` with `GET`, `wp-login.php`, sitemaps). Guessing unlinked paths (backups, `.env`, `.git/`, plugin slugs) needs `--authorized`, which you should only use with the owner's written permission. Without it, those parts are reported as not performed. |
| The target cannot turn the scanner against you | Every outgoing request is resolved first and refused if it points to a private, loopback, link-local or reserved address. Redirects are followed by hand, at most 5 hops, only within the target's host and its `www.` variant. Each audit has a request budget. |
| Secrets stay out of reports | A password, key or salt found in an exposed file is masked at the source and again before any report is written. |
| Errors are not hidden | A check that fails is reported as "not performed", the verdict says the audit is incomplete, and the exit code is `3`. |

## Install

Python 3.10 or later.

```bash
pip install "git+https://github.com/J2K0000/wp_security_ForSure"
```

A PyPI package (`wp-security-forsure`) will follow.

## Use

```bash
wp-security-forsure list
wp-security-forsure audit https://example.com
wp-security-forsure audit https://example.com --output report.html
wp-security-forsure audit https://example.com --checks fingerprint,vulnerability_scan --format json
wp-security-forsure audit https://example.com --authorized   # only with the owner's written permission
```

Reports come as terminal text, JSON or a standalone HTML page. Report text is written in French.

| Exit code | Meaning |
|---|---|
| 0 | Complete audit, no confirmed critical finding |
| 1 | At least one confirmed critical finding (takes precedence over 3) |
| 2 | Usage error: bad argument, unknown check, unreadable configuration |
| 3 | Incomplete audit: target unreachable, or at least one check failed |

Each finding carries a confidence level. `confirmed` means the evidence is deterministic;
`potential` means it has to be checked by hand. The tool never upgrades a guess to a certainty.

## What it checks

`wp-security-forsure list` prints the current catalogue with descriptions. Checks are grouped by
what an attacker gains:

- Takeover and intrusion: component and version fingerprint, known CVEs, REST API batch exposure
  (wp2shell), plugin REST routes that accept a user URL, nulled plugins, notable plugin attack surface,
  login exposure and user enumeration, WordPress features (XML-RPC, oEmbed, application passwords),
  exposed files and database dumps, signs of injected code, cloaking and SEO spam.
- Data exposure: REST API content and users, cookies and sessions, third-party scripts,
  TLS configuration, email authentication (SPF, DKIM, DMARC), webhook receivers.
- Hardening: security headers, server configuration, WAF and CDN detection, subdomain takeover,
  cache plugins, multisite.

## What it does not see

A black-box, read-only audit has limits. The report states them instead of reporting "clean".

- **A site that is already compromised.** A backdoor in a theme's `functions.php`, a must-use plugin,
  a drop-in, the database or a scheduled task is invisible from outside. Answering "am I already
  hacked?" needs server access: `wp core verify-checksums`, `wp plugin verify-checksums`, a review of
  `wp-content/mu-plugins/`, drop-ins, administrators and options.
- **Injections served to some visitors only.** Current malware campaigns hide from command-line
  clients, logged-in users and visitors without a search-engine referer. This version reads static
  HTML with an identifiable user agent and does not run JavaScript, so it can miss them.
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
| `api.wordpress.org` | Plugin information (to spot nulled copies) | When a plugin is detected |
| Hosts referenced by the home page | Dangling third-party services (takeover check) | Every audit (DNS and `GET`, same guards) |
| Your DNS resolver | SPF, DKIM and DMARC records | Every audit |
| `crt.sh` | Subdomain enumeration | Only with `takeover_enum: true` in the configuration |
| EPSS data file | Exploit prediction scores | Only when you run `wp-security-forsure refresh-epss` |

The CVE cache and the EPSS snapshot live in your user cache folder
(`%LOCALAPPDATA%\wp_security_forsure` on Windows, `~/.cache/wp_security_forsure` elsewhere),
or in `WP_SECURITY_FORSURE_CACHE_DIR` if set. Reports state where their vulnerability data came
from and how old it is.

## Responsible use

Run it on sites you own or are mandated to audit. Read [docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md)
before using `--authorized`. Usernames and email addresses found during an audit are personal data:
keep reports private and delete them when the engagement ends.

## Data sources

- Vulnerability data: [WPVulnerability](https://www.wpvulnerability.net/), queried at run time.
- Exploit prediction: [EPSS by FIRST](https://www.first.org/epss/), downloaded on request.

## Roadmap

- CISA Known Exploited Vulnerabilities and "behind its branch" checks for the core version.
- Several visitor profiles (search-engine referer, mobile, returning visitor) whose scripts, iframes
  and redirects are compared.
- An optional sandboxed browser pass for client-side injections.
- A read-only authenticated mode for integrity checks (checksums, drop-ins, mu-plugins, administrators).
- SARIF output and a `diff` between two reports.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities in the tool privately, as described in
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
WordPress is a trademark of the WordPress Foundation. This project is not affiliated with or endorsed by it.
