# Changelog

All notable changes to wp_security_ForSure. Dates are UTC.

## 0.1.0, 2026-11-27

First public release of a passive, read-only external security audit for WordPress sites. It is
meant for site owners and the people they mandate. It is not an attack tool: it only reads, and the
rules it follows are in [docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md).

### What it does

- 32 checks, listed by `wp-security-forsure list`. They cover the inventory of components and their
  known vulnerabilities (wpvulnerability, CISA KEV, EPSS), exposed files, the REST API, login
  protection, transport security, email authentication, injections and SEO spam. An optional
  sandboxed Chromium pass (`--render`) runs the pages' JavaScript.
- Graduated access: by default, the home page and standard public endpoints only. Guessed unlinked
  paths need `--authorized`, for audits under the owner's written permission.
- Every report states its limits and ends with checks for the owner and an incident procedure.
- A coverage map of 50 WordPress and PHP vulnerability classes says what the tool tests and what it
  cannot see ([docs/COVERAGE.md](docs/COVERAGE.md)).

### Lessons from the first real audit (shared hosting)

At full speed, the `--authorized` pass got the auditor's address banned by the hosting provider about
a minute and a half after guessed paths started (258 requests). The tool then sent 346 more requests,
345 of them refused or cut, while reporting a complete audit. Fixed
before this release:

- requests to the audited site are spaced (1 s, 2 s for guessed paths, `--delay`);
- the audit stops at the first sign of blocking (HTTP 429, a hosting ban page, a Cloudflare
  challenge, or a home page that turns to 403 after a run of refusals) and reports itself incomplete
  (exit code 3);
- a dropped connection is retried once, then the check says its result is partial;
- `readme.html` no longer unlocks `wp-admin/install.php` without `--authorized`;
- false positives removed: open registration on a closed site, WordPress's native REST CORS reported
  as critical, the core test cookie taken for a session cookie, core REST namespaces counted as
  plugins, a namespace mapped to the wrong plugin slug, TLS 1.0, 1.1 and 1.3 misread from a refused
  handshake, ordinary hidden markup and review widgets reported as SEO spam.
