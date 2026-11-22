# Security policy

## Reporting a vulnerability in wp_security_ForSure

Please report privately through GitHub:
**[Report a vulnerability](https://github.com/J2K0000/wp_security_ForSure/security/advisories/new)**.
Do not open a public issue.

Examples of what we want to hear about:

- a target site that can make the scanner send a request that is not `GET`, `HEAD` or `OPTIONS`,
  or carry an attack payload;
- a target site that can make the scanner reach a private, loopback or link-local address
  (for example a cloud metadata endpoint) on the auditor's network;
- content from a target that executes or injects markup in the HTML or terminal report;
- a secret found on a target that appears unmasked in a report;
- anything in the release or CI pipeline that could let someone ship modified code.

## What to expect

- Acknowledgement within 14 days.
- A fix or a documented decision within 60 days for issues rated medium or higher.
- Credit in the release notes if you want it.

## Supported versions

Only the latest released minor version receives fixes while the project is in 0.x.

## Out of scope

Vulnerabilities in WordPress, plugins or themes that you found **with** this tool belong to their
vendors, not here. Report them to the vendor or to a WordPress CNA (Wordfence, Patchstack or WPScan),
and to the site owner if you audit a site under contract.
