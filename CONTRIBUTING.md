# Contributing

Thanks for helping. Bug reports, false-positive reports, new passive detections and documentation
fixes are all welcome.

## Ground rules

1. **Read-only, always.** A check may only use the helpers of `BaseCheck`
   (`http_get`, `http_get_url`, `http_head`, `http_options`, `get_json`, `rest_index`). They refuse any
   method other than `GET`, `HEAD` and `OPTIONS`, block private addresses and enforce the request
   budget. `tests/test_checks_network_static.py` fails if a check calls `requests` or the session
   directly, and `tests/test_passivity.py` fails on any other method or attack payload.
2. **No active probes.** Pull requests that submit forms, attempt authentication, upload files, send
   injection strings, poison caches or exploit a vulnerability are declined, even behind an option.
   See [docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md).
3. **Never execute anything on the target.** Do not request guessed `.php` files under `wp-content/`,
   presumed web shells, `wp-cron.php` or Site Health diagnostics. `access_tiers.forbidden_reason`
   refuses most of them at every level.
4. **Respect access levels.** Requests outside the home page, its resources and the standard public
   WordPress endpoints are level 2 and must only run with `--authorized`.
5. **Keep audited sites private.** Never put a real site's address, usernames or secrets in an issue,
   a test or a fixture. Use `example.test` and invented values.
6. **Honest confidence.** Mark a finding `confirmed` only when the evidence is deterministic. Anything
   that needs a human to confirm is `potential`.

## Development setup

```bash
git clone https://github.com/J2K0000/wp_security_ForSure
cd wp_security_ForSure
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux and macOS: source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

Tests run offline: HTTP responses are simulated with `responses` and DNS resolution is stubbed in
`tests/conftest.py`.

## Adding a check

1. Create `wp_security_forsure/scanner/checks/<name>.py` with a subclass of `BaseCheck` that sets
   `name`, `title`, `description`, `access_tier` (0, 1 or 2, see
   `wp_security_forsure/scanner/access_tiers.py`) and, if it needs another check's output, `depends_on`.
   A mixed check keeps its level 2 part behind `self.config.get("authorized")` and calls
   `self.note_unlinked_skipped(...)` otherwise.
2. Implement `run()` and return `self.result()`. Record findings with `self._result.add_finding(...)`,
   with a severity, a confidence level and evidence. Mask secrets with
   `wp_security_forsure.scanner.redact`.
3. Add the name to the `checks` list in `wp_security_forsure/config.yaml`: the engine runs that list in
   order. A check that is not listed there only runs when named with `--checks`.
4. Write tests first: one that fails without your check, one for a clean site, and one for each false
   positive you can think of. The passivity test covers your check automatically.

## Pull requests

- One topic per pull request, with tests.
- Describe what an attacker learns from the finding, and why the detection cannot misfire on a
  healthy site.
- User-facing text in reports is in French; code, comments and documentation may be in English or
  French.

## Reporting a vulnerability in the tool

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).
