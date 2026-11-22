"""Check HTTP security headers on the target homepage.

Inherits from BaseCheck. Covers:
  1) Strict-Transport-Security (HSTS), presence, max-age (min 31536000),
     includeSubDomains, preload
  2) Content-Security-Policy (CSP), presence, parse directives for
     unsafe-inline, unsafe-eval, wildcard sources, https: in default-src
  3) X-Frame-Options         , DENY or SAMEORIGIN (missing = clickjacking)
  4) X-Content-Type-Options  , nosniff (missing = MIME sniffing)
  5) Referrer-Policy         , presence (missing = info leakage)
  6) Permissions-Policy      , presence (missing = unrestricted browser APIs)
  7) X-XSS-Protection        , presence (deprecated but still seen)

Severity map:
  CRITICAL , CSP with unsafe-inline or wildcard sources
  HIGH     , missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
  MEDIUM   , missing Referrer-Policy, Permissions-Policy
  INFO     , X-XSS-Protection present (deprecated)
"""

import re
from typing import List

from .base import BaseCheck, CheckResult


class SecurityHeadersCheck(BaseCheck):
    """Check HTTP security headers on the target homepage."""

    name = "security_headers"
    title = "Security Headers Audit"
    description = (
        "Checks HTTP security headers: HSTS, CSP, X-Frame-Options, "
        "X-Content-Type-Options, Referrer-Policy, Permissions-Policy, "
        "and X-XSS-Protection."
    )
    severity = "HIGH"
    access_tier = 0  # en-têtes de l'accueil
    depends_on: List[str] = []

    # ── CSP directive names that map to script-like execution ──────────
    _EXECUTABLE_DIRECTIVES = {
        "script-src",
        "script-src-elem",
        "script-src-attr",
        "default-src",
    }

    # ── Public API ─────────────────────────────────────────────────────

    def __init__(self, target: str, config: dict, session):
        super().__init__(target, config, session)

    def run(self) -> CheckResult:
        """Execute all security header checks."""
        resp = self._fetch_headers()
        if resp is None:
            return self._result

        headers = resp.headers
        url = resp.url or self.target

        self._check_hsts(headers, url)
        self._check_csp(headers, url)
        self._check_x_frame_options(headers, url)
        self._check_x_content_type_options(headers, url)
        self._check_referrer_policy(headers, url)
        self._check_permissions_policy(headers, url)
        self._check_xss_protection(headers, url)

        return self._result

    # ── Helpers ────────────────────────────────────────────────────────

    def _fetch_headers(self):
        """Fetch response headers via HEAD request to the homepage.

        Falls back to GET if the server rejects HEAD.
        """
        try:
            resp = self.http_head("/")
            if resp.status_code >= 400:
                # Server may reject HEAD, fall back to GET
                resp = self.http_get("/")
        except Exception:
            try:
                resp = self.http_get("/")
            except Exception as exc:
                self._result.add_finding(
                    message="Could not fetch homepage headers, connection failed",
                    severity="HIGH",
                    evidence=f"Error: {exc}",
                    url=self.target,
                )
                return None

        return resp

    # ── 1) Strict-Transport-Security (HSTS) ────────────────────────────

    def _check_hsts(self, headers, url: str) -> None:
        """Check HSTS: presence, max-age, includeSubDomains, preload."""
        hsts = headers.get("Strict-Transport-Security", "")

        if not hsts:
            self._result.add_finding(
                message="HSTS (Strict-Transport-Security) header is MISSING",
                severity="HIGH",
                evidence=(
                    "No Strict-Transport-Security header found.\n"
                    "Risk: Users may be vulnerable to SSL stripping attacks.\n"
                    "Recommendation: Set: "
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                ),
                url=url,
            )
            return

        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        has_include = "includesubdomains" in hsts.lower()
        has_preload = "preload" in hsts.lower()

        evidence_parts = [f"HSTS header: {hsts}"]

        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age == 0:
                self._result.add_finding(
                    message="HSTS max-age is 0, HSTS effectively disabled",
                    severity="HIGH",
                    evidence=f"max-age=0 detected\nFull header: {hsts}",
                    url=url,
                )
                return
            if max_age < 31536000:
                self._result.add_finding(
                    message=(
                        f"HSTS max-age ({max_age}s) is shorter than "
                        f"recommended minimum (31536000s = 1 year)"
                    ),
                    severity="MEDIUM",
                    evidence=f"Current max-age: {max_age}s\nRecommended: ≥31536000s\nFull header: {hsts}",
                    url=url,
                )
            else:
                self._result.add_finding(
                    message=f"HSTS max-age ({max_age}s) meets or exceeds recommended minimum",
                    severity="INFO",
                    evidence=f"max-age: {max_age}s\nFull header: {hsts}",
                    url=url,
                )
        else:
            self._result.add_finding(
                message="HSTS header present but missing max-age directive",
                severity="HIGH",
                evidence=f"Full header: {hsts}",
                url=url,
            )
            return

        if not has_include:
            self._result.add_finding(
                message="HSTS missing 'includeSubDomains' directive",
                severity="MEDIUM",
                evidence=(
                    "Subdomains (e.g., wp-admin.example.com, cdn.example.com) "
                    "are not covered by HSTS.\n"
                    f"Full header: {hsts}"
                ),
                url=url,
            )

        if not has_preload:
            self._result.add_finding(
                message="HSTS missing 'preload' directive",
                severity="LOW",
                evidence=(
                    "First-visit users may still be exposed (the 'first click' problem).\n"
                    "Consider submitting to the HSTS preload list at https://hstspreload.org\n"
                    f"Full header: {hsts}"
                ),
                url=url,
            )

    # ── 2) Content-Security-Policy (CSP) ───────────────────────────────

    def _check_csp(self, headers, url: str) -> None:
        """Check CSP: presence, parse directives, flag dangerous values."""
        csp = headers.get("Content-Security-Policy", "")
        csp_ro = headers.get("Content-Security-Policy-Report-Only", "")

        if not csp and not csp_ro:
            self._result.add_finding(
                message="CSP (Content-Security-Policy) header is MISSING",
                severity="HIGH",
                evidence=(
                    "No Content-Security-Policy header found.\n"
                    "Risk: No defense against XSS injection in plugins/themes/comments.\n"
                    "Recommendation: Define a Content-Security-Policy tailored to your site."
                ),
                url=url,
            )
            return

        # If only report-only mode is set, note it
        if not csp and csp_ro:
            self._result.add_finding(
                message="CSP set in Report-Only mode only, not enforced",
                severity="MEDIUM",
                evidence=(
                    "Content-Security-Policy-Report-Only is present but "
                    "Content-Security-Policy (enforced) is missing.\n"
                    f"Report-Only value: {csp_ro}"
                ),
                url=url,
            )
            # Analyze the report-only policy too
            policy_string = csp_ro
        else:
            policy_string = csp

        directives = self._parse_csp(policy_string)

        # Check for dangerous patterns
        self._analyze_csp_directives(directives, policy_string, url)

    def _parse_csp(self, policy: str) -> dict:
        """Parse a CSP policy string into a dict of directive -> [values]."""
        directives: dict[str, list[str]] = {}
        # Split by semicolons (CSP directives are separated by ;)
        parts = re.split(r";+", policy)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            # First token is the directive name, rest are source expressions
            tokens = part.split()
            if not tokens:
                continue
            directive_name = tokens[0].lower().strip()
            values = [t.strip() for t in tokens[1:] if t.strip()]
            if directive_name:
                if directive_name not in directives:
                    directives[directive_name] = []
                directives[directive_name].extend(values)
        return directives

    def _analyze_csp_directives(self, directives: dict, raw_policy: str, url: str) -> None:
        """Analyze CSP directives and flag dangerous configurations."""
        has_critical = False
        findings_buffer = []

        # Collect all values across executable directives
        for directive_name, values in directives.items():
            if directive_name not in self._EXECUTABLE_DIRECTIVES:
                continue

            # Un nonce ou un hash dans la MÊME directive neutralise 'unsafe-inline'
            # (les navigateurs conformes l'ignorent alors), pas un CRITICAL.
            dir_has_nonce_or_hash = any(
                v.lower().startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                for v in values
            )

            for val in values:
                val_lower = val.lower()

                # ── unsafe-inline: CRITICAL (sauf si neutralisé par nonce/hash) ──
                if val_lower == "'unsafe-inline'":
                    if dir_has_nonce_or_hash:
                        findings_buffer.append(
                            (
                                "LOW",
                                (
                                    f"CSP directive '{directive_name}' contient 'unsafe-inline' "
                                    f"mais un nonce/hash le neutralise (ignoré par les navigateurs conformes)"
                                ),
                                (
                                    f"Directive: {directive_name} = {val}\n"
                                    f"Un nonce/hash est présent dans la même directive → "
                                    f"'unsafe-inline' est ignoré par CSP niveau 2+.\n"
                                    f"Full CSP: {raw_policy}"
                                ),
                            )
                        )
                    else:
                        findings_buffer.append(
                            (
                                "CRITICAL",
                                (
                                    f"CSP directive '{directive_name}' contains 'unsafe-inline'"
                                ),
                                (
                                    f"Directive: {directive_name} = {val}\n"
                                    f"Risk: Allows arbitrary inline scripts/styles, greatly reduces XSS protection.\n"
                                    f"Recommendation: Use nonce- or hash-based CSP instead of 'unsafe-inline'.\n"
                                    f"Full CSP: {raw_policy}"
                                ),
                            )
                        )
                        has_critical = True

                # ── unsafe-eval: HIGH ──
                if val_lower == "'unsafe-eval'":
                    findings_buffer.append(
                        (
                            "HIGH",
                            (
                                f"CSP directive '{directive_name}' contains 'unsafe-eval'"
                            ),
                            (
                                f"Directive: {directive_name} = {val}\n"
                                f"Risk: Allows eval(), can be used for code injection.\n"
                                f"Full CSP: {raw_policy}"
                            ),
                        )
                    )

                # ── Wildcard * in script/executable directives: CRITICAL ──
                if val == "*":
                    findings_buffer.append(
                        (
                            "CRITICAL",
                            (
                                f"CSP directive '{directive_name}' uses wildcard (*) "
                                f"- essentially disables CSP for this resource type"
                            ),
                            (
                                f"Directive: {directive_name} = {val}\n"
                                f"Risk: Any domain can serve content for this resource type.\n"
                                f"Full CSP: {raw_policy}"
                            ),
                        )
                    )
                    has_critical = True

                # ── https: scheme in default-src: HIGH ──
                if (
                    directive_name == "default-src"
                    and val_lower == "https:"
                ):
                    findings_buffer.append(
                        (
                            "HIGH",
                            (
                                "CSP 'default-src' uses 'https:' scheme, allows all "
                                "HTTPS origins"
                            ),
                            (
                                "Directive: default-src = https:\n"
                                f"Risk: Any HTTPS origin is whitelisted, overly permissive.\n"
                                f"Recommendation: Use specific domains instead of the https: scheme.\n"
                                f"Full CSP: {raw_policy}"
                            ),
                        )
                    )

        # Check for wildcard * in ALL directives (not just executable ones)
        # to flag permissive CSP broadly
        for directive_name, values in directives.items():
            if any(
                v == "*" and directive_name not in self._EXECUTABLE_DIRECTIVES
                for v in values
            ):
                # Wildcard sur une directive NON exécutable (img-src, font-src,
                # connect-src…) : permissif mais faible risque (pas d'exécution
                # de script/style) → LOW, pas HIGH.
                findings_buffer.append(
                    (
                        "LOW",
                        (
                            f"CSP directive '{directive_name}' uses wildcard (*)"
                        ),
                        (
                            f"Directive: {directive_name} = *\n"
                            f"Risk (faible) : n'importe quel domaine peut servir ce type "
                            f"de ressource (non exécutable).\n"
                            f"Full CSP: {raw_policy}"
                        ),
                    )
                )

        # Check for object-src 'none'
        object_src = directives.get("object-src", [])
        if object_src:
            if "'none'" not in [v.lower() for v in object_src]:
                findings_buffer.append(
                    (
                        "MEDIUM",
                        "CSP 'object-src' is set but not 'none', Flash/plugin attack vector may remain open",
                        (
                            f"object-src: {' '.join(object_src)}\n"
                            f"Recommendation: Set object-src 'none' to block plugin-based attacks.\n"
                            f"Full CSP: {raw_policy}"
                        ),
                    )
                )
        else:
            # object-src may fall back to default-src
            if "default-src" not in directives:
                findings_buffer.append(
                    (
                        "MEDIUM",
                        "CSP 'object-src' is not set and no 'default-src' fallback, "
                        "Flash/plugin attack vector may remain open",
                        (
                            f"Recommendation: Set object-src 'none' to block plugin-based attacks.\n"
                            f"Full CSP: {raw_policy}"
                        ),
                    )
                )

        # Check for base-uri restriction
        if "base-uri" not in directives:
            findings_buffer.append(
                (
                    "MEDIUM",
                    "CSP 'base-uri' is not set, may be vulnerable to DOM clobbering via <base> tag injection",
                    (
                        "Recommendation: Set 'base-uri self' to prevent attackers from "
                        "changing the base URL for relative links.\n"
                        f"Full CSP: {raw_policy}"
                    ),
                )
            )

        # If no critical issues found but CSP is present, log a positive finding
        if not has_critical and not findings_buffer:
            self._result.add_finding(
                message="CSP (Content-Security-Policy) is present with no critical issues detected",
                severity="INFO",
                evidence=f"Full CSP: {raw_policy}",
                url=url,
            )
            return

        # Emit all findings
        for sev, msg, ev in findings_buffer:
            self._result.add_finding(
                message=msg,
                severity=sev,
                evidence=ev,
                url=url,
            )

    # ── 3) X-Frame-Options ─────────────────────────────────────────────

    def _check_x_frame_options(self, headers, url: str) -> None:
        """Check X-Frame-Options: must be DENY or SAMEORIGIN."""
        xfo = headers.get("X-Frame-Options", "")

        if not xfo:
            # CSP 'frame-ancestors' est le remplaçant moderne et recommandé de
            # X-Frame-Options : s'il est présent, la page EST protégée contre le
            # clickjacking, l'absence de l'en-tête legacy n'est pas un HIGH.
            csp = headers.get("Content-Security-Policy", "")
            if "frame-ancestors" in csp.lower():
                self._result.add_finding(
                    message="X-Frame-Options absent mais CSP 'frame-ancestors' présent (protégé)",
                    severity="INFO",
                    evidence=(
                        "Pas d'en-tête X-Frame-Options, mais la CSP définit "
                        "'frame-ancestors' (protection anti-clickjacking moderne).\n"
                        f"CSP: {csp}"
                    ),
                    url=url,
                    confidence="potential",
                )
                return
            self._result.add_finding(
                message="X-Frame-Options header is MISSING, page may be embeddable by any site (clickjacking)",
                severity="HIGH",
                evidence=(
                    "No X-Frame-Options header found.\n"
                    "Risk: Clickjacking, an attacker could embed this page in a "
                    "transparent iframe to trick users.\n"
                    "Recommendation: Set 'X-Frame-Options: DENY' (or SAMEORIGIN if "
                    "same-origin framing is needed)."
                ),
                url=url,
            )
            return

        xfo_upper = xfo.strip().upper()
        if xfo_upper not in ("DENY", "SAMEORIGIN"):
            self._result.add_finding(
                message=(
                    f"X-Frame-Options set to '{xfo.strip()}', "
                    f"not DENY or SAMEORIGIN"
                ),
                severity="MEDIUM",
                evidence=(
                    f"Current value: {xfo.strip()}\n"
                    f"Recommendation: Use 'DENY' or 'SAMEORIGIN'.\n"
                    f"Note: 'ALLOW-FROM' is obsolete and ignored by Chrome/Safari."
                ),
                url=url,
            )
        else:
            self._result.add_finding(
                message=f"X-Frame-Options is set to '{xfo.strip()}'",
                severity="INFO",
                evidence=f"Value: {xfo.strip()}\nRisk: Protected against clickjacking.",
                url=url,
            )

    # ── 4) X-Content-Type-Options ──────────────────────────────────────

    def _check_x_content_type_options(self, headers, url: str) -> None:
        """Check X-Content-Type-Options: must be nosniff."""
        xcto = headers.get("X-Content-Type-Options", "")

        if not xcto:
            self._result.add_finding(
                message="X-Content-Type-Options header is MISSING, browser may MIME-sniff (MIME sniffing risk)",
                severity="HIGH",
                evidence=(
                    "No X-Content-Type-Options header found.\n"
                    "Risk: Browser may interpret uploaded files (e.g., image.jpg with "
                    "embedded JS) as executable scripts.\n"
                    "Recommendation: Set 'X-Content-Type-Options: nosniff'."
                ),
                url=url,
            )
            return

        if xcto.strip().lower() != "nosniff":
            self._result.add_finding(
                message=(
                    f"X-Content-Type-Options set to '{xcto.strip()}' "
                    f"- should be 'nosniff'"
                ),
                severity="MEDIUM",
                evidence=(
                    f"Current value: {xcto.strip()}\n"
                    f"Recommendation: Set 'X-Content-Type-Options: nosniff'."
                ),
                url=url,
            )
        else:
            self._result.add_finding(
                message="X-Content-Type-Options is set to 'nosniff'",
                severity="INFO",
                evidence="Value: nosniff\nRisk: Protected against MIME sniffing.",
                url=url,
            )

    # ── 5) Referrer-Policy ─────────────────────────────────────────────

    def _check_referrer_policy(self, headers, url: str) -> None:
        """Check Referrer-Policy: presence only."""
        rp = headers.get("Referrer-Policy", "")

        if not rp:
            self._result.add_finding(
                message="Referrer-Policy header is MISSING, URL path/query params may leak to external sites",
                severity="MEDIUM",
                evidence=(
                    "No Referrer-Policy header found.\n"
                    "Risk: Browser default (no-referrer-when-downgrade) may leak "
                    "full URLs to cross-origin destinations.\n"
                    "Recommendation: Set 'Referrer-Policy: strict-origin-when-cross-origin'."
                ),
                url=url,
            )
            return

        rp_lower = rp.strip().lower()
        if rp_lower in ("unsafe-url",):
            self._result.add_finding(
                message=(
                    f"Referrer-Policy set to '{rp.strip()}', "
                    f"leaks entire URL to ANY destination"
                ),
                severity="HIGH",
                evidence=(
                    f"Current value: {rp.strip()}\n"
                    f"Risk: Full URLs including query parameters, session IDs, "
                    f"and password reset tokens are leaked to external sites.\n"
                    f"Recommendation: Use 'strict-origin-when-cross-origin'."
                ),
                url=url,
            )
        else:
            self._result.add_finding(
                message=f"Referrer-Policy is set to '{rp.strip()}'",
                severity="INFO",
                evidence=f"Value: {rp.strip()}",
                url=url,
            )

    # ── 6) Permissions-Policy (ex Feature-Policy) ──────────────────────

    def _check_permissions_policy(self, headers, url: str) -> None:
        """Check Permissions-Policy (or legacy Feature-Policy) presence."""
        pp = headers.get("Permissions-Policy", "")
        fp = headers.get("Feature-Policy", "")

        if not pp and not fp:
            self._result.add_finding(
                message="Permissions-Policy header is MISSING, browser APIs unrestricted",
                severity="MEDIUM",
                evidence=(
                    "No Permissions-Policy (or legacy Feature-Policy) header found.\n"
                    "Risk: Third-party scripts, ads, or compromised plugins have "
                    "unrestricted access to browser APIs (geolocation, camera, "
                    "microphone, etc.).\n"
                    "Recommendation: Set Permissions-Policy to restrict unused APIs."
                ),
                url=url,
            )
            return

        if pp:
            self._result.add_finding(
                message=f"Permissions-Policy is present: '{pp.strip()}'",
                severity="INFO",
                evidence=f"Value: {pp.strip()}",
                url=url,
            )
        if fp:
            self._result.add_finding(
                message=f"Legacy Feature-Policy header is present: '{fp.strip()}'",
                severity="INFO",
                evidence=(
                    f"Feature-Policy value: {fp.strip()}\n"
                    "Note: Feature-Policy is deprecated in favor of Permissions-Policy."
                ),
                url=url,
            )

    # ── 7) X-XSS-Protection (deprecated) ───────────────────────────────

    def _check_xss_protection(self, headers, url: str) -> None:
        """Check X-XSS-Protection: note if present (deprecated)."""
        xssp = headers.get("X-XSS-Protection", "")

        if not xssp:
            self._result.add_finding(
                message="X-XSS-Protection header is not present (acceptable, this header is deprecated)",
                severity="INFO",
                evidence=(
                    "X-XSS-Protection is missing.\n"
                    "Note: This header is deprecated. Modern browsers (Chrome ≥ 78, "
                    "Firefox ≥ 4) have removed their XSS filters in favor of CSP. "
                    "If CSP is in place, this is not a concern."
                ),
                url=url,
            )
            return

        self._result.add_finding(
            message=f"X-XSS-Protection header is present: '{xssp.strip()}' (deprecated)",
            severity="INFO",
            evidence=(
                f"Current value: {xssp.strip()}\n"
                "Note: This header is deprecated. Modern browsers ignore it. "
                "The value '0' is recommended to disable the legacy filter in "
                "older browsers. CSP is the modern XSS defense."
            ),
            url=url,
        )
