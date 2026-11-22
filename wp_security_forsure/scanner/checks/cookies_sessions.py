"""Check, WordPress Cookie & Session Security.

Analyses authentication cookie security for a WordPress target by:

  1. Fetching Set-Cookie headers from homepage, login page, and admin-ajax.php
  2. Parsing Secure, HttpOnly, SameSite flags on every cookie
  3. Detecting wordpress_test_cookie exposure
  4. Session fixation test (pre-login session ID patterns)
  5. Cookie domain scope analysis (wildcard detection)
  6. Remember-me cookie detection (long-lived wordpress_logged_in_*)
  7. Application Passwords stateless auth check via REST API /users/me
  8. Multiple auth cookie instances across subdomains

Severity mapping (per task spec):
  CRITICAL , missing Secure or HttpOnly flag on any cookie
  HIGH     , SameSite=None attribute
  MEDIUM   , missing SameSite attribute
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseCheck, CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"
SEV_INFO = "INFO"

# Cookie expiry thresholds (seconds)
STD_SESSION_MAX = 172800       # 48 h
REMEMBER_ME_DEFAULT = 1209600  # 14 d
REMEMBER_ME_WARN = 2592000     # 30 d

# WordPress auth cookie name prefixes
_WP_AUTH_PREFIXES = (
    "wordpress_logged_in_",
    "wordpress_sec_",
    "wordpress_",
    "wp-settings-",
    "wp-settings-time-",
)

# ---------------------------------------------------------------------------
# Cookie-parsing helpers
# ---------------------------------------------------------------------------


def _get_set_cookie_values(resp) -> List[str]:
    """Extract *all* raw Set-Cookie header values, preserving attributes.

    Uses three strategies in order of reliability:
      1. ``resp.raw.headers`` (urllib3 ``HTTPHeaderDict``), keeps
         multi-valued headers and supports ``.items()``.
      2. ``resp.raw._original_response.msg`` (http.client
         ``HTTPMessage``), falls back to ``.get_all()``.
      3. ``resp.headers["Set-Cookie"]``, last resort, single value only.
    """
    cookies: List[str] = []

    # Strategy 1, urllib3 HTTPHeaderDict
    try:
        raw = resp.raw
        if hasattr(raw, "headers"):
            for key, value in raw.headers.items():
                if key.lower() == "set-cookie":
                    cookies.append(value)
    except (AttributeError, ValueError, RuntimeError):
        pass

    # Strategy 2, http.client HTTPMessage
    if not cookies:
        try:
            msg = resp.raw._original_response.msg  # type: ignore[union-attr]
            if hasattr(msg, "get_all"):
                cookies = msg.get_all("Set-Cookie") or []
        except (AttributeError, ValueError, RuntimeError):
            pass

    # Strategy 3, final fallback
    if not cookies and "Set-Cookie" in resp.headers:
        cookies = [resp.headers["Set-Cookie"]]

    return cookies


def _cookie_name(raw: str) -> str:
    """Return the name portion of a raw ``Set-Cookie`` value."""
    m = re.match(r"^([^=]+)=", raw)
    return m.group(1) if m else ""


def _cookie_attr(raw: str, attr: str) -> str:
    """Return the value of a cookie attribute, or empty string if absent.

    For boolean flags (Secure, HttpOnly) returns the flag text when
    present.  For key=value attributes (SameSite, Domain, Path, Max-Age,
    Expires) returns the value after ``=``.
    """
    if attr.lower() in ("secure", "httponly"):
        for part in raw.split(";"):
            if part.strip().lower() == attr.lower():
                return part.strip()
        return ""
    m = re.search(
        re.escape(attr) + r"\s*=\s*([^;\s]+)", raw, re.IGNORECASE,
    )
    return m.group(1) if m else ""


def _is_auth_cookie(name: str) -> bool:
    """Return True if *name* looks like a WordPress auth cookie."""
    if not name:
        return False
    nl = name.lower()
    return any(nl.startswith(p.lower()) for p in _WP_AUTH_PREFIXES)


def _is_remember_me(name: str) -> bool:
    """Return True if *name* looks like a ``wordpress_logged_in_*`` cookie."""
    return name.lower().startswith("wordpress_logged_in_")


# ---------------------------------------------------------------------------
# Check class
# ---------------------------------------------------------------------------


class CookiesSessionsCheck(BaseCheck):
    """Evaluates WordPress authentication cookie security."""

    name = "cookies_sessions"
    title = "WordPress Cookie & Session Security"
    description = (
        "Analyses authentication cookie security including flag presence "
        "(Secure, HttpOnly, SameSite), session fixation resistance, "
        "test cookie exposure, cookie domain scope, "
        "remember-me cookie lifetime, application passwords stateless auth, "
        "and multiple auth cookie instances."
    )
    severity = SEV_HIGH
    access_tier = 1  # accueil, wp-login.php, admin-ajax.php, REST

    # ------------------------------------------------------------------
    def run(self) -> CheckResult:
        """Execute all cookie/session security checks."""
        self._check_cookie_flags()
        self._check_test_cookie()
        self._check_session_fixation()
        self._check_domain_scope()
        self._check_remember_me()
        self._check_application_passwords()
        self._check_multiple_auth_cookies()
        return self._result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_cookies(self, path: str) -> List[str]:
        """GET *path* and return all raw Set-Cookie header values."""
        try:
            resp = self.http_get(path)
            return _get_set_cookie_values(resp)
        except Exception as exc:
            self._result.add_finding(
                message=f"Failed to fetch cookies from {path}: {exc}",
                severity=SEV_INFO,
                evidence=str(exc),
                url=f"{self.target.rstrip('/')}/{path.lstrip('/')}",
            )
            return []

    # ------------------------------------------------------------------
    # 1 & 2, Cookie Flags Check (homepage, login, admin-ajax)
    # ------------------------------------------------------------------

    def _check_cookie_flags(self) -> None:
        """Fetch cookies from all relevant pages and check Secure, HttpOnly,
        SameSite."""
        paths = ["", "wp-login.php", "wp-admin/admin-ajax.php"]
        all_cookies: List[Tuple[str, str, str]] = []

        for path in paths:
            for rc in self._fetch_cookies(path):
                all_cookies.append((path, rc, f"{self.target}/{path}"))

        if not all_cookies:
            self._result.add_finding(
                message="No Set-Cookie headers found on any page.",
                severity=SEV_INFO,
                evidence=(
                    "Homepage, wp-login.php, and admin-ajax.php "
                    "returned no Set-Cookie headers."
                ),
            )
            return

        seen: set = set()
        for page_path, raw, url in all_cookies:
            name = _cookie_name(raw)
            if not name or (name, page_path) in seen:
                continue
            seen.add((name, page_path))

            secure = _cookie_attr(raw, "Secure")
            httponly = _cookie_attr(raw, "HttpOnly")
            samesite = _cookie_attr(raw, "SameSite")
            is_auth = _is_auth_cookie(name)

            ev = (
                f"Cookie: {name}\n"
                f"  Secure:   {'PRESENT' if secure else 'MISSING'}\n"
                f"  HttpOnly: {'PRESENT' if httponly else 'MISSING'}\n"
                f"  SameSite: {samesite if samesite else 'NOT SET'}"
            )

            # Secure flag missing → CRITICAL
            if not secure:
                tag = "auth cookie" if is_auth else "cookie"
                self._result.add_finding(
                    message=(
                        f"{name} ({tag}) missing Secure flag, "
                        "cookie sent in cleartext over HTTP."
                    ),
                    severity=SEV_CRITICAL,
                    evidence=ev,
                    url=url,
                )

            # HttpOnly flag missing → CRITICAL
            if not httponly:
                tag = "auth cookie" if is_auth else "cookie"
                self._result.add_finding(
                    message=(
                        f"{name} ({tag}) missing HttpOnly flag, "
                        "accessible via JavaScript (XSS risk)."
                    ),
                    severity=SEV_CRITICAL,
                    evidence=ev,
                    url=url,
                )

            # SameSite=None → HIGH
            if samesite and samesite.lower() == "none":
                self._result.add_finding(
                    message=(
                        f"{name} has SameSite=None, "
                        "cookie sent on cross-site requests (CSRF risk)."
                    ),
                    severity=SEV_HIGH,
                    evidence=ev,
                    url=url,
                )
            elif not samesite:
                # Missing SameSite → MEDIUM (browser-dependent default)
                self._result.add_finding(
                    message=(
                        f"{name} has no SameSite attribute, "
                        "browser-dependent default behaviour."
                    ),
                    severity=SEV_MEDIUM,
                    evidence=ev,
                    url=url,
                )

    # ------------------------------------------------------------------
    # 3, WordPress Test Cookie Detection
    # ------------------------------------------------------------------

    def _check_test_cookie(self) -> None:
        """Detect ``wordpress_test_cookie`` in headers and page source."""
        # Headers on login page
        for rc in self._fetch_cookies("wp-login.php"):
            name = _cookie_name(rc)
            if "wordpress_test_cookie" in name.lower() or "test" in name.lower():
                secure = _cookie_attr(rc, "Secure")
                httponly = _cookie_attr(rc, "HttpOnly")
                samesite = _cookie_attr(rc, "SameSite")
                ev = (
                    f"Test cookie found: {name}\n"
                    f"  Secure:   {'PRESENT' if secure else 'MISSING'}\n"
                    f"  HttpOnly: {'PRESENT' if httponly else 'MISSING'}\n"
                    f"  SameSite: {samesite if samesite else 'NOT SET'}"
                )
                self._result.add_finding(
                    message=(
                        f'WordPress test cookie "{name}" detected in '
                        "HTTP response headers, confirms cookie "
                        "mechanism is active."
                    ),
                    severity=SEV_INFO,
                    evidence=ev,
                    url=f"{self.target}/wp-login.php",
                )
                break

        # Page source, JS-injected test cookie
        try:
            resp = self.http_get("")
            idx = resp.text.find("wordpress_test_cookie")
            if idx != -1:
                ctx = resp.text[max(0, idx - 40): idx + 60]
                self._result.add_finding(
                    message=(
                        "wordpress_test_cookie referenced in page source "
                        "(likely set via JavaScript for comment forms)."
                    ),
                    severity=SEV_INFO,
                    evidence=f"Page source context: ...{ctx}...",
                    url=self.target,
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 4, Session Fixation Test
    # ------------------------------------------------------------------

    def _check_session_fixation(self) -> None:
        """Fetch wp-login.php pre-auth and analyse session cookies."""
        try:
            resp = self.http_get("wp-login.php")
        except Exception as exc:
            self._result.add_finding(
                message=f"Session fixation pre-login fetch failed: {exc}",
                severity=SEV_INFO,
                evidence=str(exc),
            )
            return

        pre_cookies = _get_set_cookie_values(resp)

        if not pre_cookies:
            self._result.add_finding(
                message=(
                    "No pre-login session cookies detected, "
                    "WordPress does not appear to set PHP session cookies "
                    "before authentication."
                ),
                severity=SEV_INFO,
                evidence=(
                    "No Set-Cookie headers on wp-login.php before login. "
                    "WordPress default behaviour is stateless pre-auth."
                ),
            )
            return

        # Look for session identifiers (PHPSESSID, etc.)
        session_cookies: List[Tuple[str, str]] = []
        auth_cookies_pre: List[Tuple[str, str]] = []

        for rc in pre_cookies:
            name = _cookie_name(rc)
            if not name:
                continue
            if name.lower().startswith("phpsess") or "sess" in name.lower():
                session_cookies.append((name, rc))
            if _is_auth_cookie(name):
                auth_cookies_pre.append((name, rc))

        # Auth cookies before login → leakage
        if auth_cookies_pre:
            lines = ["Auth-like cookies found before login (possible leakage):"]
            for n, rc in auth_cookies_pre:
                lines.append(f"  {n}: {rc[:80]}")
            self._result.add_finding(
                message=(
                    "Auth cookies detected before authentication, "
                    "possible session leakage via cache or proxy."
                ),
                severity=SEV_HIGH,
                evidence="\n".join(lines),
                url=f"{self.target}/wp-login.php",
            )

        # Session ID pre-auth → fixation surface
        if session_cookies:
            lines = ["Session cookies set before login:"]
            for n, rc in session_cookies:
                lines.append(f"  {n}")
                lines.append(f"    Raw: {rc[:100]}")
            lines.append(
                "\nPHP session cookies set pre-auth indicate WordPress or a "
                "plugin is starting sessions before login. If the session ID "
                "is not regenerated on login, session fixation attacks are "
                "possible."
            )
            self._result.add_finding(
                message=(
                    "Session cookie detected before authentication, "
                    "possible session fixation attack surface."
                ),
                severity=SEV_MEDIUM,
                evidence="\n".join(lines),
                url=f"{self.target}/wp-login.php",
            )
        else:
            self._result.add_finding(
                message=(
                    "No PHP session cookies detected pre-login, "
                    "WordPress default (stateless before auth)."
                ),
                severity=SEV_INFO,
                evidence=(
                    "No PHPSESSID or similar session identifier found "
                    "in pre-login cookies."
                ),
            )

    # ------------------------------------------------------------------
    # 5, Cookie Domain Scope
    # ------------------------------------------------------------------

    def _check_domain_scope(self) -> None:
        """Check for wildcard / broad domain attributes on cookies."""
        checked: set = set()
        for path in ("", "wp-login.php"):
            for rc in self._fetch_cookies(path):
                name = _cookie_name(rc)
                if not name or name in checked:
                    continue
                checked.add(name)

                domain = _cookie_attr(rc, "Domain")
                cookie_path = _cookie_attr(rc, "Path") or "/"
                if not domain:
                    continue  # origin-only, secure default

                ev = (
                    f"Cookie: {name}\n"
                    f"  Domain: {domain}\n"
                    f"  Path:   {cookie_path}"
                )

                if domain.startswith("."):
                    self._result.add_finding(
                        message=(
                            f"{name} has wildcard domain "
                            f'"{domain}", cookie shared across '
                            "all subdomains (subdomain hijacking risk)."
                        ),
                        severity=SEV_HIGH,
                        evidence=ev,
                        url=f"{self.target}/{path}",
                    )

    # ------------------------------------------------------------------
    # 6, Remember-Me Cookie Detection
    # ------------------------------------------------------------------

    def _check_remember_me(self) -> None:
        """Detect long-lived wordpress_logged_in_* cookies."""
        auth_cookies: List[Tuple[str, str]] = []
        for path in ("", "wp-login.php"):
            for rc in self._fetch_cookies(path):
                name = _cookie_name(rc)
                if _is_remember_me(name):
                    auth_cookies.append((path, rc))

        if not auth_cookies:
            self._result.add_finding(
                message=(
                    "No wordpress_logged_in_ cookies found "
                    "(expected, unauthenticated scan)."
                ),
                severity=SEV_INFO,
                evidence="No remember-me style cookies detected.",
            )
            return

        for path, rc in auth_cookies:
            name = _cookie_name(rc)
            max_age_s = _cookie_attr(rc, "Max-Age")
            expires_s = _cookie_attr(rc, "Expires")

            lines = [f"Cookie: {name}"]
            duration: Optional[int] = None

            if max_age_s:
                try:
                    duration = int(max_age_s)
                    days = duration // 86400
                    lines.append(
                        f"  Max-Age: {duration}s ({days}d)"
                    )
                except ValueError:
                    pass
            elif expires_s:
                lines.append(f"  Expires: {expires_s}")

            ev = "\n".join(lines)

            if duration is not None:
                days = duration // 86400
                if duration > REMEMBER_ME_WARN:
                    self._result.add_finding(
                        message=(
                            f"{name} has excessively long expiry "
                            f"({days} days > 30), remember-me cookie "
                            "could be stolen and reused for a month+."
                        ),
                        severity=SEV_HIGH,
                        evidence=ev,
                        url=f"{self.target}/{path}",
                    )
                elif duration > REMEMBER_ME_DEFAULT:
                    self._result.add_finding(
                        message=(
                            f"{name} has long expiry "
                            f"({days} days > 14), exceeds default "
                            "remember-me period."
                        ),
                        severity=SEV_MEDIUM,
                        evidence=ev,
                        url=f"{self.target}/{path}",
                    )
                elif duration > STD_SESSION_MAX:
                    self._result.add_finding(
                        message=(
                            f"{name} has extended expiry "
                            f"({days} days > 2), remember-me is active."
                        ),
                        severity=SEV_LOW,
                        evidence=ev,
                        url=f"{self.target}/{path}",
                    )

    # ------------------------------------------------------------------
    # 7, Application Passwords / Stateless Auth
    # ------------------------------------------------------------------

    def _check_application_passwords(self) -> None:
        """Check REST API for Application Password acceptance.

        Hits ``/wp-json/wp/v2/users/me`` and checks whether cookies are
        still present (Application Passwords should be stateless).
        """
        try:
            resp = self.http_get("wp-json/wp/v2/users/me")
        except Exception as exc:
            self._result.add_finding(
                message=(
                    "Application password REST API check failed: "
                    f"{exc}"
                ),
                severity=SEV_INFO,
                evidence=str(exc),
            )
            return

        rest_cookies = _get_set_cookie_values(resp)

        if rest_cookies:
            lines = ["REST API /wp/v2/users/me sets cookies:"]
            for rc in rest_cookies:
                lines.append(f"  {rc[:100]}")
            lines.append(
                "\nApplication Passwords should be stateless (no cookies). "
                "Cookies from the REST API suggest mixed auth methods."
            )
            self._result.add_finding(
                message=(
                    "REST API /wp/v2/users/me sets cookies, "
                    "Application Passwords are meant to be stateless. "
                    "Possible mixed auth model."
                ),
                severity=SEV_MEDIUM,
                evidence="\n".join(lines),
                url=f"{self.target}/wp-json/wp/v2/users/me",
            )
        else:
            self._result.add_finding(
                message=(
                    "REST API /wp/v2/users/me does not set cookies, "
                    "consistent with stateless Application Password auth."
                ),
                severity=SEV_INFO,
                evidence="No Set-Cookie headers from REST API endpoint.",
                url=f"{self.target}/wp-json/wp/v2/users/me",
            )

        # Check response body for application password mentions
        body = resp.text.lower()
        if "application_password" in body or "application password" in body:
            self._result.add_finding(
                message=(
                    "Application Passwords referenced in REST API "
                    "response, feature appears to be enabled."
                ),
                severity=SEV_INFO,
                evidence="'Application Password' mentioned in response body.",
                url=f"{self.target}/wp-json/wp/v2/users/me",
            )

    # ------------------------------------------------------------------
    # 8, Multiple Auth Cookie Instances
    # ------------------------------------------------------------------

    def _check_multiple_auth_cookies(self) -> None:
        """Detect multiple auth cookie instances across pages."""
        paths = ["", "wp-login.php", "wp-admin/admin-ajax.php"]
        auth_by_name: Dict[str, List[Tuple[str, str]]] = {}

        for path in paths:
            for rc in self._fetch_cookies(path):
                name = _cookie_name(rc)
                if name and _is_auth_cookie(name):
                    auth_by_name.setdefault(name, []).append((path, rc))

        # Same cookie name set on multiple pages
        for cname, instances in auth_by_name.items():
            if len(instances) > 1:
                lines = [
                    f'Cookie "{cname}" set on {len(instances)} pages:',
                ]
                for p, rc in instances:
                    domain = _cookie_attr(rc, "Domain") or "origin-only"
                    cpath = _cookie_attr(rc, "Path") or "/"
                    lines.append(
                        f"  Page: {p} | Domain: {domain} | Path: {cpath}"
                    )
                self._result.add_finding(
                    message=(
                        f'Auth cookie "{cname}" appears on '
                        f"{len(instances)} different pages, "
                        "possible conflicting cookie paths or "
                        "misconfigured cache/proxy."
                    ),
                    severity=SEV_MEDIUM,
                    evidence="\n".join(lines),
                    url=f"{self.target}/wp-login.php",
                )

        # Different auth cookie prefixes → separate WP installs
        prefixes: set = set()
        for cname in auth_by_name:
            if cname.startswith("wordpress_sec_"):
                prefixes.add("wordpress_sec_")
            elif cname.startswith("wordpress_logged_in_"):
                prefixes.add("wordpress_logged_in_")
            elif cname.startswith("wordpress_"):
                prefixes.add("wordpress_")
            elif cname.startswith("wp-settings-"):
                prefixes.add("wp-settings-")

        if len(prefixes) > 2:
            self._result.add_finding(
                message=(
                    f"Multiple auth cookie prefixes detected "
                    f"({len(prefixes)}): "
                    f'{", ".join(sorted(prefixes))}. '
                    "Possible multiple WordPress installations "
                    "on same domain."
                ),
                severity=SEV_LOW,
                evidence=(
                    f"Auth cookie prefixes: "
                    f'{", ".join(sorted(prefixes))}'
                ),
            )

        if not auth_by_name:
            self._result.add_finding(
                message=(
                    "No auth cookies found "
                    "(expected for unauthenticated scan)."
                ),
                severity=SEV_INFO,
                evidence="No WordPress auth cookie prefixes detected.",
            )
