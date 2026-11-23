"""Check for WordPress REST API security issues.

Inherits from BaseCheck. Covers namespace enumeration, user enumeration,
posts/pages/media exposure, custom plugin endpoints, SSRF vectors (block
directory, pattern directory, oEmbed), CORS misconfiguration, rest_route
bypass, search data leakage, application passwords, site health disclosure,
and JSONP callback XSS.

Flagged CRITICAL:
  - User enumeration (any users returned or ID oracle)
  - Private data leaks via posts/pages (draft/private content exposed)
  - Unauthenticated sensitive endpoints (application passwords data)
  - JSONP callback XSS reflection

Flagged HIGH:
  - CORS reflective/wildcard misconfiguration
  - Custom plugin endpoints returning data without auth
  - SSRF vectors (block/pattern/oEmbed)
  - rest_route bypass working
  - Post revisions accessible unauthenticated
"""

from typing import List, Optional, Any
import json

from ..redact import mask_email, mask_username, usernames_masked
from .base import BaseCheck, CheckResult
from .brute_force_login import (UserSighting, report_risky_accounts,
                                rest_user_sightings)
from .rest_api_data import (
    RISKY_NAMESPACE_PATTERNS,
    CORE_NAMESPACE_PREFIXES,
    JSONP_PARAMS,
    BAC_ENDPOINTS,
    BAC_SENSITIVE_ROUTE,
    BAC_MAX_REQUESTS,
)


class RestApiCheck(BaseCheck):
    """Check for WordPress REST API security issues."""

    name = "rest_api"
    title = "WordPress REST API Security Audit"
    description = (
        "Audits the WordPress REST API for security issues including "
        "namespace enumeration, user enumeration, posts/pages/media exposure, "
        "custom plugin endpoints, SSRF vectors (block directory, pattern "
        "directory, oEmbed), CORS misconfiguration, rest_route bypass, "
        "search data leakage, application passwords exposure, site health "
        "disclosure, and JSONP callback XSS."
    )
    severity = "CRITICAL"
    access_tier = 1  # routes REST en lecture
    depends_on: List[str] = []

    def __init__(self, target: str, config: dict, session):
        super().__init__(target, config, session)
        # Noms relevés par l'énumération (liste et fiches wp/v2/users),
        # confrontés à la liste unique des noms à risque (redact).
        self._sightings: List[UserSighting] = []

    # ── Public API ────────────────────────────────────────────────────

    def run(self) -> CheckResult:
        """Execute the REST API security audit."""
        self._check_namespace_enumeration()
        self._check_user_enumeration()
        self._check_posts_pages_exposure()
        self._check_media_endpoint()
        self._check_custom_plugin_endpoints()
        self._check_block_directory()
        self._check_pattern_directory()
        self._check_application_passwords()
        self._check_cors()
        self._check_rest_disabled_bypass()
        self._check_oembed_ssrf()
        self._check_search_data_leakage()
        self._check_site_health()
        self._check_jsonp_callback()
        self._check_bac_endpoints()
        return self._result

    # ── 1) Namespace enumeration from /wp-json/ root ──────────────────

    def _check_namespace_enumeration(self) -> None:
        """Fetch /wp-json/ root and enumerate all namespaces and routes."""
        data, resp = self.get_json("wp-json/")
        if resp is None:
            return

        if resp.status_code != 200:
            self._result.add_finding(
                message=(
                    f"REST API root returned HTTP {resp.status_code} "
                    f"- API may be disabled or blocked"
                ),
                severity="INFO",
                evidence=f"GET /wp-json/ -> HTTP {resp.status_code}",
                url=f"{self.target.rstrip('/')}/wp-json/",
            )
            return

        if data is None:
            # Not JSON, API likely disabled or returns HTML
            snippet = resp.text[:200].strip()
            self._result.add_finding(
                message=(
                    "REST API root does not return JSON, "
                    "API may be disabled"
                ),
                severity="INFO",
                evidence=f"Non-JSON response: {snippet}",
                url=f"{self.target.rstrip('/')}/wp-json/",
            )
            return

        # Store for use by other check methods
        self._wp_json_data = data

        namespaces: List[str] = data.get("namespaces", [])
        routes = data.get("routes", {})
        route_count = len(routes)
        ns_count = len(namespaces)

        self._result.add_finding(
            message=(
                f"REST API is active, {route_count} routes across "
                f"{ns_count} namespaces"
            ),
            severity="INFO",
            evidence=(
                f"Namespaces: {', '.join(namespaces[:20])}\n"
                f"Total routes: {route_count}"
            ),
            url=f"{self.target.rstrip('/')}/wp-json/",
        )

        # Flag high namespace count as potential bloat
        custom_ns = [
            ns for ns in namespaces
            if not ns.startswith(CORE_NAMESPACE_PREFIXES)
        ]
        if len(custom_ns) > 5:
            self._result.add_finding(
                message=(
                    f"High number of custom namespaces ({len(custom_ns)}) "
                    f"- large plugin attack surface"
                ),
                severity="MEDIUM",
                evidence=(
                    f"Custom namespaces: {', '.join(custom_ns)}"
                ),
                url=f"{self.target.rstrip('/')}/wp-json/",
            )

    # ── 2) User enumeration ────────────────────────────────────────────

    def _user(self, name) -> str:
        """Nom tel qu'il peut figurer dans une preuve (redact.mask_username)."""
        return mask_username(name, self.target, usernames_masked(self.config))

    def _saw_rest_user(self, user: dict, source: str) -> None:
        self._sightings += rest_user_sightings(user, source)

    def _report_risky_accounts(self) -> None:
        """Comptes à risque vus par cette source (même message que
        brute_force_login : le moteur n'en garde qu'un)."""
        report_risky_accounts(self._result, self.target, self._sightings)

    def _check_user_enumeration(self) -> None:
        """Check for user enumeration via /wp/v2/users/."""
        if self._check_user_enumeration_list():
            self._check_user_enumeration_ids()
        self._report_risky_accounts()

    def _check_user_enumeration_list(self) -> bool:
        """a) Liste des utilisateurs. False si l'API ne répond pas ou refuse :
        l'oracle par identifiant n'est alors pas tenté."""
        url_path = "wp-json/wp/v2/users"
        users, resp = self.get_json(url_path)
        if users is None:
            return False

        # Check for error response
        if isinstance(users, dict) and "code" in users:
            code = users.get("code", "")
            if code == "rest_user_cannot_view":
                self._result.add_finding(
                    message=(
                        "Users endpoint restricted (rest_user_cannot_view) "
                        "- user protection active"
                    ),
                    severity="INFO",
                    evidence=f"REST API error: {users.get('message', '')}",
                    url=f"{self.target.rstrip('/')}/{url_path}",
                )
            return False

        # Users returned as array
        if isinstance(users, list) and len(users) > 0:
            users = [u for u in users if isinstance(u, dict)]
            for u in users:
                self._saw_rest_user(u, "API REST wp-json/wp/v2/users")
            user_ids = [u.get("id") for u in users if u.get("id")]
            user_slugs = [self._user(u.get("slug")) for u in users if u.get("slug")]
            has_email = any(u.get("email") for u in users)

            severity = "CRITICAL" if has_email else "HIGH"
            evidence_parts = []
            evidence_parts.append(
                f"Users exposed: {len(users)} "
                f"(IDs: {user_ids[:20]})"
            )
            evidence_parts.append(
                f"Slugs: {user_slugs[:20]}"
            )
            if has_email:
                evidence_parts.append(
                    "EMAIL ADDRESSES EXPOSED, this is a critical data leak"
                )

            # Check for admin user
            admin_user = None
            for u in users:
                if u.get("id") == 1 or u.get("slug") == "admin":
                    admin_user = u
                    break
            if admin_user:
                evidence_parts.append(
                    f"Admin user found: id={admin_user.get('id')}, "
                    f"slug={self._user(admin_user.get('slug'))}, "
                    f"name={self._user(admin_user.get('name'))}"
                )

            # Try to get X-WP-Total header for user count
            try:
                head_resp = self.http_head(url_path)
                total = head_resp.headers.get("X-WP-Total", "")
                if total:
                    evidence_parts.append(f"X-WP-Total header reveals {total} total users")
            except Exception:
                pass

            self._result.add_finding(
                message=(
                    f"User enumeration via /wp/v2/users, "
                    f"{len(users)} users exposed"
                ),
                severity=severity,
                evidence="\n".join(evidence_parts),
                url=f"{self.target.rstrip('/')}/{url_path}",
            )
        return True

    def _check_user_enumeration_ids(self) -> None:
        """b) Oracle par identifiant, ID 1 à 10."""
        for uid in range(1, 11):
            u_data, u_resp = self.get_json(f"wp-json/wp/v2/users/{uid}")
            if u_data is None:
                continue

            if isinstance(u_data, dict) and "code" in u_data:
                code = u_data.get("code", "")
                if code == "rest_user_invalid_id":
                    # User doesn't exist, stop if we hit a gap
                    # If uid=1 exists but uid=2 doesn't, we have a gap
                    # but still note that user 1 exists
                    if uid == 1:
                        # User 1 doesn't exist, unusual
                        pass
                    continue
                elif code == "rest_user_cannot_view":
                    # User exists but protected, this is an oracle
                    self._result.add_finding(
                        message=(
                            f"User ID oracle, user ID {uid} confirmed "
                            f"to exist (differential error response)"
                        ),
                        severity="MEDIUM",
                        evidence=(
                            f"GET /wp/v2/users/{uid} -> "
                            f"'{code}' confirms user exists vs "
                            f"'rest_user_invalid_id' for non-existent users"
                        ),
                        url=(
                            f"{self.target.rstrip('/')}/"
                            f"wp-json/wp/v2/users/{uid}"
                        ),
                    )
                continue

            # If we get data back, that's user data exposed
            if isinstance(u_data, dict) and u_data.get("id"):
                self._saw_rest_user(u_data, f"API REST wp-json/wp/v2/users/{uid}")
                has_email = bool(u_data.get("email"))
                email = (mask_email(u_data["email"], self.target,
                                    usernames_masked(self.config))
                         if has_email else "")
                self._result.add_finding(
                    message=(
                        f"User ID {uid} data exposed via "
                        f"/wp/v2/users/{uid}"
                    ),
                    severity="CRITICAL" if has_email else "HIGH",
                    evidence=(
                        f"User: {self._user(u_data.get('name', 'unknown'))} "
                        f"(slug: {self._user(u_data.get('slug', ''))})"
                        + (f", email: {email}" if has_email else "")
                    ),
                    url=(
                        f"{self.target.rstrip('/')}/"
                        f"wp-json/wp/v2/users/{uid}"
                    ),
                )

    # ── 3) Posts/pages exposure ────────────────────────────────────────

    def _check_posts_pages_exposure(self) -> None:
        """Check posts and pages endpoints for sensitive data leaks."""
        # ── Posts ──
        posts_path = "wp-json/wp/v2/posts"
        posts_data = self._fetch_json_list(posts_path, per_page=100)
        if posts_data is None:
            return

        if isinstance(posts_data, dict) and "code" in posts_data:
            # Error, endpoint restricted
            return

        if not isinstance(posts_data, list):
            return

        self._result.add_finding(
            message=(
                f"Posts endpoint returns {len(posts_data)} posts publicly"
            ),
            severity="INFO",
            evidence=(
                f"GET /wp-json/wp/v2/posts -> "
                f"{len(posts_data)} posts accessible"
            ),
            url=f"{self.target.rstrip('/')}/{posts_path}",
        )

        # Check for password-protected posts
        protected = [
            p for p in posts_data
            if isinstance(p, dict)
            and p.get("content", {}).get("protected") is True
        ]
        if protected:
            protected_ids = [p.get("id") for p in protected if p.get("id")]
            protected_titles = [
                p.get("title", {}).get("rendered", "?")
                for p in protected
            ]
            self._result.add_finding(
                message=(
                    f"{len(protected)} password-protected posts detected "
                    f"- titles and slugs visible"
                ),
                severity="MEDIUM",
                evidence=(
                    f"Protected post IDs: {protected_ids}\n"
                    f"Titles: {protected_titles}"
                ),
                url=f"{self.target.rstrip('/')}/{posts_path}",
            )

        # Check for post revisions
        rev_data, rev_resp = self.get_json(
            "wp-json/wp/v2/posts/1/revisions?per_page=1"
        )
        if (rev_resp is not None and rev_resp.status_code == 200
                and isinstance(rev_data, list) and len(rev_data) > 0):
            self._result.add_finding(
                message=(
                    "Post revisions accessible without "
                    "authentication"
                ),
                severity="HIGH",
                evidence=(
                    f"GET /wp/v2/posts/1/revisions -> "
                    f"HTTP 200, {len(rev_data)} revision(s)"
                ),
                url=(
                    f"{self.target.rstrip('/')}/"
                    f"wp-json/wp/v2/posts/1/revisions"
                ),
            )

        # Check for draft/private posts via status parameter
        for status in ("draft", "private", "future"):
            s_data, s_resp = self.get_json(
                f"wp-json/wp/v2/posts?status={status}&per_page=1"
            )
            if s_resp is None or s_resp.status_code != 200:
                continue
            if not (isinstance(s_data, list) and len(s_data) > 0):
                continue
            severity = "CRITICAL" if status == "private" else "HIGH"
            self._result.add_finding(
                message=(
                    f"Posts with status='{status}' accessible "
                    f"without authentication"
                ),
                severity=severity,
                evidence=(
                    f"GET /wp/v2/posts?status={status} "
                    f"returned {len(s_data)} "
                    f"{status} post(s)"
                ),
                url=(
                    f"{self.target.rstrip('/')}/"
                    f"wp-json/wp/v2/posts?"
                    f"status={status}"
                ),
            )

        # ── Pages ──
        pages_path = "wp-json/wp/v2/pages"
        pages_data = self._fetch_json_list(pages_path, per_page=100)
        if pages_data is None:
            return

        if isinstance(pages_data, dict) and "code" in pages_data:
            return

        if isinstance(pages_data, list) and len(pages_data) > 0:
            self._result.add_finding(
                message=(
                    f"Pages endpoint returns {len(pages_data)} pages publicly"
                ),
                severity="INFO",
                evidence=(
                    f"GET /wp-json/wp/v2/pages -> "
                    f"{len(pages_data)} pages accessible"
                ),
                url=f"{self.target.rstrip('/')}/{pages_path}",
            )

    # ── 4) Media endpoint ──────────────────────────────────────────────

    def _check_media_endpoint(self) -> None:
        """Check media endpoint for private media leak and metadata."""
        media_path = "wp-json/wp/v2/media"
        media_data = self._fetch_json_list(media_path, per_page=20)
        if media_data is None:
            return

        if isinstance(media_data, dict) and "code" in media_data:
            return

        if not isinstance(media_data, list):
            return

        # Get total count from header
        total_media = str(len(media_data))
        try:
            head_resp = self.http_head(f"{media_path}?per_page=1")
            total_h = head_resp.headers.get("X-WP-Total", "")
            if total_h:
                total_media = total_h
        except Exception:
            pass

        evidence_parts = [
            f"Media items visible: {len(media_data)} "
            f"(total in library: {total_media})"
        ]

        # Check for EXIF metadata
        has_exif = False
        has_private_media = False
        for item in media_data:
            if not isinstance(item, dict):
                continue
            meta = item.get("meta", {})
            if meta and meta.get("exif"):
                has_exif = True
                evidence_parts.append(
                    f"EXIF metadata found on media ID {item.get('id')}: "
                    f"{str(meta['exif'])[:200]}"
                )
                break

            # Check for orphaned media (no parent post)
            if item.get("post") is None:
                has_private_media = True
                evidence_parts.append(
                    f"Orphaned media: ID {item.get('id')} "
                    f"({item.get('title', {}).get('rendered', '?')}) "
                    f"- no parent post"
                )

        # Check source URLs for full-size images
        source_urls = [
            item.get("source_url")
            for item in media_data
            if isinstance(item, dict) and item.get("source_url")
        ]
        if source_urls:
            evidence_parts.append(
                f"Full-size image URLs exposed: "
                f"{len(source_urls)} source URLs visible"
            )

        # Un média « orphelin » (post is None : logo, image d'en-tête, upload de
        # médiathèque) est parfaitement normal et n'est PAS une fuite. Seul un
        # EXIF réellement sensible justifie HIGH.
        severity = "HIGH" if has_exif else "LOW"
        self._result.add_finding(
            message=(
                f"Media endpoint exposes {len(media_data)} items "
                f"(total: {total_media})"
            ),
            severity=severity,
            evidence="\n".join(evidence_parts),
            url=f"{self.target.rstrip('/')}/{media_path}",
        )

    # ── 5) Custom plugin endpoints ─────────────────────────────────────

    def _check_custom_plugin_endpoints(self) -> None:
        """Identify unknown/risky namespaces from the registered routes."""
        wp_json = getattr(self, "_wp_json_data", None)
        if not wp_json:
            return

        namespaces: List[str] = wp_json.get("namespaces", [])
        routes = wp_json.get("routes", {})

        custom_ns = [
            ns for ns in namespaces
            if not ns.startswith(CORE_NAMESPACE_PREFIXES)
        ]

        if not custom_ns:
            return

        seen_patterns = set()
        for ns in custom_ns:
            # Namespace à historique de CVE connu ?
            risk_found = False
            for pattern, risk_desc in RISKY_NAMESPACE_PATTERNS.items():
                if pattern in ns.lower():
                    risk_found = True
                    # Dédup : un SEUL constat par plugin, pas un par sous-namespace
                    # (Elementor enregistre ~6 namespaces → 1 seul finding, pas 6).
                    if pattern in seen_patterns:
                        break
                    seen_patterns.add(pattern)
                    plugin_ns = [n for n in custom_ns if pattern in n.lower()]
                    # Surface/recon, PAS une vulnérabilité : la simple présence
                    # d'une API REST de plugin populaire n'est pas exploitable en
                    # soi ; les CVE réelles sont gérées par vulnerability_scan
                    # (version → CVE). Donc INFO/potential, pas MEDIUM.
                    self._result.add_finding(
                        message=(
                            f"Surface REST d'un plugin à historique de CVE : "
                            f"'{pattern}' ({len(plugin_ns)} namespace(s))"
                        ),
                        severity="INFO",
                        evidence=(
                            f"Historique : {risk_desc}\n"
                            f"Namespaces : {plugin_ns[:10]}\n"
                            f"La présence d'une surface REST n'est pas une "
                            f"vulnérabilité en soi : les CVE réelles sont évaluées "
                            f"par le check vulnerability_scan (version → CVE). À "
                            f"revoir si un endpoint expose des données sensibles "
                            f"(voir le contrôle d'accès REST)."
                        ),
                        url=f"{self.target.rstrip('/')}/wp-json/{ns}",
                        confidence="potential",
                    )
                    break

            if not risk_found:
                # Unknown namespace, flag it
                ns_routes = [
                    route for route in routes
                    if route.startswith(f"/{ns}")
                ]
                auth_status = self._test_route_auth(ns, ns_routes)

                # Only flag if it has actual routes and returns data
                if auth_status and "returns data" in auth_status.lower():
                    self._result.add_finding(
                        message=(
                            f"Namespace REST personnalisé détecté : '{ns}' "
                            f"(listing de routes public, normal en WordPress)"
                        ),
                        severity="INFO",
                        evidence=(
                            f"Routes: {ns_routes[:10]}\n"
                            f"Auth test: {auth_status}\n"
                            f"Note : la découverte de routes est publique ; vérifier "
                            f"manuellement si un endpoint expose des données sensibles."
                        ),
                        url=f"{self.target.rstrip('/')}/wp-json/{ns}",
                        confidence="potential",
                    )

    def _test_route_auth(
        self, ns: str, routes: List[str]
    ) -> str:
        """Test the first route of a namespace for unauthenticated access."""
        if not routes:
            return "no routes found"

        route = routes[0]
        try:
            resp = self.http_get(f"wp-json{route}")
            if resp.status_code in (200, 201, 203):
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        return (
                            f"HTTP {resp.status_code}, "
                            f"returns data ({len(data)} items)"
                        )
                    elif isinstance(data, dict) and "code" not in data:
                        return (
                            f"HTTP {resp.status_code}, "
                            f"returns data"
                        )
                except (ValueError, json.JSONDecodeError):
                    if len(resp.text) > 50:
                        return (
                            f"HTTP {resp.status_code}, "
                            f"returns {len(resp.text)} bytes"
                        )
            return f"HTTP {resp.status_code}"
        except Exception:
            return "request failed"

    # ── 6) Block directory (SSRF) ─────────────────────────────────────

    def _check_block_directory(self) -> None:
        """Check block-directory/search endpoint (potentially SSRF)."""
        path = "wp-json/wp/v2/block-directory/search?term=test"
        data, resp = self.get_json(path)
        if data is None:
            return

        if isinstance(data, dict) and "code" in data:
            return

        self._result.add_finding(
            message=(
                "Block directory search endpoint accessible "
                "(natif, destination fixe api.wordpress.org, pas un SSRF exploitable)"
            ),
            severity="INFO",
            evidence=(
                f"GET /wp/v2/block-directory/search?term=test -> "
                f"HTTP {resp.status_code}, "
                f"type: {type(data).__name__}"
            ),
            url=f"{self.target.rstrip('/')}/{path}",
            confidence="potential",
        )

    # ── 7) Pattern directory (SSRF) ────────────────────────────────────

    def _check_pattern_directory(self) -> None:
        """Check pattern-directory/patterns endpoint (potentially SSRF)."""
        path = "wp-json/wp/v2/pattern-directory/patterns?per_page=1"
        data, resp = self.get_json(path)
        if data is None:
            return

        if isinstance(data, dict) and "code" in data:
            return

        self._result.add_finding(
            message=(
                "Pattern directory endpoint accessible "
                "(natif, destination fixe api.wordpress.org, pas un SSRF exploitable)"
            ),
            severity="INFO",
            evidence=(
                f"GET /wp/v2/pattern-directory/patterns -> "
                f"HTTP {resp.status_code}, "
                f"type: {type(data).__name__}"
            ),
            url=f"{self.target.rstrip('/')}/{path}",
            confidence="potential",
        )

    # ── 8) Application passwords ──────────────────────────────────────

    def _check_application_passwords(self) -> None:
        """Check application-passwords endpoint for exposure."""
        path = "wp-json/wp/v2/users/1/application-passwords"
        data, resp = self.get_json(path)
        if data is None:
            return

        # Exposition RÉELLE : 200 + liste de mots de passe applicatifs.
        if resp.status_code == 200 and isinstance(data, list):
            self._result.add_finding(
                message=(
                    "Application passwords endpoint returned data "
                    "without authentication"
                ),
                severity="CRITICAL",
                evidence=f"HTTP {resp.status_code}\nResponse: {resp.text[:300]}",
                url=f"{self.target.rstrip('/')}/{path}",
            )
            return

        if not isinstance(data, dict):
            return

        code = data.get("code", "")
        message = data.get("message", "")

        if code == "rest_no_route":
            # Endpoint does not exist, Application Passwords probably disabled
            pass
        elif code in ("rest_user_cannot_view", "rest_cannot_view"):
            self._result.add_finding(
                message=(
                    "Application passwords endpoint exists "
                    "but requires authentication"
                ),
                severity="LOW",
                evidence=(
                    f"Error: {code}, {message}"
                ),
                url=f"{self.target.rstrip('/')}/{path}",
            )
        elif code == "rest_user_invalid_id":
            # Different error for invalid user, oracle
            # Check if user 1 exists by trying application-passwords
            # This by itself is an oracle
            self._result.add_finding(
                message=(
                    "Application passwords endpoint confirms "
                    "user ID oracle (differential error response)"
                ),
                severity="MEDIUM",
                evidence=(
                    f"User 1: '{code}' (invalid ID) vs "
                    f"'rest_user_cannot_view' for valid users"
                ),
                url=f"{self.target.rstrip('/')}/{path}",
            )
        else:
            # Tout autre WP_Error (rest_forbidden, rest_not_logged_in, …) =
            # endpoint présent mais PROTÉGÉ. Ce n'est pas une exposition.
            self._result.add_finding(
                message=(
                    "Application passwords endpoint present but protected "
                    f"(WP_Error: {code or 'unknown'})"
                ),
                severity="INFO",
                evidence=(
                    f"HTTP {resp.status_code}, code: {code}\n{message}"[:300]
                ),
                url=f"{self.target.rstrip('/')}/{path}",
                confidence="potential",
            )

    # ── 9) CORS test ───────────────────────────────────────────────────

    def _check_cors(self) -> None:
        """Check CORS headers for misconfiguration."""
        test_path = "wp-json/wp/v2/posts"
        base_url = f"{self.target.rstrip('/')}/{test_path.lstrip('/')}"

        try:
            # Baseline (no Origin header)
            base_resp = self.http_get(test_path)
            base_origin = base_resp.headers.get("Access-Control-Allow-Origin", "")
            base_cred = base_resp.headers.get(
                "Access-Control-Allow-Credentials", ""
            )

            # Test with arbitrary Origin
            evil_resp = self.http_get(
                test_path, headers={"Origin": "https://evil.com"},
            )
            evil_origin = evil_resp.headers.get("Access-Control-Allow-Origin", "")
            evil_cred = evil_resp.headers.get(
                "Access-Control-Allow-Credentials", ""
            )

            # Test with null origin
            null_resp = self.http_get(test_path, headers={"Origin": "null"})
            null_origin = null_resp.headers.get("Access-Control-Allow-Origin", "")
            null_cred = null_resp.headers.get(
                "Access-Control-Allow-Credentials", ""
            )
        except Exception:
            return

        # ── Check wildcard CORS ──
        if base_origin == "*":
            self._result.add_finding(
                message=(
                    "Wildcard CORS: Access-Control-Allow-Origin: *"
                ),
                severity="HIGH",
                evidence=(
                    "Any website can read REST API responses via JavaScript.\n"
                    f"Access-Control-Allow-Origin: {base_origin}\n"
                    f"Access-Control-Allow-Credentials: {base_cred}"
                ),
                url=base_url,
            )

        # ── Check reflective CORS ──
        if "evil.com" in evil_origin:
            severity = "CRITICAL" if evil_cred == "true" else "HIGH"
            self._result.add_finding(
                message=(
                    "Reflective CORS detected, Origin header "
                    "is echoed back in Access-Control-Allow-Origin"
                ),
                severity=severity,
                evidence=(
                    f"Origin: https://evil.com -> "
                    f"Access-Control-Allow-Origin: {evil_origin}\n"
                    f"Access-Control-Allow-Credentials: {evil_cred}\n"
                    + (
                        "⚠️ With credentials allowed, an attacker "
                        "can exfiltrate authenticated API data"
                        if evil_cred == "true"
                        else ""
                    )
                ),
                url=base_url,
            )

        # ── Check null origin ──
        if null_origin == "null" or "null" in null_origin:
            self._result.add_finding(
                message=(
                    "Null Origin accepted in CORS "
                    "(Access-Control-Allow-Origin: null)"
                ),
                severity="HIGH",
                evidence=(
                    "Sandboxed iframes can make cross-origin requests.\n"
                    f"Access-Control-Allow-Origin: {null_origin}\n"
                    f"Access-Control-Allow-Credentials: {null_cred}"
                ),
                url=base_url,
            )

        # ── Check bypass d'allowlist via origin dérivé du domaine cible ──
        # Ne se déclenche que si l'Origin arbitraire (evil.com) n'était PAS déjà
        # reflété : sinon c'est de la réflexion totale, déjà signalée plus haut.
        # Cible les allowlists au match trop laxiste (substring/préfixe/suffixe).
        if "evil.com" not in evil_origin:
            td = self.target.split("://")[-1].split("/")[0].split(":")[0]
            bypass_origins = [
                (f"https://{td}.evil.com",
                 "préfixe, origin attaquant commençant par le domaine cible"),
                (f"https://evil-{td}",
                 "suffixe, origin attaquant finissant par le domaine cible"),
            ]
            for origin, kind in bypass_origins:
                try:
                    r = self.http_get(test_path, headers={"Origin": origin})
                except Exception:
                    continue
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if origin in acao:
                    sev = "CRITICAL" if acac == "true" else "HIGH"
                    self._result.add_finding(
                        message=(
                            "Bypass d'allowlist CORS, origin dérivé du domaine "
                            f"cible reflété ({kind.split(', ')[0]})"
                        ),
                        severity=sev,
                        evidence=(
                            f"Origin: {origin} -> Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}\n"
                            f"Type de faille : {kind}. La validation d'origine du "
                            "serveur accepte un domaine attaquant contenant le "
                            "domaine cible (match trop permissif)."
                            + (" Avec credentials, exfiltration de données "
                               "authentifiées possible." if acac == "true" else "")
                        ),
                        url=base_url,
                        confidence="potential",
                    )

        # ── Check credentials with CORS ──
        if base_cred == "true" and base_origin and base_origin != "*":
            self._result.add_finding(
                message=(
                    "CORS with credentials allowed "
                    f"(Origin: {base_origin})"
                ),
                severity="MEDIUM",
                evidence=(
                    "Access-Control-Allow-Credentials: true, "
                    "authenticated requests may be exfiltrated "
                    "if combined with permissive origin"
                ),
                url=base_url,
            )

    # ── 10) REST API disabled check (?rest_route=) ─────────────────────

    def _check_rest_disabled_bypass(self) -> None:
        """Check if REST API is accessible via ?rest_route= bypass.

        Ce n'est un « bypass » que si /wp-json/ est RÉELLEMENT bloqué. Si la voie
        standard fonctionne déjà, ?rest_route= n'est que le mécanisme de secours
        natif de WordPress (permaliens absents), pas une faille.
        """
        direct_data, direct_resp = self.get_json(
            "wp-json/wp/v2/posts?per_page=1", bail_404=False
        )
        direct_ok = (direct_resp is not None and direct_resp.status_code == 200
                     and isinstance(direct_data, (list, dict)))
        if direct_ok:
            return  # /wp-json/ fonctionne : pas de bypass, comportement normal.

        bypass_path = "/?rest_route=/wp/v2/posts&per_page=1"
        data, resp = self.get_json(bypass_path, bail_404=False)
        if resp is None:
            return

        is_json = isinstance(data, (list, dict))

        if is_json:
            self._result.add_finding(
                message=(
                    "REST API accessible via ?rest_route= bypass, "
                    "parameter-based access works even if /wp-json/ "
                    "is blocked"
                ),
                severity="HIGH",
                evidence=(
                    f"GET /?rest_route=/wp/v2/posts -> "
                    f"HTTP {resp.status_code}, JSON returned"
                ),
                url=f"{self.target.rstrip('/')}/?rest_route=/wp/v2/posts",
            )

        # Try with Accept: application/json header
        data2, json_resp = self.get_json(
            bypass_path, bail_404=False, headers={"Accept": "application/json"}
        )
        if json_resp is not None:
            is_json2 = isinstance(data2, (list, dict))

            if is_json2 and not is_json:
                self._result.add_finding(
                    message=(
                        "REST API bypass works with "
                        "Accept: application/json + ?rest_route="
                    ),
                    severity="HIGH",
                    evidence=(
                        f"GET /?rest_route=/wp/v2/posts + "
                        f"Accept: application/json -> "
                        f"HTTP {json_resp.status_code}, JSON returned"
                    ),
                    url=(
                        f"{self.target.rstrip('/')}/"
                        f"?rest_route=/wp/v2/posts"
                    ),
                )

    # ── 11) OEmbed SSRF ────────────────────────────────────────────────

    def _check_oembed_ssrf(self) -> None:
        """Signale la surface oEmbed d'après l'index REST, sans jamais appeler
        les routes oEmbed avec une URL (aucune récupération déclenchée).

        /oembed/1.0/proxy récupère des URL distantes pour un utilisateur
        authentifié (edit_posts) : c'est une surface SSRF, mais son
        exploitabilité exige de lui soumettre une URL, ce que le scanner ne
        fait pas (non évaluable passivement).
        """
        data, index_url = self.rest_index()
        routes = data.get("routes") if isinstance(data, dict) else None
        if not isinstance(routes, dict):
            return
        present = [r for r in ("/oembed/1.0/embed", "/oembed/1.0/proxy")
                   if r in routes]
        if not present:
            return
        self._result.add_finding(
            message=(
                "Routes oEmbed présentes dans l'index REST (surface SSRF via "
                "/oembed/1.0/proxy, non évaluable passivement)"
            ),
            severity="INFO",
            evidence=(
                f"Index REST : {index_url}\n"
                f"Routes : {', '.join(present)}\n"
                "Aucune URL n'a été soumise aux routes oEmbed : leur capacité à "
                "récupérer une ressource interne n'est pas testée (lecture seule)."
            ),
            url=f"{self.target.rstrip('/')}/wp-json/oembed/1.0/proxy"
            if "/oembed/1.0/proxy" in present
            else f"{self.target.rstrip('/')}/wp-json/oembed/1.0/embed",
            confidence="potential",
        )

    # ── 12) Search endpoint data leakage ──────────────────────────────

    def _check_search_data_leakage(self) -> None:
        """Check search endpoint for data leakage."""
        search_path = "wp-json/wp/v2/search?search=test&per_page=5"
        data, resp = self.get_json(search_path)
        if data is None:
            return

        if isinstance(data, dict) and "code" in data:
            return

        if not isinstance(data, list):
            return

        self._result.add_finding(
            message=(
                f"Search endpoint accessible, "
                f"{len(data)} results for 'test'"
            ),
            severity="INFO",
            evidence=(
                f"GET /wp/v2/search?search=test -> "
                f"HTTP {resp.status_code}, "
                f"{len(data)} results"
            ),
            url=f"{self.target.rstrip('/')}/{search_path}",
        )

    # ── 13) Site health ────────────────────────────────────────────────

    def _check_site_health(self) -> None:
        """Check wp-site-health/v1 endpoint for information disclosure.

        Seule la racine du namespace est lue : les points de test
        (tests/background-updates, tests/loopback-requests,
        tests/https-status) exécutent chacun un diagnostic côté serveur et ne
        sont jamais appelés (constat INFO du check wp_features)."""
        paths = [
            "wp-json/wp-site-health/v1",
        ]

        for path in paths:
            data, resp = self.get_json(path)
            if resp is None:
                continue
            if resp.status_code in (401, 403):
                continue
            if data is None:
                continue

            if isinstance(data, dict) and "code" in data:
                continue

            severity = "HIGH"
            # Extract evidence based on response content
            evidence_parts = [
                f"GET {path} -> HTTP {resp.status_code}"
            ]

            if isinstance(data, dict):
                # Check for test results
                if "test" in data:
                    evidence_parts.append(
                        f"Test: {data.get('test', 'unknown')}"
                    )
                    evidence_parts.append(
                        f"Status: {data.get('status', 'unknown')}"
                    )
                    if "message" in data.get("actions", {}):
                        evidence_parts.append(
                            f"Details: {data['actions']['message'][:200]}"
                        )
                    severity = "HIGH"
                elif "tests" in data:
                    # This is a test result object
                    tests = data.get("tests", {})
                    evidence_parts.append(
                        f"Tests returned: {list(tests.keys())[:5]}"
                    )
                else:
                    # General info disclosure
                    keys = list(data.keys())[:10]
                    evidence_parts.append(f"Keys: {keys}")
                    severity = "MEDIUM"

            self._result.add_finding(
                message=(
                    f"Site health endpoint accessible at {path} "
                    f"- potential information disclosure"
                ),
                severity=severity,
                evidence="\n".join(evidence_parts),
                url=f"{self.target.rstrip('/')}/{path}",
            )

    # ── 14) JSONP callback XSS ─────────────────────────────────────────

    def _check_jsonp_callback(self) -> None:
        """Check for JSONP callback XSS via _jsonp and callback params."""
        test_path = "wp-json/wp/v2/posts"

        for param in JSONP_PARAMS:
            try:
                resp = self.http_get(
                    f"{test_path}?{param}=testCallback"
                )
            except Exception:
                continue

            body = resp.text

            if body.startswith("testCallback("):
                self._result.add_finding(
                    message=(
                        f"JSONP callback reflection via '{param}' "
                        f"parameter, XSS vector"
                    ),
                    severity="CRITICAL",
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Response starts with: "
                        f"testCallback({{...}})\n"
                        f"Try: ?{param}=<script>alert(1)</script>"
                    ),
                    url=(
                        f"{self.target.rstrip('/')}/"
                        f"{test_path}?{param}=testCallback"
                    ),
                )
            elif body.startswith("/**/") and "testCallback" in body:
                # Le préfixe /**/ EST la protection anti-XSSI native de WordPress :
                # le callback n'est pas exécutable comme du JS. Ce n'est donc PAS
                # une vulnérabilité → INFO (observation), pas LOW.
                self._result.add_finding(
                    message=(
                        f"JSONP via '{param}' protégé par préfixe /**/ "
                        f"(anti-XSSI natif, non exploitable)"
                    ),
                    severity="INFO",
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Response has /**/ prefix wrapper (protection native)"
                    ),
                    url=(
                        f"{self.target.rstrip('/')}/"
                        f"{test_path}?{param}=testCallback"
                    ),
                )
            elif "testCallback" in body:
                self._result.add_finding(
                    message=(
                        f"JSONP callback '{param}' recognized "
                        f"but sanitized"
                    ),
                    severity="INFO",
                    evidence=(
                        f"Parameter '{param}' is processed "
                        f"but sanitized"
                    ),
                    url=(
                        f"{self.target.rstrip('/')}/"
                        f"{test_path}?{param}=testCallback"
                    ),
                )

    # ── 15) Broken Access Control, endpoints exposant des données ────

    def _check_bac_endpoints(self) -> None:
        """Sonde des endpoints REST tiers susceptibles d'exposer des données
        sans authentification (permission_callback manquant).

        Broken Access Control est le vecteur d'attaque réel n°1 (≈57 % du
        référentiel 2025-2026), souvent dû à du code « vibe-codé » par IA qui
        oublie le `permission_callback` sur un endpoint renvoyant des données
        sensibles. On combine :
          1) une liste CURÉE d'endpoints tiers plausibles (heuristique) ;
          2) l'analyse dynamique des `routes` de /wp-json/ dont le nom matche
             un motif sensible.
        Le nombre total de requêtes est borné à BAC_MAX_REQUESTS.
        """
        seen: set = set()
        budget = BAC_MAX_REQUESTS

        # ── 1) Liste curée d'endpoints tiers ──
        for path in BAC_ENDPOINTS:
            if budget <= 0:
                return
            if path in seen:
                continue
            seen.add(path)
            budget -= 1
            self._probe_bac_endpoint(path)

        # ── 2) Analyse dynamique des routes de /wp-json/ (racine) ──
        wp_json = getattr(self, "_wp_json_data", None)
        if not isinstance(wp_json, dict):
            return
        routes = wp_json.get("routes", {})
        if not isinstance(routes, dict):
            return

        for route in routes:
            if budget <= 0:
                return
            if not isinstance(route, str) or not route:
                continue
            # Ignore les namespaces core (déjà couverts par d'autres checks).
            ns = route.lstrip("/")
            if ns.startswith(CORE_NAMESPACE_PREFIXES):
                continue
            if not BAC_SENSITIVE_ROUTE.search(route):
                continue
            # Ignore les routes paramétrées (ex. .../(?P<id>...)) : non sondables
            # à l'aveugle sans valeur.
            if "(?P<" in route or "(?" in route:
                continue
            path = "wp-json" + route
            if path in seen:
                continue
            seen.add(path)
            budget -= 1
            self._probe_bac_endpoint(path)

    def _probe_bac_endpoint(self, path: str) -> None:
        """GET un endpoint et flag si 200 + données sans champ `code`."""
        data, resp = self.get_json(path)

        if resp is None:
            return

        # 404 / non trouvé, ou témoin « ressource absente » → sain.
        if resp.status_code == 404:
            return
        try:
            if self._is_soft404(resp):
                return
        except Exception:
            pass

        if data is None:
            return

        # WP_Error (endpoint protégé) → réponse SAINE, ne PAS flagger.
        if isinstance(data, dict) and "code" in data:
            return
        # Auth explicitement refusée → sain.
        if resp.status_code in (401, 403):
            return

        # Fuite probable : 200 + liste non vide OU dict de données sans `code`.
        is_nonempty_list = isinstance(data, list) and len(data) > 0
        is_data_dict = isinstance(data, dict) and len(data) > 0
        if resp.status_code == 200 and (is_nonempty_list or is_data_dict):
            snippet = resp.text[:300].strip()
            self._result.add_finding(
                message=(
                    "Endpoint REST expose des données sans authentification "
                    "(permission_callback probablement manquant) : "
                    f"{path}"
                ),
                severity="HIGH",
                evidence=(
                    f"GET /{path.lstrip('/')} -> HTTP {resp.status_code}\n"
                    f"Type: {type(data).__name__}"
                    + (f" ({len(data)} éléments)" if is_nonempty_list else "")
                    + f"\nExtrait: {snippet}"
                ),
                url=f"{self.target.rstrip('/')}/{path.lstrip('/')}",
                confidence="potential",
            )

    # ── Internal helpers ───────────────────────────────────────────────

    def _fetch_json_list(
        self, path: str, per_page: int = 100
    ) -> Optional[Any]:
        """Fetch a JSON endpoint and return parsed data.

        Returns None if the request fails, the response is 401/403/404, or
        the body is not JSON.
        """
        data, resp = self.get_json(f"{path}?per_page={per_page}")
        if resp is not None and resp.status_code in (401, 403):
            return None
        return data
