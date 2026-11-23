"""Check for WordPress Multisite detection and security issues.

Inherits from BaseCheck. Covers:
  1) Multisite detection via multiple signals (wp-signup.php, REST API,
     cookies, wp-sites.php, HTML patterns)
  2) If NOT multisite: single INFO finding, skip all other checks
  3) If multisite: network-wide user enumeration via REST API
  4) Cross-site contamination risk (shared DB = CRITICAL)
  5) Signup option enabled (anyone can create a site - HIGH)
  6) New site verification disabled (instant site creation - HIGH)
  7) Upload space check (unlimited = disk exhaustion - MEDIUM)
  8) Network admin URL exposure (/wp-admin/network/ - HIGH)
  9) Super admin detection (ID 1 is super admin - HIGH)
  10) Site archiving/suspended sites exposure (MEDIUM)

Flagged CRITICAL:
  - Open registration without verification (signup + no verification)

Flagged HIGH:
  - User enumeration
  - Network admin exposure
  - Super admin targeting
"""

import json
import re
from typing import Dict, List, Optional, Tuple

import requests

from ..redact import is_risky_username, mask_email, mask_username, usernames_masked
from .base import BaseCheck, CheckResult


class MultisiteCheck(BaseCheck):
    """Check WordPress Multisite detection and security issues."""

    name = "multisite"
    title = "WordPress Multisite Security Audit"
    description = (
        "Detects if the site is a WordPress Multisite network and, if so, "
        "checks for multisite-specific vulnerabilities including user "
        "enumeration, cross-site contamination, signup settings, upload "
        "limits, network admin exposure, super admin targeting, and "
        "archived site exposure."
    )
    severity = "INFO"
    access_tier = 1  # mixte : wp-sites.php, éditeurs et wp-admin/network/ sous --authorized
    depends_on: List[str] = []

    # ── Scoring thresholds ──────────────────────────────────────────────
    _MULTISITE_THRESHOLD = 2  # Minimum signals to confirm multisite

    # ── HTML patterns that suggest multisite ────────────────────────────
    _MS_HTML_PATTERNS: List[str] = [
        r"wpmu",
        r"ms-files",
        r"network/sites",
        r"/sites/\d+",
        r"site_id[\"'\s]*:",
        r"wp-admin/network/",
        r"get_site_url\(\)",
    ]

    # ── Signup page indicators ──────────────────────────────────────────
    _SIGNUP_ENABLED_PATTERNS: List[str] = [
        r"(?i)(create a new site|register a new site|get your own\s)",
        r"(?i)(signup|registration)\s*(form|page)",
    ]

    _SIGNUP_DISABLED_PATTERNS: List[str] = [
        r"(?i)registration has been disabled",
        r"(?i)registrations? are (not |dis)allowed",
    ]

    # ── Verification / activation indicators ────────────────────────────
    _VERIFICATION_PATTERNS: List[str] = [
        r"(?i)(email|verify|confirm|activate)",
    ]

    # ── Network admin indicators ────────────────────────────────────────
    _NETWORK_ADMIN_PATTERNS: List[str] = [
        r"(?i)(network admin|super admin|manage sites|manage network)",
    ]

    # ── Public API ──────────────────────────────────────────────────────

    def _user(self, name) -> str:
        """Nom d'utilisateur masqué dans les preuves (RGPD), sauf nom à risque."""
        return mask_username(name, self.target, usernames_masked(self.config))

    def run(self) -> CheckResult:
        """Execute the multisite security audit."""
        # Phase 1: Detection
        is_multisite, detection_evidence = self._detect_multisite()
        if not self.config.get("authorized"):
            self.note_unlinked_skipped(
                "wp-sites.php, éditeurs de fichiers (plugin-editor.php, "
                "theme-editor.php) et wp-admin/network/")

        if not is_multisite:
            self._result.add_finding(
                message="Site is not a WordPress Multisite",
                severity="INFO",
                evidence=(
                    "None of the multisite detection signals returned "
                    "a positive match. See detection details:\n"
                    f"{detection_evidence}"
                ),
            )
            return self._result

        # Record detection as info finding
        self._result.add_finding(
            message="WordPress Multisite network detected",
            severity="INFO",
            evidence=detection_evidence,
        )

        # Phase 2: Multisite-specific vulnerability checks
        self._check_user_enumeration()
        self._check_cross_site_contamination()
        self._check_signup_option()
        self._check_site_verification()
        self._check_upload_space()
        self._check_network_admin_exposure()
        self._check_super_admin()
        self._check_archived_sites()

        return self._result

    # ── Phase 1: Multisite detection ────────────────────────────────────

    def _detect_multisite(self) -> Tuple[bool, str]:
        """Detect if the target is a WordPress Multisite network.

        Uses multiple signals and aggregates them into a confidence score.
        Returns (is_multisite, evidence_string).
        """
        signals: Dict[str, bool] = {}
        evidence_lines: List[str] = []
        signal_count = 0

        # 1.1, Check wp-signup.php
        self._check_signup_endpoint(signals, evidence_lines)

        # 1.2, Check REST API /wp/v2/sites endpoint
        self._check_sites_endpoint(signals, evidence_lines)

        # 1.3, Check response headers for multisite REST cookies
        self._check_multisite_cookies(signals, evidence_lines)

        # 1.4 : wp-sites.php (legacy), chemin deviné : --authorized
        if self.config.get("authorized"):
            self._check_wp_sites_php(signals, evidence_lines)

        # 1.5, Check HTML for multisite patterns
        self._check_html_patterns(signals, evidence_lines)

        # Count positive signals
        signal_count = sum(1 for v in signals.values() if v)

        evidence_lines.insert(
            0,
            f"Multisite detection: {signal_count}/5 signals positive "
            f"(threshold: {self._MULTISITE_THRESHOLD})",
        )
        evidence = "\n".join(evidence_lines)

        return signal_count >= self._MULTISITE_THRESHOLD, evidence

    def _check_signup_endpoint(
        self, signals: Dict[str, bool], evidence: List[str]
    ) -> None:
        """Check /wp-signup.php, multisite-only file."""
        resp = self._safe_get("wp-signup.php")
        if resp is None:
            signals["wp-signup.php"] = False
            evidence.append("  wp-signup.php: [NO] Connection error")
            return

        status = resp.status_code
        body_lower = resp.text.lower()

        if status == 200:
            # Check if it's actually a signup page vs a generic 200
            if "registration" in body_lower or "signup" in body_lower:
                signals["wp-signup.php"] = True
                evidence.append(
                    f"  wp-signup.php: [YES] HTTP {status}, "
                    "signup/registration content detected"
                )
            else:
                signals["wp-signup.php"] = True
                evidence.append(
                    f"  wp-signup.php: [YES] HTTP {status}, "
                    "file exists (multisite-only)"
                )
        elif status in (301, 302, 307, 308):
            signals["wp-signup.php"] = False
            location = resp.headers.get("Location", "")
            evidence.append(
                f"  wp-signup.php: [NO] HTTP {status} redirect → {location}"
            )
        else:
            signals["wp-signup.php"] = False
            evidence.append(
                f"  wp-signup.php: [NO] HTTP {status}, likely single-site"
            )

    def _check_sites_endpoint(
        self, signals: Dict[str, bool], evidence: List[str]
    ) -> None:
        """Check /wp-json/wp/v2/sites, multisite-only REST endpoint."""
        resp = self._safe_get("wp-json/wp/v2/sites")
        if resp is None:
            signals["wp/v2/sites"] = False
            evidence.append("  REST /wp/v2/sites: [NO] Connection error")
            return

        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "")

        if status == 200:
            # Try parsing JSON to see if we get site data
            try:
                data = resp.json()
                if isinstance(data, list):
                    site_count = len(data)
                    signals["wp/v2/sites"] = True
                    evidence.append(
                        f"  REST /wp/v2/sites: [YES] HTTP {status}, "
                        f"{site_count} sites returned (multisite-only endpoint)"
                    )
                elif isinstance(data, dict):
                    signals["wp/v2/sites"] = True
                    evidence.append(
                        f"  REST /wp/v2/sites: [YES] HTTP {status}, "
                        "responds with JSON object"
                    )
                else:
                    signals["wp/v2/sites"] = False
                    evidence.append(
                        f"  REST /wp/v2/sites: [?] HTTP {status}, "
                        "unexpected response type"
                    )
            except (ValueError, json.JSONDecodeError):
                # Non-JSON response but 200, might still be multisite
                signals["wp/v2/sites"] = True
                evidence.append(
                    f"  REST /wp/v2/sites: [YES] HTTP {status}, "
                    "non-JSON but endpoint exists"
                )
        elif status in (401, 403):
            # Endpoint exists but requires auth, could be multisite
            signals["wp/v2/sites"] = True
            evidence.append(
                f"  REST /wp/v2/sites: [POSSIBLE] HTTP {status}, "
                "endpoint exists (requires auth)"
            )
        else:
            # Check X-WP-Total and X-WP-TotalPages headers
            total = resp.headers.get("X-WP-Total", "")
            total_pages = resp.headers.get("X-WP-TotalPages", "")
            if total or total_pages:
                signals["wp/v2/sites"] = True
                evidence.append(
                    f"  REST /wp/v2/sites: [YES] HTTP {status}, "
                    f"X-WP-Total={total}, X-WP-TotalPages={total_pages}"
                )
            else:
                signals["wp/v2/sites"] = False
                evidence.append(
                    f"  REST /wp/v2/sites: [NO] HTTP {status}"
                )

    def _check_multisite_cookies(
        self, signals: Dict[str, bool], evidence: List[str]
    ) -> None:
        """Check Set-Cookie headers for multisite patterns."""
        resp = self._safe_get("wp-login.php")
        if resp is None:
            signals["cookies"] = False
            evidence.append("  MS Cookies: [NO] Cannot access wp-login.php")
            return

        cookie_values = []

        # Collect all Set-Cookie values (CaseInsensitiveDict may have
        # multiple values under the same key)
        for key, value in resp.headers.items():
            if key.lower() == "set-cookie":
                cookie_values.append(value)

        if not cookie_values:
            signals["cookies"] = False
            evidence.append("  MS Cookies: [NO] No Set-Cookie headers")
            return

        # Multisite-specific indicators:
        # - Multiple distinct wordpress_logged_in_* hashes
        # - wp-settings-* and wp-settings-time-* cookies present
        logged_in_cookies = [
            c for c in cookie_values
            if "wordpress_logged_in_" in c
        ]
        settings_cookies = [
            c for c in cookie_values
            if "wp-settings" in c
        ]
        network_cookies = [
            c for c in cookie_values
            if "wordpress_" in c and "test_cookie" not in c
        ]

        # Multisite typically sets wp-settings-time-{user_id}
        # for users on the network
        settings_time_pattern = r"wp-settings-time-\d+"
        settings_time_matches = sum(
            1 for c in cookie_values if re.search(settings_time_pattern, c)
        )

        # Strong signal: multiple distinct logged-in cookie scopes
        if len(logged_in_cookies) > 1:
            signals["cookies"] = True
            evidence.append(
                f"  MS Cookies: [YES] {len(logged_in_cookies)} "
                "wordpress_logged_in_* cookie variants "
                "(multisite network-wide session cookies)"
            )
        elif settings_time_matches > 0 and len(settings_cookies) > 1:
            signals["cookies"] = True
            evidence.append(
                f"  MS Cookies: [YES] {len(settings_cookies)} wp-settings* "
                "cookies with settings-time (multisite pattern)"
            )
        elif len(network_cookies) >= 2:
            signals["cookies"] = False
            evidence.append(
                f"  MS Cookies: [POSSIBLE] {len(network_cookies)} "
                "WordPress cookies present, insufficient for confirmation"
            )
        else:
            signals["cookies"] = False
            evidence.append(
                f"  MS Cookies: [NO] Standard single-site cookie pattern "
                f"({len(network_cookies)} WP cookies)"
            )

    def _check_wp_sites_php(
        self, signals: Dict[str, bool], evidence: List[str]
    ) -> None:
        """Check /wp-sites.php, legacy WPMU file."""
        resp = self._safe_get("wp-sites.php")
        if resp is None:
            signals["wp-sites.php"] = False
            evidence.append("  wp-sites.php: [NO] Connection error")
            return

        status = resp.status_code
        if status == 200:
            signals["wp-sites.php"] = True
            evidence.append(
                f"  wp-sites.php: [YES] HTTP {status}, "
                "legacy WPMU file accessible (multisite indicator)"
            )
        elif status in (401, 403):
            signals["wp-sites.php"] = True
            evidence.append(
                f"  wp-sites.php: [POSSIBLE] HTTP {status}, "
                "file exists but access restricted"
            )
        else:
            signals["wp-sites.php"] = False
            evidence.append(
                f"  wp-sites.php: [NO] HTTP {status}, not found or removed"
            )

    def _check_html_patterns(
        self, signals: Dict[str, bool], evidence: List[str]
    ) -> None:
        """Check homepage HTML for multisite patterns."""
        resp = self._safe_get("")
        if resp is None:
            signals["html_patterns"] = False
            evidence.append("  HTML Patterns: [NO] Cannot fetch homepage")
            return

        body = resp.text
        matches = []

        for pattern in self._MS_HTML_PATTERNS:
            found = re.findall(pattern, body, re.IGNORECASE)
            if found:
                matches.extend(found[:3])  # Cap at 3 per pattern

        if len(matches) >= 2:
            signals["html_patterns"] = True
            unique_matches = list(set(matches))
            evidence.append(
                f"  HTML Patterns: [YES] {len(unique_matches)} "
                f"multisite pattern(s) found: {unique_matches[:5]}"
            )
        elif len(matches) == 1:
            signals["html_patterns"] = False
            evidence.append(
                f"  HTML Patterns: [WEAK] 1 pattern found: {matches[0]}"
            )
        else:
            signals["html_patterns"] = False
            evidence.append(
                "  HTML Patterns: [NO] No multisite patterns in HTML"
            )

    # ── Phase 2: Multisite vulnerability checks ──────────────────────────

    # ── 3) Network-wide user enumeration ─────────────────────────────────

    def _check_user_enumeration(self) -> None:
        """Check if REST API enumerates all network users (multisite)."""
        url_path = "wp-json/wp/v2/users"
        resp = self._safe_get(url_path)
        if resp is None:
            return

        if resp.status_code == 404:
            # Try without auth, endpoint may be disabled
            return

        try:
            users = resp.json()
        except (ValueError, json.JSONDecodeError):
            return

        # Check for error response
        if isinstance(users, dict) and "code" in users:
            code = users.get("code", "")
            if code == "rest_user_cannot_view":
                self._result.add_finding(
                    message=(
                        "Users endpoint restricted, network-wide "
                        "user enumeration prevented"
                    ),
                    severity="INFO",
                    evidence=(
                        f"REST API error: {users.get('message', '')}\n"
                        "User enumeration is blocked at the API level"
                    ),
                    url=f"{self.target.rstrip('/')}/{url_path}",
                )
            return

        if isinstance(users, list) and len(users) > 0:
            user_ids = [u.get("id") for u in users if u.get("id")]
            user_slugs = [u.get("slug") for u in users if u.get("slug")]
            has_email = any(
                u.get("email") for u in users if isinstance(u, dict)
            )

            # Get total from header for network-wide count
            total_users = len(users)
            try:
                head_resp = self._safe_head(f"{url_path}?per_page=1")
                if head_resp:
                    total_h = head_resp.headers.get("X-WP-Total", "")
                    if total_h and total_h.isdigit():
                        total_users = int(total_h)
            except Exception:
                pass

            evidence_parts = [
                f"Users exposed: {len(users)} returned "
                f"(X-WP-Total: {total_users})",
                f"User IDs: {user_ids[:20]}",
                f"User slugs: {[self._user(s) for s in user_slugs[:20]]}",
            ]
            risky = sorted({s for s in user_slugs if is_risky_username(s, self.target)})
            if risky:
                evidence_parts.append(
                    f"Noms à risque exposés : {risky} (supprimer ou renommer ces comptes)")
            if has_email:
                evidence_parts.append(
                    "EMAIL ADDRESSES EXPOSED, critical data leak"
                )

            # Check for super admin indicators (user ID 1 appearing)
            if 1 in user_ids:
                evidence_parts.append(
                    "Super admin indicator: user ID 1 is present "
                    "in network-wide user list"
                )

            severity = "CRITICAL" if has_email else "HIGH"

            self._result.add_finding(
                message=(
                    f"Network-wide user enumeration via REST API, "
                    f"{total_users} total users exposed across network"
                ),
                severity=severity,
                evidence="\n".join(evidence_parts),
                url=f"{self.target.rstrip('/')}/{url_path}",
            )

        # Also check user ID oracle for ID 1 (super admin)
        self._check_user_by_id(1)
        # Spot-check IDs 2-5
        for uid in range(2, 6):
            self._check_user_by_id(uid)

    def _check_user_by_id(self, uid: int) -> None:
        """Check if a specific user ID is exposed via REST API."""
        url_path = f"wp-json/wp/v2/users/{uid}"
        resp = self._safe_get(url_path)
        if resp is None:
            return

        if resp.status_code == 404:
            return

        try:
            u_data = resp.json()
        except (ValueError, json.JSONDecodeError):
            return

        if isinstance(u_data, dict) and "code" in u_data:
            code = u_data.get("code", "")
            if code == "rest_user_invalid_id":
                return
            elif code == "rest_user_cannot_view":
                # User exists but protected, oracle
                self._result.add_finding(
                    message=(
                        f"User ID oracle, user ID {uid} confirmed "
                        f"to exist (differential error response)"
                    ),
                    severity="MEDIUM",
                    evidence=(
                        f"GET /wp/v2/users/{uid} -> '{code}' confirms "
                        f"user exists vs 'rest_user_invalid_id' for "
                        f"non-existent users"
                    ),
                    url=(
                        f"{self.target.rstrip('/')}/"
                        f"wp-json/wp/v2/users/{uid}"
                    ),
                )
            return

        if isinstance(u_data, dict) and u_data.get("id"):
            has_email = bool(u_data.get("email"))
            is_super = uid == 1  # ID 1 is typically the super admin
            severity = "CRITICAL" if has_email else "HIGH"

            msg = (
                f"User ID {uid} data exposed via "
                f"/wp/v2/users/{uid}"
            )
            if is_super:
                msg += ", this is typically the network super admin"

            evidence_parts = [
                f"User: {self._user(u_data.get('name', 'unknown'))} "
                f"(slug: {self._user(u_data.get('slug', ''))})",
            ]
            if has_email:
                evidence_parts.append(
                    f"Email: {mask_email(u_data['email'], self.target, usernames_masked(self.config))}"
                )
            if is_super:
                evidence_parts.append(
                    "User ID 1 is typically the network super admin, "
                    "high-value target for targeted attacks"
                )
            evidence_parts.append(
                f"Roles: {u_data.get('roles', 'not disclosed')}"
            )

            self._result.add_finding(
                message=msg,
                severity=severity,
                evidence="\n".join(evidence_parts),
                url=(
                    f"{self.target.rstrip('/')}/"
                    f"wp-json/wp/v2/users/{uid}"
                ),
            )

    # ── 4) Cross-site contamination risk ─────────────────────────────────

    def _check_cross_site_contamination(self) -> None:
        """Assess cross-site contamination risk in multisite.

        In a multisite network, all subsites share the same database.
        A compromised subsite can potentially escalate to the entire
        network via SQL injection, file inclusion, or shared credentials.
        """
        evidence_parts = [
            "In a WordPress Multisite network, ALL subsites share:",
            "  - The same wp-config.php (database credentials)",
            "  - The same database server (shared wp_users table)",
            "  - The same filesystem (wp-content/plugins, wp-content/themes)",
            "",
            "Attack chain:",
            "  1. Attacker finds a vulnerable plugin on any subsite",
            "  2. SQL injection on that subsite reads wp_users across network",
            "  3. Extracted hashes cracked → super admin credentials",
            "  4. Full network takeover via /wp-admin/network/",
        ]

        # Check if common hardening constants are likely present
        # by probing for file modification endpoints
        hardening_indicators = []

        # Check if DISALLOW_FILE_MODS might be defined by probing
        # the plugin/theme editor endpoints (chemins devinés : --authorized)
        authorized = bool(self.config.get("authorized"))
        editor_resp = authorized and self._safe_get(
            "wp-admin/plugin-editor.php?file=wp-content/plugins/"
        )
        if editor_resp and editor_resp.status_code in (200, 403):
            if editor_resp.status_code == 403:
                hardening_indicators.append(
                    "Plugin editor blocked (403), DISALLOW_FILE_MODS "
                    "may be active"
                )
            else:
                hardening_indicators.append(
                    "Plugin editor accessible, DISALLOW_FILE_MODS "
                    "likely NOT defined"
                )

        theme_editor_resp = authorized and self._safe_get(
            "wp-admin/theme-editor.php?file=style.css"
        )
        if theme_editor_resp and theme_editor_resp.status_code in (200, 403):
            if theme_editor_resp.status_code == 403:
                hardening_indicators.append(
                    "Theme editor blocked (403), DISALLOW_FILE_MODS "
                    "may be active"
                )
            else:
                hardening_indicators.append(
                    "Theme editor accessible, DISALLOW_FILE_MODS "
                    "likely NOT defined"
                )

        if hardening_indicators:
            evidence_parts.append("File modification hardening check:")
            evidence_parts.extend(f"  - {i}" for i in hardening_indicators)
        else:
            evidence_parts.append(
                "File modification hardening: Could not determine "
                "(endpoints blocked or redirected)"
            )

        # Check for /wp-admin/network/ accessibility
        network_resp = authorized and self._safe_get("wp-admin/network/")
        if network_resp:
            evidence_parts.append(
                f"Network admin URL accessible: HTTP {network_resp.status_code}"
            )

        evidence = "\n".join(evidence_parts)

        # La base partagée est une caractéristique STRUCTURELLE du multisite, pas
        # une vuln en soi. On ne monte en CRITICAL que si un vecteur réel est
        # confirmé (éditeur de fichiers accessible ⇒ DISALLOW_FILE_MODS absent).
        editor_open = any("likely NOT defined" in i for i in hardening_indicators)
        if editor_open:
            self._result.add_finding(
                message=(
                    "Cross-site contamination risk, plugin/theme editor "
                    "accessible (DISALLOW_FILE_MODS not set) enables "
                    "network-wide compromise from any subsite"
                ),
                severity="CRITICAL",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-admin/network/",
            )
        else:
            self._result.add_finding(
                message=(
                    "Multisite partage une base de données entre tous les "
                    "sous-sites (caractéristique structurelle, aucun vecteur "
                    "d'édition de fichiers confirmé)"
                ),
                severity="INFO",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-admin/network/",
                confidence="potential",
            )

    # ── 5) Signup option enabled ───────────────────────────────────────

    def _check_signup_option(self) -> None:
        """Check if anyone can create a new site on the network."""
        resp = self._safe_get("wp-signup.php")
        if resp is None:
            return

        if resp.status_code != 200:
            self._result.add_finding(
                message="Signup page not accessible, may be disabled",
                severity="INFO",
                evidence=(
                    f"wp-signup.php returned HTTP {resp.status_code}"
                ),
                url=f"{self.target.rstrip('/')}/wp-signup.php",
            )
            return

        body = resp.text

        # Check for enabled signup patterns
        enabled_match = any(
            re.search(p, body) for p in self._SIGNUP_ENABLED_PATTERNS
        )
        disabled_match = any(
            re.search(p, body) for p in self._SIGNUP_DISABLED_PATTERNS
        )

        if enabled_match and not disabled_match:
            evidence_lines = [
                "wp-signup.php shows a registration form "
                "(site creation is enabled)",
                "Anyone can create a new site on this network",
            ]
            # Extract form fields as evidence
            form_match = re.search(
                r"(?i)<form[^>]*signup[^>]*>.*?</form>",
                body,
                re.DOTALL,
            )
            if form_match:
                evidence_lines.append(
                    f"Signup form found: "
                    f"{form_match.group()[:300]}"
                )

            evidence = "\n".join(evidence_lines)

            self._result.add_finding(
                message=(
                    "Signup option enabled, anyone can create "
                    "a new site on this network"
                ),
                severity="HIGH",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-signup.php",
            )
        elif disabled_match:
            self._result.add_finding(
                message="Signup option disabled on this network",
                severity="INFO",
                evidence=(
                    "wp-signup.php shows 'Registration has been disabled' "
                    "or similar message"
                ),
                url=f"{self.target.rstrip('/')}/wp-signup.php",
            )
        else:
            # Ambiguous, check body for clues
            if "signup" in body.lower() or "register" in body.lower():
                evidence_lines = [
                    "wp-signup.php content is ambiguous, "
                    "contains signup/registration language",
                    f"Response snippet: {body[:300]}",
                ]
                self._result.add_finding(
                    message=(
                        "Signup status unclear, wp-signup.php "
                        "responds but status indeterminate"
                    ),
                    severity="MEDIUM",
                    evidence="\n".join(evidence_lines),
                    url=f"{self.target.rstrip('/')}/wp-signup.php",
                )

    # ── 6) New site verification disabled ───────────────────────────────

    def _check_site_verification(self) -> None:
        """Check if new site creation bypasses email verification."""
        resp = self._safe_get("wp-signup.php")
        if resp is None:
            return

        if resp.status_code != 200:
            return

        body = resp.text
        verification_match = any(
            re.search(p, body) for p in self._VERIFICATION_PATTERNS
        )

        # Check if signup is enabled first
        enabled_match = any(
            re.search(p, body) for p in self._SIGNUP_ENABLED_PATTERNS
        )

        if not enabled_match:
            # Signup disabled, verification is moot
            return

        if verification_match:
            # Verification appears to be present, low risk
            evidence_lines = [
                "wp-signup.php contains email/verification/activation "
                "language, site verification appears enabled",
            ]
            # Extract verification-related text
            for pattern in self._VERIFICATION_PATTERNS:
                text_matches = re.findall(
                    r"[^.]*" + pattern + r"[^.]*\.", body, re.IGNORECASE
                )
                if text_matches:
                    evidence_lines.append(f"  - {text_matches[0].strip()}")

            self._result.add_finding(
                message="New site verification appears enabled "
                "(email verification present)",
                severity="INFO",
                evidence="\n".join(evidence_lines),
                url=f"{self.target.rstrip('/')}/wp-signup.php",
            )
        else:
            # No verification language found, likely disabled
            evidence_lines = [
                "wp-signup.php does NOT contain email/verify/confirm/activate "
                "language, new site verification may be disabled",
                "Sites may be created instantly without email confirmation",
                "Risk: Automated bots can create thousands of sites "
                "for spam/phishing SEO farms",
            ]

            evidence = "\n".join(evidence_lines)

            self._result.add_finding(
                message=(
                    "New site verification disabled, "
                    "instant site creation without confirmation"
                ),
                severity="HIGH",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-signup.php",
            )

        # CRITICAL check: signup enabled AND no verification
        if enabled_match and not verification_match:
            evidence = (
                "COMBINED RISK: Signup is enabled AND verification "
                "is disabled, anyone can create sites instantly "
                "with no email confirmation.\n\n"
                "This is the most dangerous multisite configuration: "
                "automated bots can register unlimited sites for "
                "spam SEO farms, phishing, and malware hosting."
            )
            self._result.add_finding(
                message=(
                    "CRITICAL: Open registration without verification, "
                    "instant site creation by anyone"
                ),
                severity="CRITICAL",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-signup.php",
            )

    # ── 7) Upload space check ───────────────────────────────────────────

    def _check_upload_space(self) -> None:
        """Check if upload space quota is unlimited or unset."""
        evidence_parts = [
            "Checking multisite upload space configuration...",
        ]

        # Try REST API settings endpoint for blog_upload_space
        resp = self._safe_get("wp-json/wp/v2/settings")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                upload_space = data.get("blog_upload_space")
                if upload_space is None or upload_space == "":
                    evidence_parts.append(
                        "REST API /wp/v2/settings: blog_upload_space "
                        "is null/absent, likely unlimited (default)"
                    )
                    evidence_parts.append(
                        "Risk: Unlimited upload space enables disk "
                        "exhaustion, DoS via upload flood, "
                        "abuse for file hosting"
                    )

                    evidence = "\n".join(evidence_parts)
                    self._result.add_finding(
                        message=(
                            "Upload space quota likely unlimited "
                            "(blog_upload_space not set)"
                        ),
                        severity="MEDIUM",
                        evidence=evidence,
                        url=(
                            f"{self.target.rstrip('/')}/"
                            f"wp-json/wp/v2/settings"
                        ),
                    )
                elif isinstance(upload_space, (int, float)):
                    space_mb = int(upload_space)
                    if space_mb == 0:
                        evidence_parts.append(
                            f"blog_upload_space = {space_mb} MB "
                            "(0 = effectively unlimited)"
                        )
                        severity = "MEDIUM"
                    elif space_mb < 100:
                        evidence_parts.append(
                            f"blog_upload_space = {space_mb} MB "
                            "(restrictive limit)"
                        )
                        severity = "LOW"
                    else:
                        evidence_parts.append(
                            f"blog_upload_space = {space_mb} MB "
                            "(explicit quota set)"
                        )
                        severity = "LOW"

                    evidence = "\n".join(evidence_parts)
                    self._result.add_finding(
                        message=(
                            f"Upload space quota configured: "
                            f"{space_mb} MB"
                        ),
                        severity=severity,
                        evidence=evidence,
                        url=(
                            f"{self.target.rstrip('/')}/"
                            f"wp-json/wp/v2/settings"
                        ),
                    )
            except (ValueError, json.JSONDecodeError):
                evidence_parts.append(
                    "REST API /wp/v2/settings returned non-JSON response"
                )
        else:
            # Fallback: check via site info endpoint or probative methods
            evidence_parts.append(
                "REST API /wp/v2/settings not accessible or blocked"
            )

            # Try probing upload capabilities via media endpoint
            media_resp = self._safe_get(
                "wp-json/wp/v2/media?per_page=1"
            )
            if media_resp and media_resp.status_code == 200:
                evidence_parts.append(
                    "Media endpoint accessible, upload capability "
                    "is present (space limits unknown)"
                )

            evidence_parts.append(
                "Could not determine upload quota, "
                "assume unlimited unless proven otherwise"
            )

            evidence = "\n".join(evidence_parts)
            # Quota non lisible en scan non authentifié : c'est une hypothèse,
            # pas une vulnérabilité prouvée → INFO/potential.
            self._result.add_finding(
                message=(
                    "Upload space quota non déterminé "
                    "(REST /settings protégé, non vérifié)"
                ),
                severity="INFO",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-json/wp/v2/settings",
                confidence="potential",
            )

    # ── 8) Network admin URL exposure ───────────────────────────────────

    def _check_network_admin_exposure(self) -> None:
        """Check if /wp-admin/network/ is exposed and distinguishable.

        Chemin deviné (niveau 2) : seulement avec --authorized."""
        if not self.config.get("authorized"):
            return
        network_url = "wp-admin/network/"
        resp = self._safe_get(network_url)
        if resp is None:
            return

        status = resp.status_code
        body = resp.text
        content_type = resp.headers.get("Content-Type", "")

        evidence_parts = [
            f"/wp-admin/network/ returned HTTP {status}",
        ]

        # Check for network admin content
        network_admin_match = any(
            re.search(p, body) for p in self._NETWORK_ADMIN_PATTERNS
        )

        if status == 200:
            # Login form or direct access
            if network_admin_match:
                evidence_parts.append(
                    "Response contains 'Network Admin' or 'Super Admin' "
                    "language, network admin login is exposed"
                )
                evidence_parts.append(
                    "Risk: Attackers can target super admin accounts "
                    "specifically, brute-force the network-level login"
                )

                evidence = "\n".join(evidence_parts)
                self._result.add_finding(
                    message=(
                        "Network admin URL exposed (/wp-admin/network/) "
                        "- high-value login page accessible"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/{network_url}",
                )
            elif "wp-login" in body or "login" in body.lower():
                evidence_parts.append(
                    "Shows a login form (standard WordPress login)"
                )
                evidence = "\n".join(evidence_parts)
                self._result.add_finding(
                    message=(
                        "Network admin URL accessible /wp-admin/network/ "
                        "(login form displayed)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/{network_url}",
                )
            else:
                evidence_parts.append(
                    f"Response snippet: {body[:200]}"
                )
                evidence = "\n".join(evidence_parts)
                self._result.add_finding(
                    message=(
                        "/wp-admin/network/ returned HTTP 200, "
                        "network admin endpoint accessible"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/{network_url}",
                )

        elif status in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            evidence_parts.append(
                f"Redirect to: {location}"
            )
            # If it redirects to wp-login.php, it's the normal login flow
            if "wp-login.php" in location:
                evidence_parts.append(
                    "Redirects to wp-login.php (standard behavior)"
                )
                evidence = "\n".join(evidence_parts)
                self._result.add_finding(
                    message=(
                        "/wp-admin/network/ redirects to login, "
                        "network admin endpoint identified"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/{network_url}",
                )
            else:
                evidence = "\n".join(evidence_parts)
                self._result.add_finding(
                    message=(
                        f"/wp-admin/network/ redirects (HTTP {status})"
                    ),
                    severity="LOW",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/{network_url}",
                )
        else:
            evidence_parts.append(
                "Endpoint returns non-200 status, "
                "likely blocked or protected"
            )
            evidence = "\n".join(evidence_parts)
            self._result.add_finding(
                message=(
                    f"/wp-admin/network/ returned HTTP {status} "
                    f"- may be protected"
                ),
                severity="INFO",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/{network_url}",
            )

    # ── 9) Super admin detection ────────────────────────────────────────

    def _check_super_admin(self) -> None:
        """Check for super admin targeting via user ID 1.

        In multisite, user ID 1 is almost always the network super admin.
        """
        # Check user ID 1 specifically
        resp = self._safe_get("wp-json/wp/v2/users/1")
        if resp is None:
            return

        if resp.status_code == 404:
            self._result.add_finding(
                message=(
                    "User ID 1 not found, super admin may have "
                    "been renamed or protected"
                ),
                severity="INFO",
                evidence=(
                    "GET /wp/v2/users/1 returned HTTP 404, "
                    "user ID 1 does not exist or is hidden"
                ),
                url=f"{self.target.rstrip('/')}/wp-json/wp/v2/users/1",
            )
            return

        try:
            u_data = resp.json()
        except (ValueError, json.JSONDecodeError):
            return

        if isinstance(u_data, dict) and "code" in u_data:
            code = u_data.get("code", "")
            if code == "rest_user_cannot_view":
                self._result.add_finding(
                    message=(
                        "User ID 1 confirmed to exist but protected "
                        "(super admin likely)"
                    ),
                    severity="MEDIUM",
                    evidence=(
                        f"GET /wp/v2/users/1 -> '{code}', "
                        f"user exists but data is hidden. "
                        f"ID 1 is typically the network super admin."
                    ),
                    url=f"{self.target.rstrip('/')}/wp-json/wp/v2/users/1",
                )
            return

        if isinstance(u_data, dict) and u_data.get("id") == 1:
            slug = u_data.get("slug", "unknown")
            name = u_data.get("name", "unknown")
            roles = u_data.get("roles", "not disclosed")
            has_email = bool(u_data.get("email"))

            evidence_parts = [
                f"User ID 1: {name} (slug: {slug})",
                f"Roles: {roles}",
            ]
            if has_email:
                evidence_parts.append(
                    f"Email exposed: {u_data['email']}"
                )
            evidence_parts.append(
                "User ID 1 is almost always the network super admin, "
                "this is a high-value target for credential stuffing, "
                "spear-phishing, and brute-force attacks on "
                "/wp-admin/network/"
            )

            severity = "CRITICAL" if has_email else "HIGH"

            self._result.add_finding(
                message=(
                    "Super admin targeting, user ID 1 exposed "
                    f"({name}), typically the network super admin"
                ),
                severity=severity,
                evidence="\n".join(evidence_parts),
                url=f"{self.target.rstrip('/')}/wp-json/wp/v2/users/1",
            )

    # ── 10) Site archiving / suspended sites exposure ───────────────────

    def _check_archived_sites(self) -> None:
        """Check if archived or suspended sites still serve content."""
        evidence_parts = [
            "Checking for archived/suspended site exposure...",
        ]

        # Try REST API /wp/v2/sites to find archived sites
        resp = self._safe_get("wp-json/wp/v2/sites")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    archived = [
                        s for s in data
                        if isinstance(s, dict) and s.get("archived")
                    ]
                    if archived:
                        evidence_parts.append(
                            f"REST API reports {len(archived)} "
                            "archived site(s):"
                        )
                        for site in archived[:5]:
                            site_url = (
                                site.get("url")
                                or site.get("link")
                                or f"ID {site.get('id', '?')}"
                            )
                            site_name = site.get("name", site.get("slug", "?"))
                            evidence_parts.append(
                                f"  - {site_name}: {site_url}"
                            )
                        evidence_parts.append(
                            "Risk: Archived sites rarely get security "
                            "updates, they are easy entry points into "
                            "the shared database"
                        )

                        evidence = "\n".join(evidence_parts)
                        self._result.add_finding(
                            message=(
                                f"{len(archived)} archived site(s) "
                                f"exposed via REST API"
                            ),
                            severity="MEDIUM",
                            evidence=evidence,
                            url=(
                                f"{self.target.rstrip('/')}/"
                                f"wp-json/wp/v2/sites"
                            ),
                        )
                    else:
                        evidence_parts.append(
                            "No archived sites found via REST API"
                        )
                elif isinstance(data, dict) and data.get("sites"):
                    # Alternative response structure
                    sites = data.get("sites", [])
                    archived = [
                        s for s in sites
                        if isinstance(s, dict) and s.get("archived")
                    ]
                    if archived:
                        evidence_parts.append(
                            f"REST API reports {len(archived)} "
                            "archived site(s)"
                        )
            except (ValueError, json.JSONDecodeError):
                evidence_parts.append(
                    "Could not parse /wp/v2/sites response as JSON"
                )
        else:
            evidence_parts.append(
                "REST API /wp/v2/sites not accessible or blocked"
            )

        # Check for common archived/suspended URL patterns
        evidence_parts.append(
            "Note: Archived sites in Multisite still serve content "
            "via their URL, they are only administratively hidden. "
            "They should return 410 (Gone) but often return 200 (OK)."
        )

        # Note générale sur le comportement des sites archivés. Les sites
        # réellement archivés/exposés sont déjà signalés (MEDIUM) plus haut ;
        # cette note générique ne doit pas être un finding MEDIUM inconditionnel.
        evidence = "\n".join(evidence_parts)

        self._result.add_finding(
            message=(
                "Rappel : en multisite, un site archivé peut continuer à "
                "servir du contenu via son URL (note générale, non vérifiée ici)"
            ),
            severity="INFO",
            evidence=evidence,
            url=f"{self.target.rstrip('/')}/wp-json/wp/v2/sites",
            confidence="potential",
        )

    # ── HTTP helpers ────────────────────────────────────────────────────

    def _safe_get(self, path: str, **kwargs) -> Optional[requests.Response]:
        """Safe GET that returns None on connection errors."""
        try:
            return self.http_get(path, **kwargs)
        except Exception:
            return None

    def _safe_head(self, path: str, **kwargs) -> Optional[requests.Response]:
        """Safe HEAD that returns None on connection errors."""
        try:
            return self.http_head(path, **kwargs)
        except Exception:
            return None
