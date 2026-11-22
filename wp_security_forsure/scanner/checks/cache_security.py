"""Check for cache plugin security issues on WordPress.

Inherits from BaseCheck. Covers cache plugin detection (W3 Total Cache,
WP Super Cache, LiteSpeed Cache, WP Rocket), exposed cache/config file
paths, cache header analysis, sensitive page caching detection, and CDN
(Cloudflare) cache assessment.

Détection PASSIVE uniquement : les réponses sont lues telles qu'elles sont
servies à un visiteur. Retirés car actifs : l'empoisonnement de cache (en-tête
X-Forwarded-Host forgé), la web cache deception (URL piégées mises en cache)
et les tests d'isolation par faux cookie de session WordPress. Ils sont
signalés par un constat INFO « non évaluable passivement ».

Flagged CRITICAL:
  - Exposed database cache files (W3TC dbcache/)
  - Exposed plugin configuration files revealing PHP source or sensitive data

Flagged HIGH:
  - Sensitive pages (wp-admin, wp-login.php) cached without no-cache header
  - Exposed cache file directories with directory listing
  - Cloudflare full-page caching authenticated pages
"""

from typing import Dict, List, Optional, Set, Tuple

from .base import BaseCheck, CheckResult


class CacheSecurityCheck(BaseCheck):
    """Check for cache plugin security vulnerabilities on WordPress."""

    name = "cache_security"
    title = "Cache Plugin Security"
    description = (
        "Detects cache plugins, checks for exposed cache/config files, "
        "insecure cache headers, sensitive page caching, and CDN cache "
        "misconfigurations (passive only)."
    )
    severity = "CRITICAL"
    depends_on: List[str] = []
    access_tier = 1  # mixte : répertoires de cache devinés sous --authorized

    # ── Cache plugin detection paths ────────────────────────────────────
    PLUGIN_DIR_PATHS: List[str] = [
        "wp-content/plugins/w3-total-cache/",
        "wp-content/plugins/wp-super-cache/",
        "wp-content/plugins/litespeed-cache/",
        "wp-content/plugins/wp-rocket/",
    ]

    # ── Generator tag patterns for detection ────────────────────────────
    GENERATOR_PATTERNS: Dict[str, List[str]] = {
        "W3 Total Cache": [
            '<meta name="generator" content="W3 Total Cache',
        ],
        "WP Super Cache": [
            "WP Super Cache",
            "wp-super-cache",
        ],
        "LiteSpeed Cache": [
            '<meta name="generator" content="LiteSpeed Cache',
            "Powered by LiteSpeed",
            "litespeed-cache",
        ],
        "WP Rocket": [
            "wp-rocket",
            "WP Rocket",
        ],
    }

    # ── W3 Total Cache paths ────────────────────────────────────────────
    # Les fichiers de configuration PHP (W3TC_CONFIG_PATHS, WPSC_CONFIG_PATHS,
    # WPROCKET_ADVANCED_CACHE) ne sont plus demandés : un GET les exécuterait.
    # Ils ne servent plus qu'au constat INFO « non évaluable ».
    W3TC_DBCACHE_PATHS: List[str] = [
        "wp-content/w3tc/dbcache/",
        "wp-content/cache/db/",
        "wp-content/w3tc-cache/db/",
    ]

    W3TC_CONFIG_PATHS: List[str] = [
        "wp-content/w3tc-config/master.php",
        "wp-content/w3tc-config/master-admin.php",
        "wp-content/w3tc/config/master.php",
        "wp-content/cache/config/master.php",
    ]

    # ── WP Super Cache paths ────────────────────────────────────────────
    WPSC_CONFIG_PATHS: List[str] = [
        "wp-content/plugins/wp-super-cache/wp-cache-config.php",
        "wp-content/wp-cache-config.php",
    ]

    WPSC_CACHE_PATHS: List[str] = [
        "wp-content/cache/supercache/",
    ]

    # ── LiteSpeed Cache indicators ──────────────────────────────────────
    LITESPEED_HEADER_PATTERNS: List[str] = [
        "x-litespeed-cache",
        "x-litespeed-esi",
        "x-litespeed-tag",
        "x-litespeed-vary",
    ]

    # ── WP Rocket paths ─────────────────────────────────────────────────
    WPROCKET_CACHE_PATHS: List[str] = [
        "wp-content/cache/wp-rocket/",
    ]

    WPROCKET_ADVANCED_CACHE: str = "wp-content/advanced-cache.php"

    # ── Sensitive pages to test for caching ─────────────────────────────
    SENSITIVE_PAGES: List[str] = [
        "wp-admin/",
        "wp-login.php",
        "wp-json/",
        "wp-json/wp/v2/users",
    ]

    # ── Cloudflare detection headers ────────────────────────────────────
    CLOUDFLARE_HEADERS: List[str] = [
        "cf-ray",
        "cf-cache-status",
        "cf-request-id",
    ]

    # ── Secure cache control directives ─────────────────────────────────
    SECURE_CACHE_DIRECTIVES: List[str] = [
        "no-cache",
        "no-store",
        "private",
        "max-age=0",
    ]

    # ── Public API ──────────────────────────────────────────────────────

    def run(self) -> CheckResult:
        """Execute the cache security check across all categories."""
        self._check_plugin_detection()
        if self.config.get("authorized"):
            self._check_w3tc_dbcache_exposure()
            self._check_wpsc_cache_exposure()
            self._check_wprocket_cache_exposure()
        else:
            self.note_unlinked_skipped(
                "répertoires d'extensions de cache et dossiers de cache "
                "(W3 Total Cache, WP Super Cache, LiteSpeed Cache, WP Rocket)")
        self._report_php_config_not_assessable()
        self._check_litespeed_cache()
        self._check_cache_headers()
        self._check_sensitive_page_caching()
        self._check_cdn_cache()
        self._report_not_assessable()
        return self._result

    def _report_php_config_not_assessable(self) -> None:
        """Constat INFO : fichiers de configuration PHP des extensions de cache
        (W3 Total Cache, WP Super Cache, advanced-cache.php de WP Rocket) non
        demandés, un GET les exécuterait."""
        files = (self.W3TC_CONFIG_PATHS + self.WPSC_CONFIG_PATHS
                 + [self.WPROCKET_ADVANCED_CACHE])
        self.note_not_assessable(
            "Fichiers de configuration PHP des extensions de cache (W3 Total "
            "Cache, WP Super Cache, advanced-cache.php)",
            evidence=("Fichiers non demandés : " + ", ".join(files) + ". Un GET "
                      "sur un fichier PHP l'exécute côté serveur"))

    def _report_not_assessable(self) -> None:
        """Constat INFO : sous-contrôles retirés car ils exigeaient une requête
        forgée (en-tête, URL piégée ou cookie de session factice)."""
        self._result.add_finding(
            message=(
                "Sous-contrôles cache non évaluables passivement : empoisonnement "
                "de cache, web cache deception, isolation du cache par cookie de "
                "session"
            ),
            severity="INFO",
            evidence=(
                "Ces vérifications exigent d'envoyer un en-tête forgé "
                "(X-Forwarded-Host), des URL piégées destinées à être mises en "
                "cache, ou un faux cookie de session : le scanner ne le fait "
                "jamais (lecture seule). À vérifier manuellement, dans un cadre "
                "autorisé."
            ),
            url=self.target,
            confidence="potential",
        )

    # ── 1) Cache plugin detection ──────────────────────────────────────

    def _check_plugin_detection(self) -> None:
        """Detect active cache plugins via generator tags, file paths, and headers."""
        detected: Dict[str, List[str]] = {}

        # ── a) Generator meta tags ──
        try:
            resp = self.http_get("")
            body = resp.text
            headers = resp.headers
        except Exception:
            body = ""
            headers = {}

        if body:
            body_lower = body.lower()
            for plugin_name, patterns in self.GENERATOR_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in body_lower:
                        detected.setdefault(plugin_name, []).append(
                            f"Generator tag matched: '{pattern}'"
                        )
                        break

        # ── b) Plugin directory probing (chemins devinés : --authorized) ──
        dir_paths = self.PLUGIN_DIR_PATHS if self.config.get("authorized") else []
        for path in dir_paths:
            plugin_name = self._plugin_name_from_path(path)
            try:
                head_resp = self.http_head(path, allow_redirects=False)
                if head_resp.status_code not in (404,):
                    detected.setdefault(plugin_name, []).append(
                        f"Plugin directory accessible at {path} "
                        f"(HTTP {head_resp.status_code})"
                    )
            except Exception:
                continue

        # ── c) Response header detection ──
        if headers:
            for header_name, header_value in headers.items():
                header_lower = header_name.lower()

                # X-Cache (generic)
                if header_lower == "x-cache":
                    detected.setdefault("Generic Cache", []).append(
                        f"X-Cache header: {header_value}"
                    )

                # X-LiteSpeed-Cache
                if "litespeed" in header_lower and "cache" in header_lower:
                    detected.setdefault("LiteSpeed Cache", []).append(
                        f"Header: {header_name}: {header_value}"
                    )

                # X-WP-Super-Cache
                if "wp-super-cache" in header_lower or "super-cache" in header_lower:
                    detected.setdefault("WP Super Cache", []).append(
                        f"Header: {header_name}: {header_value}"
                    )

                # CF-Cache-Status (CDN, not plugin, still note)
                if header_lower == "cf-cache-status":
                    detected.setdefault("Cloudflare CDN", []).append(
                        f"Header: {header_name}: {header_value}"
                    )

        # ── d) Cookie detection ──
        cookie_header = headers.get("Set-Cookie", "")
        if cookie_header:
            if "w3tc_logged_out" in cookie_header:
                detected.setdefault("W3 Total Cache", []).append(
                    "Cookie: w3tc_logged_out present"
                )
            if "wpSGCacheBypass" in cookie_header:
                detected.setdefault("WP Super Cache", []).append(
                    "Cookie: wpSGCacheBypass present"
                )
            if "litespeed_vary" in cookie_header:
                detected.setdefault("LiteSpeed Cache", []).append(
                    "Cookie: litespeed_vary present"
                )

        # ── Report findings ──
        if detected:
            evidence_parts: List[str] = []
            for plugin_name, indicators in sorted(detected.items()):
                evidence_parts.append(f"  {plugin_name}:")
                for ind in indicators:
                    evidence_parts.append(f"    - {ind}")
            evidence = "\n".join(evidence_parts)

            plugins_str = ", ".join(sorted(detected.keys()))
            self._result.add_finding(
                message=(
                    f"Cache plugin(s) detected: {plugins_str} "
                    f"(INFO, enables subsequent targeted checks)"
                ),
                severity="INFO",
                evidence=evidence,
                url=self.target,
            )
        else:
            # No cache plugin detected, still note it
            self._result.add_finding(
                message=(
                    "No cache plugin detected via generator tags, "
                    "headers, cookies, or file paths (INFO)"
                ),
                severity="INFO",
                evidence="Checked generator meta tags, plugin directories, "
                         "response headers, and cookies. No cache plugin "
                         "signatures found.",
                url=self.target,
            )

    # ── 2) W3 Total Cache, Database cache exposure ────────────────────

    def _check_w3tc_dbcache_exposure(self) -> None:
        """Check for exposed W3 Total Cache database cache files (CRITICAL)."""
        for path in self.W3TC_DBCACHE_PATHS:
            resp, body, status, content_type = self._head_then_get(path)
            if body is None:
                continue

            url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
            listing_keywords = [
                "Index of", "index of", "Directory listing",
                "<title>Index of", "Parent Directory",
            ]
            has_listing = any(kw in body for kw in listing_keywords)

            if has_listing:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"W3 Total Cache database cache directory listing, "
                        f"{path} (CRITICAL, DB cache files may be downloadable)"
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                    url=url,
                )
            elif status in (200, 301, 302) and len(body) > 50:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"W3 Total Cache database cache path accessible, "
                        f"{path} (HIGH, HTTP {status}, {len(body)} bytes)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=url,
                )
            elif status not in (404,) and len(body) > 10:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"W3 Total Cache database cache path exists, "
                        f"{path} (MEDIUM, HTTP {status})"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=url,
                )

    # ── 5) WP Super Cache, Cache file exposure ────────────────────────

    def _check_wpsc_cache_exposure(self) -> None:
        """Check for exposed WP Super Cache cache files (HIGH/CRITICAL)."""
        for path in self.WPSC_CACHE_PATHS:
            resp, body, status, content_type = self._head_then_get(path)
            if body is None:
                continue

            url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
            listing_keywords = [
                "Index of", "index of", "Directory listing",
                "<title>Index of", "Parent Directory",
            ]
            has_listing = any(kw in body for kw in listing_keywords)

            if has_listing:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"WP Super Cache cache directory listing, "
                        f"{path} (HIGH, cached HTML files exposed, "
                        f"may include drafts or private content)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=url,
                )
            elif status in (200, 301, 302) and len(body) > 50:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"WP Super Cache cache path accessible, "
                        f"{path} (MEDIUM, HTTP {status}, {len(body)} bytes)"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=url,
                )

    # ── 6) LiteSpeed Cache detection and logged-in cache check ─────────

    def _check_litespeed_cache(self) -> None:
        """Check for LiteSpeed Cache presence and logged-in user cache issues."""
        try:
            base_resp = self.http_get("")
            headers = base_resp.headers
            body = base_resp.text
        except Exception:
            return

        url = self.target
        header_dict = {k.lower(): v for k, v in headers.items()}

        # ── a) Check for LiteSpeed-specific headers ──
        ls_headers_found: List[str] = []
        for pattern in self.LITESPEED_HEADER_PATTERNS:
            if pattern in header_dict:
                ls_headers_found.append(f"{pattern}: {header_dict[pattern]}")

        if ls_headers_found:
            evidence = "LiteSpeed Cache headers found:\n" + "\n".join(
                f"  - {h}" for h in ls_headers_found
            )
            self._result.add_finding(
                message=(
                    "LiteSpeed Cache detected via headers "
                    "(INFO, enables targeted checks)"
                ),
                severity="INFO",
                evidence=evidence,
                url=url,
            )

        # ── b) Check for litespeed_vary cookie ──
        set_cookie = headers.get("Set-Cookie", "")
        has_litespeed_cookie = "litespeed_vary" in set_cookie

        if has_litespeed_cookie:
            self._result.add_finding(
                message=(
                    "LiteSpeed Cache litespeed_vary cookie detected "
                    "(INFO, used for logged-in/out cache variation)"
                ),
                severity="INFO",
                evidence=f"Set-Cookie header contains: litespeed_vary",
                url=url,
            )

        # ── c) Isolation du cache (en-tête Vary, lecture passive) ──
        if ls_headers_found or has_litespeed_cookie:
            # Check Vary header
            vary = headers.get("Vary", "")
            if "litespeed_vary" not in vary and ls_headers_found:
                evidence = (
                    f"Vary header: {vary}\n"
                    f"Missing 'Vary: litespeed_vary' may cause improper "
                    f"cache isolation for authenticated users."
                )
                self._result.add_finding(
                    message=(
                        "LiteSpeed Cache missing Vary: litespeed_vary header "
                        "(MEDIUM, cache may not properly isolate user sessions)"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=url,
                )

    # ── 7) WP Rocket, Cache directory exposure ────────────────────────

    def _check_wprocket_cache_exposure(self) -> None:
        """Check for exposed WP Rocket cache directories."""
        for path in self.WPROCKET_CACHE_PATHS:
            resp, body, status, content_type = self._head_then_get(path)
            if body is None:
                continue

            url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
            listing_keywords = [
                "Index of", "index of", "Directory listing",
                "<title>Index of", "Parent Directory",
            ]
            has_listing = any(kw in body for kw in listing_keywords)

            if has_listing:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"WP Rocket cache directory listing, "
                        f"{path} (HIGH, cached HTML files exposed)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=url,
                )
            elif status in (200, 301, 302) and len(body) > 50:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"WP Rocket cache path accessible, "
                        f"{path} (MEDIUM, HTTP {status}, {len(body)} bytes)"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=url,
                )

    # ── 10) Cache headers analysis ─────────────────────────────────────

    def _check_cache_headers(self) -> None:
        """Analyze X-Cache, Age, Cache-Control, and Vary headers."""
        try:
            resp = self.http_get("")
            headers = resp.headers
        except Exception:
            return

        url = self.target
        header_dict = {k.lower(): v for k, v in headers.items()}
        findings: List[str] = []

        # ── a) X-Cache header analysis ──
        x_cache = header_dict.get("x-cache", "")
        if x_cache:
            x_cache_lower = x_cache.lower()
            if "hit" in x_cache_lower:
                findings.append(f"X-Cache: {x_cache}, page served from cache")
            elif "miss" in x_cache_lower:
                findings.append(f"X-Cache: {x_cache}, page not in cache")
            else:
                findings.append(f"X-Cache: {x_cache}")

        # ── b) Age header analysis ──
        age = header_dict.get("age", "")
        if age:
            try:
                age_seconds = int(age)
                if age_seconds > 3600:
                    findings.append(
                        f"Age: {age}s ({age_seconds/3600:.1f}h), "
                        f"long cache TTL, stale content risk"
                    )
                else:
                    findings.append(f"Age: {age}s")
            except ValueError:
                findings.append(f"Age: {age}")

        # ── c) Cache-Control analysis ──
        cache_control = header_dict.get("cache-control", "")
        if cache_control:
            cc_lower = cache_control.lower()
            if "public" in cc_lower:
                findings.append(
                    f"Cache-Control: {cache_control}, "
                    f"'public' allows any cache to store response"
                )
            elif "private" in cc_lower:
                findings.append(
                    f"Cache-Control: {cache_control}, "
                    f"'private' limits caching to browser only"
                )
            elif "no-store" in cc_lower:
                findings.append(
                    f"Cache-Control: {cache_control}, "
                    f"'no-store' prevents caching entirely"
                )
            else:
                findings.append(f"Cache-Control: {cache_control}")
        else:
            findings.append("Cache-Control header absent, no caching restrictions")

        # ── d) Vary header analysis ──
        vary = header_dict.get("vary", "")
        if vary:
            vary_lower = vary.lower()
            has_cookie = "cookie" in vary_lower
            has_auth = "authorization" in vary_lower
            if has_cookie and has_auth:
                findings.append(
                    f"Vary: {vary}, properly varies by cookie and auth"
                )
            elif has_cookie:
                findings.append(
                    f"Vary: {vary}, varies by cookie (good for user isolation)"
                )
            else:
                findings.append(
                    f"Vary: {vary}, does NOT vary by Cookie or Authorization "
                    f"(cache may serve same content to all users)"
                )
        else:
            findings.append(
                "Vary header absent, cache may serve same content "
                "to all users regardless of authentication"
            )

        if findings:
            evidence = "\n".join(f"  - {f}" for f in findings)
            self._result.add_finding(
                message=(
                    "Cache headers analysis (INFO, see evidence for details)"
                ),
                severity="INFO",
                evidence=evidence,
                url=url,
            )

    # ── 11) Sensitive page caching ─────────────────────────────────────

    def _check_sensitive_page_caching(self) -> None:
        """Check if sensitive WordPress pages are cached (HIGH if so).

        wp-admin and wp-login.php should return Cache-Control with
        no-cache/no-store/private directives. Missing these indicates
        sensitive pages may be cached and served to unauthenticated users.
        """
        for page in self.SENSITIVE_PAGES:
            try:
                resp = self.http_get(page, allow_redirects=False)
                headers = resp.headers
                status = resp.status_code
            except Exception:
                continue

            # Une redirection (ex. wp-admin/ -> wp-login en 302, corps vide) n'est
            # pas du contenu sensible mis en cache. On ne juge que les 200 servis.
            if status != 200:
                continue

            url = f"{self.target.rstrip('/')}/{page.lstrip('/')}"
            cache_control = headers.get("Cache-Control", "")
            cc_lower = cache_control.lower()

            # Check if response is missing proper caching restrictions
            has_secure_directive = any(
                d in cc_lower for d in self.SECURE_CACHE_DIRECTIVES
            )

            if not cache_control:
                evidence = (
                    f"Path: {page}\n"
                    f"HTTP {status}\n"
                    f"Cache-Control header: ABSENT\n"
                    f"No caching restrictions defined, page may be cached "
                    f"by browsers, proxies, and CDNs."
                )
                severity = "HIGH" if "wp-admin" in page or "wp-login" in page else "MEDIUM"
                self._result.add_finding(
                    message=(
                        f"Sensitive page {page} has no Cache-Control header "
                        f"({severity}, page may be cached)"
                    ),
                    severity=severity,
                    evidence=evidence,
                    url=url,
                )
            elif not has_secure_directive:
                evidence = (
                    f"Path: {page}\n"
                    f"HTTP {status}\n"
                    f"Cache-Control: {cache_control}\n"
                    f"Missing no-cache/no-store/private directives, "
                    f"page may be cached in shared caches."
                )
                severity = "HIGH" if "wp-admin" in page or "wp-login" in page else "MEDIUM"
                self._result.add_finding(
                    message=(
                        f"Sensitive page {page} lacks secure cache directives "
                        f"({severity}, Cache-Control: {cache_control} "
                        f"missing no-cache/no-store/private)"
                    ),
                    severity=severity,
                    evidence=evidence,
                    url=url,
                )
            elif "public" in cc_lower:
                evidence = (
                    f"Path: {page}\n"
                    f"HTTP {status}\n"
                    f"Cache-Control: {cache_control}\n"
                    f"'public' directive allows shared caches to store "
                    f"this sensitive page."
                )
                severity = "HIGH" if "wp-admin" in page or "wp-login" in page else "MEDIUM"
                self._result.add_finding(
                    message=(
                        f"Sensitive page {page} is Cache-Control: public "
                        f"({severity}, shared caches may store this page)"
                    ),
                    severity=severity,
                    evidence=evidence,
                    url=url,
                )

    # ── 12) CDN cache check (Cloudflare) ───────────────────────────────

    def _check_cdn_cache(self) -> None:
        """Check if behind Cloudflare and if authenticated pages are cached."""
        try:
            resp = self.http_get("")
            headers = resp.headers
        except Exception:
            return

        header_dict = {k.lower(): v for k, v in headers.items()}

        # ── a) Detect Cloudflare ──
        is_cloudflare = any(
            cf_hdr in header_dict for cf_hdr in self.CLOUDFLARE_HEADERS
        )
        if not is_cloudflare:
            return

        cf_cache_status = header_dict.get("cf-cache-status", "")
        cf_ray = header_dict.get("cf-ray", "")

        self._result.add_finding(
            message=(
                "Cloudflare CDN detected "
                "(INFO, checking CDN cache configuration)"
            ),
            severity="INFO",
            evidence=(
                f"CF-Ray: {cf_ray}\n"
                f"CF-Cache-Status: {cf_cache_status}\n"
                f"Target is behind Cloudflare CDN."
            ),
            url=self.target,
        )

        # ── b) Check if Cloudflare caches authenticated pages ──
        for page in self.SENSITIVE_PAGES:
            try:
                page_resp = self.http_get(page, allow_redirects=False)
                page_headers = {k.lower(): v for k, v in page_resp.headers.items()}
                page_cf_status = page_headers.get("cf-cache-status", "")
                page_cache_control = page_headers.get("cache-control", "")
            except Exception:
                continue

            url = f"{self.target.rstrip('/')}/{page.lstrip('/')}"

            if page_cf_status.upper() == "HIT":
                evidence = (
                    f"Path: {page}\n"
                    f"CF-Cache-Status: {page_cf_status}\n"
                    f"Cache-Control: {page_cache_control}\n"
                    f"Cloudflare is serving this page from cache, "
                    f"sensitive content may be publicly cached."
                )
                severity = "HIGH" if "wp-admin" in page or "wp-login" in page else "MEDIUM"
                self._result.add_finding(
                    message=(
                        f"Cloudflare caches {page} (CF-Cache-Status: HIT) "
                        f"({severity}, authenticated/sensitive page "
                        f"served from CDN cache)"
                    ),
                    severity=severity,
                    evidence=evidence,
                    url=url,
                )

    # ── Internal helpers ───────────────────────────────────────────────

    def _head_then_get(
        self, path: str,
    ) -> Tuple[Optional[object], Optional[str], int, str]:
        """HEAD-first-then-GET strategy.

        Returns (response, body_text, status_code, content_type).
        body_text is None if the file doesn't exist or can't be fetched.
        """
        try:
            head_resp = self.http_head(path, allow_redirects=False)
        except Exception:
            return (None, None, 0, "")

        if head_resp.status_code == 404:
            return (None, None, 404, "")

        try:
            get_resp = self.http_get(path)
        except Exception:
            return (None, None, 0, "")

        if get_resp.status_code == 404:
            return (None, None, 404, "")

        # Site soft-404 : 200 + page d'accueil pour toute URL inexistante →
        # traité comme « ressource absente » (évite les faux « path accessible »).
        if self._is_soft404(get_resp):
            return (None, None, 404, "")

        body = get_resp.text
        status = get_resp.status_code
        content_type = get_resp.headers.get("Content-Type", "")

        if len(body) < 10:
            return (None, None, status, content_type)

        return (get_resp, body, status, content_type)

    def _build_evidence(
        self, path: str, status: int,
        content_type: str, body: str,
    ) -> str:
        """Build an evidence string for a finding."""
        snippet = body[:600].strip()
        if len(body) > 600:
            snippet = snippet[:597] + "..."

        return (
            f"Path: {path}\n"
            f"HTTP {status} | Content-Type: {content_type} "
            f"| Size: {len(body)} bytes\n"
            f"Snippet:\n{snippet}"
        )

    def _plugin_name_from_path(self, path: str) -> str:
        """Extract a human-readable plugin name from a directory path."""
        mapping = {
            "w3-total-cache": "W3 Total Cache",
            "wp-super-cache": "WP Super Cache",
            "litespeed-cache": "LiteSpeed Cache",
            "wp-rocket": "WP Rocket",
        }
        for key, name in mapping.items():
            if key in path:
                return name
        return path.split("/")[-2] if "/" in path else path
