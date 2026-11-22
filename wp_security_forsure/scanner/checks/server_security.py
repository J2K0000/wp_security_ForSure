"""Check for server-level security configuration weaknesses on the target.

Inherits from BaseCheck. Covers:
  1) Web server detection, Apache/Nginx/LiteSpeed/IIS from Server header
  2) Server header version disclosure, version number in Server header (HIGH)
  3) X-Powered-By header, PHP version disclosed (MEDIUM)
  4) Directory listing test, wp-content/uploads/, plugins/, themes/, wp-includes/ (HIGH)
  5) HTTP methods allowed : en-tête Allow renvoyé par OPTIONS (aucune méthode
     dangereuse n'est jamais émise)
  6) ModSecurity/WAF detection : en-têtes d'une réponse normale (passif)
  7) HTTP/2 detection, check server HTTP/2 support (INFO)
  8) PHP detection, .php extension probes, X-Powered-By header
  9) Compression info leakage, gzip/brotli encoding and timing differences
"""

import re
import time
from typing import Dict, List, Optional, Tuple

from .base import BaseCheck, CheckResult


class ServerSecurityCheck(BaseCheck):
    """Check server-level security configuration of the target."""

    name = "server_security"
    title = "Server Security Configuration Audit"
    description = (
        "Checks web server fingerprinting, version disclosure, directory listing, "
        "allowed HTTP methods, WAF/ModSecurity detection, HTTP/2 support, "
        "PHP detection, and compression-related information leakage."
    )
    severity = "CRITICAL"
    access_tier = 1  # mixte : listings de répertoires sous --authorized
    depends_on: List[str] = []

    # ── Directory listing paths ─────────────────────────────────────────
    DIR_LISTING_PATHS: List[str] = [
        "wp-content/uploads/",
        "wp-content/plugins/",
        "wp-content/themes/",
        "wp-includes/",
        "wp-content/",
        "wp-admin/",
    ]

    # ── Méthodes dangereuses recherchées dans l'en-tête Allow ───────────────────────────────
    DANGEROUS_METHODS: Dict[str, str] = {
        "PUT": "CRITICAL",
        "DELETE": "CRITICAL",
        "TRACE": "HIGH",
        "CONNECT": "CRITICAL",
    }

    # ── Directory listing keywords ─────────────────────────────────────
    DIR_LISTING_KEYWORDS: List[str] = [
        "Index of", "index of", "Directory listing",
        "<title>Index of", "Parent Directory",
        "[parent directory]",
        # NB : « .. » retiré, présent dans toute page (URLs relatives),
        # source de faux positifs de directory listing.
    ]

    # ── Public API ─────────────────────────────────────────────────────

    def run(self) -> CheckResult:
        """Execute all server security checks."""
        # 1) Web server detection
        server_header, server_info = self._get_server_header()
        self._detect_web_server(server_header, server_info)

        # 2) Server header version disclosure
        if server_header:
            self._check_version_disclosure(server_header)

        # 3) X-Powered-By header
        self._check_x_powered_by()

        # 4) Directory listing test
        self._check_directory_listing()

        # 5) HTTP methods allowed
        self._check_http_methods()

        # 6) ModSecurity / WAF detection
        self._check_waf()

        # 7) HTTP/2 detection
        self._check_http2()

        # 8) PHP detection
        self._check_php_detection()

        # 9) Compression info leakage
        self._check_compression_leakage()

        return self._result

    # ── 1) Web server detection ────────────────────────────────────────

    def _get_server_header(self) -> Tuple[str, dict]:
        """Fetch the Server header and extra response metadata.

        Returns (server_header_value, info_dict).
        """
        info: dict = {
            "headers": {},
            "cookies": "",
        }
        try:
            resp = self.http_head("")
            info["headers"] = dict(resp.headers)
            info["cookies"] = resp.headers.get("Set-Cookie", "")
            server_value = resp.headers.get("Server", "")
            return server_value, info
        except Exception:
            return "", info

    def _detect_web_server(self, server_header: str, info: dict) -> None:
        """Identify the web server from Server header and response clues."""
        server_lower = server_header.lower()
        evidence_parts: List[str] = []

        # Direct Server header detection
        if server_lower:
            evidence_parts.append(f"Server header: {server_header}")

        # Map known servers
        server_type = "Unknown"
        if "apache" in server_lower:
            server_type = "Apache HTTPD"
        elif "nginx" in server_lower:
            server_type = "Nginx"
        elif "litespeed" in server_lower or "openlitespeed" in server_lower:
            server_type = "LiteSpeed / OpenLiteSpeed"
        elif "microsoft-iis" in server_lower or "iis" in server_lower:
            server_type = "Microsoft IIS"
        elif "cloudflare" in server_lower:
            server_type = "Cloudflare (CDN, origin server masked)"
        elif server_lower == "":
            server_type = "Unknown (no Server header)"

        # Additional clues from other headers
        all_headers = info.get("headers", {})
        all_headers_lower = {k.lower(): v for k, v in all_headers.items()}

        # X-Powered-By clues
        x_powered_by = all_headers_lower.get("x-powered-by", "")
        if x_powered_by:
            if "asp.net" in x_powered_by.lower():
                server_type = f"{server_type} (X-Powered-By: {x_powered_by} → IIS/ASP.NET clue)"
            elif "php" in x_powered_by.lower():
                server_type = f"{server_type} (PHP backend detected)"

        # ASP.NET / IIS cookies
        set_cookie = info.get("cookies", "")
        if "aspsession" in set_cookie.lower() and "iis" not in server_type.lower():
            server_type = f"{server_type} (ASPSESSION cookie → IIS clue)"

        # x-litespeed-cache header
        if "x-litespeed-cache" in all_headers_lower:
            server_type = f"LiteSpeed (X-LiteSpeed-Cache header present)"

        evidence_parts.insert(0, f"Detected server: {server_type}")

        self._result.add_finding(
            message=f"Web server detected: {server_type}",
            severity="INFO",
            evidence="\n".join(evidence_parts),
            url=self.target,
        )

    # ── 2) Server header version disclosure ────────────────────────────

    def _check_version_disclosure(self, server_header: str) -> None:
        """Check if the Server header reveals version information (HIGH)."""
        # Look for version numbers in the Server header
        version_patterns = [
            r"/(\d+\.\d+(?:\.\d+)?)",          # Apache/2.4.6 or nginx/1.18.0
            r"/(\d+\.\d+)",                      # shorter version
        ]

        version_match = None
        for pattern in version_patterns:
            match = re.search(pattern, server_header)
            if match:
                version_match = match.group(0)
                break

        if version_match:
            # Check for OS information too (Ubuntu, Debian, etc.)
            os_match = re.search(r"\((.*?)\)", server_header)
            os_info = f" OS: {os_match.group(1)}" if os_match else ""

            self._result.add_finding(
                message=(
                    f"Server header discloses version{os_info}: "
                    f"'{server_header}' (HIGH)"
                ),
                severity="HIGH",
                evidence=(
                    f"Server header: {server_header}\n"
                    f"Version disclosed: {version_match}{os_info}\n"
                    f"Risk: Enables version-specific CVE targeting\n"
                    f"Recommendation: Set ServerTokens Prod (Apache) "
                    f"or server_tokens off; (Nginx)"
                ),
                url=self.target,
            )
        else:
            # Server header present but no version, still report as info
            self._result.add_finding(
                message=(
                    f"Server header present without version: "
                    f"'{server_header}' (INFO)"
                ),
                severity="INFO",
                evidence=(
                    f"Server header: {server_header}\n"
                    f"No version disclosed, moderate hardening applied"
                ),
                url=self.target,
            )

    # ── 3) X-Powered-By header ─────────────────────────────────────────

    def _check_x_powered_by(self) -> None:
        """Check if X-Powered-By header reveals PHP/ASP.NET version (MEDIUM)."""
        try:
            resp = self.http_head("")
        except Exception:
            return

        x_powered_by = resp.headers.get("X-Powered-By", "")
        if not x_powered_by:
            return

        # Check for version disclosure
        version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", x_powered_by)
        if version_match:
            self._result.add_finding(
                message=(
                    f"X-Powered-By header discloses "
                    f"version '{version_match.group(0)}': "
                    f"'{x_powered_by}' (MEDIUM)"
                ),
                severity="MEDIUM",
                evidence=(
                    f"X-Powered-By: {x_powered_by}\n"
                    f"Version disclosed: {version_match.group(0)}\n"
                    f"Risk: Enables version-specific vulnerability search\n"
                    f"Recommendation: Set expose_php = Off in php.ini"
                ),
                url=self.target,
            )
        else:
            self._result.add_finding(
                message=(
                    f"X-Powered-By header present (no version): "
                    f"'{x_powered_by}' (LOW)"
                ),
                severity="LOW",
                evidence=f"X-Powered-By: {x_powered_by}",
                url=self.target,
            )

    # ── 4) Directory listing test ──────────────────────────────────────

    def _check_directory_listing(self) -> None:
        """Test WordPress directories for directory listing (Index of)."""
        paths = list(self.DIR_LISTING_PATHS)
        if not self.config.get("authorized"):
            # Répertoires devinés (niveau 2) ; wp-admin/ reste (niveau 1).
            paths = [p for p in paths if self.may_request(p)]
            self.note_unlinked_skipped(
                "listings de répertoires (wp-content/, plugins/, themes/, "
                "uploads/, wp-includes/)")
        for path in paths:
            try:
                resp = self.http_get(path)
            except Exception:
                continue

            # Site soft-404 : 200 + home pour toute URL → pas un vrai listing.
            if self._is_soft404(resp):
                continue

            body = resp.text
            status = resp.status_code
            url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"

            # Un vrai autoindex est servi en 200 avec une signature explicite.
            has_listing = status == 200 and any(
                kw in body for kw in self.DIR_LISTING_KEYWORDS)

            if has_listing:
                # Determine severity based on path sensitivity
                severity = "HIGH"
                sensitive = any(
                    sensitive_path in path
                    for sensitive_path in ["uploads", "plugins", "themes", "wp-includes"]
                )

                self._result.add_finding(
                    message=(
                        f"Directory listing ENABLED on {path} "
                        f"({severity})"
                    ),
                    severity=severity,
                    evidence=(
                        f"Path: /{path}\n"
                        f"HTTP {status} | Size: {len(body)} bytes\n"
                        f"Directory listing keywords detected in response\n"
                        f"Snippet:\n{body[:500].strip()}"
                    ),
                    url=url,
                )
            elif status == 200 and len(body) < 100:
                # 200 + corps quasi vide = AUCUN listing de répertoire (index vide
                # ou fallback). C'est le comportement SÉCURISÉ attendu, pas une
                # exposition → INFO (observation), pas un finding LOW.
                self._result.add_finding(
                    message=(
                        f"Répertoire /{path} accessible (HTTP 200) mais sans "
                        f"listing ({len(body)} octets), pas d'exposition"
                    ),
                    severity="INFO",
                    evidence=(
                        f"Path: /{path}\n"
                        f"HTTP {status} | Size: {len(body)} bytes\n"
                        f"Corps quasi vide : aucun listing de répertoire n'est exposé."
                    ),
                    url=url,
                    confidence="confirmed",
                )
            elif status == 403:
                self._result.add_finding(
                    message=(
                        f"Directory {path} properly blocked "
                        f"(HTTP 403 Forbidden)"
                    ),
                    severity="INFO",
                    evidence=f"Path: /{path}\nHTTP 403 Forbidden, access denied",
                    url=url,
                )

    # ── 5) HTTP methods allowed ────────────────────────────────────────

    # Verbes HTTP mutants par sémantique : écrivent/suppriment une ressource
    # si le serveur les honore. Comme TRACE et CONNECT, ils ne sont JAMAIS
    # envoyés à la cible : le client HTTP de BaseCheck n'émet que GET, HEAD et
    # OPTIONS. La détection repose uniquement sur l'en-tête Allow d'OPTIONS.
    _WRITE_METHODS = frozenset({"PUT", "DELETE"})

    def _check_http_methods(self) -> None:
        """Méthodes HTTP annoncées par OPTIONS (en-tête Allow), passif.

        Aucune méthode dangereuse n'est émise : qu'elle soit réellement
        honorée reste non évaluable passivement (finding `potential`).
        """
        allowed_methods = set()
        try:
            options_resp = self.http_options("")
            allow_header = options_resp.headers.get("Allow", "")
            if allow_header:
                allowed_methods = {m.strip().upper() for m in allow_header.split(",")}
        except Exception:
            return

        if not allowed_methods:
            return

        # PUT/DELETE annoncées par OPTIONS : détection PASSIVE uniquement.
        write_methods_advertised = allowed_methods & self._WRITE_METHODS
        if write_methods_advertised:
            self._result.add_finding(
                message=(
                    "Méthodes HTTP dangereuses annoncées (PUT/DELETE), "
                    "écriture arbitraire à confirmer manuellement, non testée activement"
                ),
                severity="HIGH",
                evidence=(
                    f"Allow: {', '.join(sorted(allowed_methods))}\n"
                    f"Méthodes d'écriture annoncées: "
                    f"{', '.join(sorted(write_methods_advertised))}\n"
                    "Aucune requête PUT/DELETE active n'a été envoyée à la cible "
                    "(détection passive uniquement)."
                ),
                url=self.target,
                confidence="potential",
            )

        # Autres méthodes dangereuses annoncées par OPTIONS (TRACE/CONNECT).
        other_dangerous_advertised = (
            allowed_methods & set(self.DANGEROUS_METHODS.keys())
        ) - write_methods_advertised
        if other_dangerous_advertised:
            self._result.add_finding(
                message=("OPTIONS advertises dangerous methods: "
                         f"{', '.join(sorted(other_dangerous_advertised))}"),
                severity="MEDIUM",
                evidence=(
                    f"Allow: {', '.join(sorted(allowed_methods))}\n"
                    "Méthodes non émises (lecture seule) : leur prise en charge "
                    "réelle n'est pas évaluable passivement."
                ),
                url=self.target,
                confidence="potential",
            )

    # ── 6) ModSecurity / WAF detection ─────────────────────────────────

    def _check_waf(self) -> None:
        """Détecte ModSecurity / un WAF via les en-têtes d'une réponse normale.

        Aucune charge d'attaque n'est envoyée pour provoquer un blocage : une
        absence d'indicateur ne prouve donc pas l'absence de WAF.
        """
        # Step 1: Check response headers for WAF indicators
        waf_detected = False
        waf_evidence: List[str] = []

        try:
            resp = self.http_head("")
            header_keys_lower = {k.lower(): v for k, v in resp.headers.items()}

            # Check for ModSecurity headers
            modsec_headers = ["x-mod-security", "x-modsec", "mod_security"]
            for h in modsec_headers:
                if h in header_keys_lower:
                    waf_detected = True
                    waf_evidence.append(
                        f"WAF header found: {h}: {header_keys_lower[h]}"
                    )

            # Check for generic WAF markers
            sec_headers = [k for k in header_keys_lower if k.startswith("x-sec")]
            for h in sec_headers:
                if h not in ("x-served-by", "x-seen-by"):
                    waf_detected = True
                    waf_evidence.append(
                        f"Security header found: {h}: {header_keys_lower[h]}"
                    )
        except Exception:
            pass

        if waf_detected:
            evidence_text = "\n".join(waf_evidence)
            self._result.add_finding(
                message=(
                    "ModSecurity / WAF detected on target "
                    "(INFO, WAF presence is good)"
                ),
                severity="INFO",
                evidence=(
                    f"WAF detection indicators:\n{evidence_text}\n\n"
                    f"Note: WAF presence is positive, "
                    f"it provides an additional security layer"
                ),
                url=self.target,
            )
        else:
            self._result.add_finding(
                message=(
                    "Aucun WAF identifié par les en-têtes (détection passive, "
                    "non concluante)"
                ),
                severity="INFO",
                evidence=(
                    "Aucun en-tête de WAF (x-mod-security, x-sec*) sur une "
                    "réponse normale. Le scanner n'envoie aucune charge "
                    "d'attaque pour déclencher un blocage : la présence d'un "
                    "WAF n'est pas évaluable passivement au-delà des en-têtes."
                ),
                url=self.target,
            )

    # ── 7) HTTP/2 detection ────────────────────────────────────────────

    def _check_http2(self) -> None:
        """Check if the server supports HTTP/2 (good, modern protocol)."""
        http2_supported = False
        http1_only = False

        # Try HTTP/2 via the session (if requests supports it via urllib3)
        try:
            # First do a normal request to see what's available
            resp = self.http_get("")
            http_version = getattr(resp, "raw", None)
            if http_version is not None:
                version_str = getattr(http_version, "version", None)
                if version_str == 20:  # HTTP/2
                    http2_supported = True
        except Exception:
            pass

        # Pas de tentative d'Upgrade h2c (bascule de protocole demandée à la
        # cible) : la négociation ALPN ci-dessous suffit à détecter HTTP/2.

        # Try with explicit http2 via urllib3 if possible
        # Fallback: check via openssl if available
        import subprocess
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.target)
            hostname = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            proc = subprocess.run(
                [
                    "openssl", "s_client", "-alpn", "h2,http/1.1",
                    "-connect", f"{hostname}:{port}",
                    "-servername", hostname,
                ],
                input=b"\n",
                capture_output=True,
                timeout=10,
            )
            output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
            if "alpn protocol: h2" in output.lower() or "ALPN, server accepted to use h2" in output:
                http2_supported = True
            elif "alpn protocol: http/1.1" in output.lower():
                http1_only = True
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        if http2_supported:
            self._result.add_finding(
                message=(
                    "HTTP/2 is supported by the server "
                    "(INFO, modern, efficient protocol)"
                ),
                severity="INFO",
                evidence=(
                    "HTTP/2 supported via ALPN handshake (h2)\n"
                    "HTTP/2 is a modern, efficient protocol with "
                    "no additional security risk over HTTP/1.1\n"
                    "Recommendation: Ensure HTTP/1.1 is also "
                    "available for compatibility"
                ),
                url=self.target,
            )
        else:
            self._result.add_finding(
                message=(
                    "HTTP/2 is NOT supported, "
                    "server uses HTTP/1.1 only (LOW)"
                ),
                severity="LOW",
                evidence=(
                    "Server does not advertise HTTP/2 support\n"
                    "Recommendation: Enable HTTP/2 for performance "
                    "improvements (but not a security vulnerability)"
                ),
                url=self.target,
            )

    # ── 8) PHP detection ───────────────────────────────────────────────

    def _check_php_detection(self) -> None:
        """Detect PHP usage via headers and extension probing."""
        php_detected = False
        version_disclosed = False
        php_version = ""
        evidence_parts: List[str] = []

        # Method 1: X-Powered-By header (already checked in check #3,
        # but we look for it specifically here too)
        try:
            resp = self.http_head("")
            x_powered_by = resp.headers.get("X-Powered-By", "")
            if x_powered_by:
                php_detected = True
                evidence_parts.append(f"X-Powered-By header: {x_powered_by}")
                if "php" in x_powered_by.lower():
                    version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", x_powered_by)
                    if version_match:
                        version_disclosed = True
                        php_version = version_match.group(0)
        except Exception:
            pass

        # Method 2: Probe for .php extension handling
        php_probes = [
            "index.php",
            "wp-login.php",
            "xmlrpc.php",
        ]
        for probe in php_probes:
            try:
                resp = self.http_head(probe)
                if resp.status_code in (200, 301, 302, 401, 403):
                    if not php_detected:
                        php_detected = True
                        evidence_parts.append(
                            f"PHP file '{probe}' → HTTP {resp.status_code}"
                        )
            except Exception:
                continue

        # Report findings
        if php_detected:
            message = "PHP detected on server"
            if version_disclosed:
                message += f" (PHP version {php_version} disclosed via headers)"
            else:
                message += " (no version disclosure)"

            severity = "MEDIUM" if version_disclosed else "INFO"

            self._result.add_finding(
                message=message,
                severity=severity,
                evidence="\n".join(evidence_parts) if evidence_parts else "PHP detected via extension probing",
                url=self.target,
            )
        else:
            self._result.add_finding(
                message=(
                    "PHP not conclusively detected "
                    "(INFO, may be static site or PHP headers hidden)"
                ),
                severity="INFO",
                evidence=(
                    "No X-Powered-By header found\n"
                    "No .php files returned non-404 status\n"
                ),
                url=self.target,
            )

    # ── 9) Compression info leakage ────────────────────────────────────

    def _check_compression_leakage(self) -> None:
        """Check compression support and timing-based information leakage."""
        encodings_tested: Dict[str, dict] = {}
        encoding_labels = {
            "gzip": "gzip",
            "deflate": "deflate",
            "br": "brotli",
            "identity": "no compression (identity)",
        }

        # Test each encoding
        for encoding, label in encoding_labels.items():
            try:
                start = time.time()
                resp = self.http_get(
                    "",
                    headers={"Accept-Encoding": encoding},
                )
                elapsed = time.time() - start

                content_encoding = resp.headers.get("Content-Encoding", "")
                content_length = resp.headers.get("Content-Length", str(len(resp.text)))

                encodings_tested[encoding] = {
                    "label": label,
                    "content_encoding": content_encoding,
                    "content_length": int(content_length) if content_length.isdigit() else len(resp.text),
                    "time": elapsed,
                    "status": resp.status_code,
                }
            except Exception:
                continue

        # Report compression support
        supported_encodings = [
            e for e, data in encodings_tested.items()
            if data.get("content_encoding") and e != "identity"
        ]

        if supported_encodings:
            encoding_names = ", ".join(
                encoding_labels.get(e, e) for e in supported_encodings
            )
            evidence_parts = ["Compression support:", ""]
            for enc, data in encodings_tested.items():
                status = "✓ supported" if data["content_encoding"] else "- not returned"
                evidence_parts.append(
                    f"  {data['label']:25s} → {status:20s} "
                    f"({data['content_length']} bytes, "
                    f"{data['time']:.3f}s)"
                )

            # Check for timing-based leakage: compare identity vs compressed
            identity_data = encodings_tested.get("identity", {})
            identity_time = identity_data.get("time", 0)

            timing_diff_found = False
            for enc, data in encodings_tested.items():
                if enc != "identity" and data.get("content_encoding"):
                    compressed_time = data["time"]
                    if identity_time > 0 and compressed_time > 0:
                        ratio = compressed_time / identity_time if identity_time > 0 else 0
                        if ratio < 0.5 or ratio > 1.5:
                            timing_diff_found = True
                            break

            if timing_diff_found:
                evidence_parts.append(
                    "\nNote: Response time differs significantly between "
                    "compressed and uncompressed requests, possible "
                    "timing side-channel leakage"
                )

            self._result.add_finding(
                message=(
                    f"Compression enabled: {encoding_names} "
                    f"(INFO, standard, expected)"
                ),
                severity="INFO",
                evidence="\n".join(evidence_parts),
                url=self.target,
            )
        else:
            self._result.add_finding(
                message=(
                    "No compression detected (LOW, "
                    "potentially slower, not vulnerable)"
                ),
                severity="LOW",
                evidence=(
                    "No Content-Encoding returned for any "
                    "Accept-Encoding header\n"
                    "Server may not support compression, "
                    "acceptable from a security standpoint"
                ),
                url=self.target,
            )
