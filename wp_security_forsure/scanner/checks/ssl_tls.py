"""Check for SSL/TLS configuration weaknesses on the target.

Inherits from BaseCheck. Covers:
  1) Certificate validation, expiration, issuer, subject, SAN
  2) Protocol versions, TLS 1.0 (HIGH), TLS 1.1 (HIGH), TLS 1.2, TLS 1.3
  3) Cipher suites, weak ciphers (CRITICAL), Perfect Forward Secrecy
  4) HSTS, Strict-Transport-Security header: max-age, includeSubDomains, preload
  5) Mixed content, HTTP resources loaded on HTTPS pages (HIGH)
  6) OCSP stapling, via openssl s_client -status
  7) HTTP/2 support, ALPN check via openssl or curl
"""

import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from .base import BaseCheck, CheckResult


class SSLTLSChannel(BaseCheck):
    """Check SSL/TLS configuration of the target."""

    name = "ssl_tls"
    title = "SSL/TLS Configuration Audit"
    description = (
        "Checks SSL/TLS certificate validity, protocol versions, cipher suites, "
        "HSTS configuration, mixed content, OCSP stapling, and HTTP/2 support."
    )
    severity = "CRITICAL"
    access_tier = 0  # accueil et poignée de main TLS
    depends_on: List[str] = []

    # ── Weak cipher groups to test ──────────────────────────────────────

    _WEAK_CIPHERS = {
        "NULL": "CRITICAL",
        "aNULL": "CRITICAL",
        "EXPORT": "CRITICAL",
        "RC4": "CRITICAL",
        "DES": "CRITICAL",
        "3DES": "CRITICAL",
    }

    # ── Protocol version flags ──────────────────────────────────────────

    _PROTOCOLS = [
        ("TLS 1.3", "-tls1_3", "OK"),
        ("TLS 1.2", "-tls1_2", "OK"),
        ("TLS 1.1", "-tls1_1", "HIGH"),
        ("TLS 1.0", "-tls1", "HIGH"),
    ]

    # ── Public API ──────────────────────────────────────────────────────

    def __init__(self, target: str, config: dict, session):
        super().__init__(target, config, session)

    def run(self) -> CheckResult:
        """Execute all SSL/TLS checks."""
        hostname = self._extract_hostname(self.target)
        port = self._extract_port(self.target)

        # Les sous-checks cert/protocoles/ciphers/OCSP dépendent d'openssl,
        # absent d'un Windows standard. On les saute proprement plutôt que
        # d'émettre ~15 findings dupliqués et de faux "TLS non supporté".
        if shutil.which("openssl"):
            cert_info = self._get_certificate_info(hostname, port)
            self._check_certificate_validity(cert_info, hostname)
            self._check_san(cert_info, hostname)
            self._check_protocol_versions(hostname, port)
            self._check_weak_ciphers(hostname, port)
            self._check_pfs(hostname, port)
            self._check_ocsp_stapling(hostname, port)
        else:
            self._result.add_finding(
                message="Audit SSL/TLS partiel, OpenSSL absent du système",
                severity="INFO",
                evidence=(
                    "Certificat, versions TLS, ciphers et OCSP non testés "
                    "(binaire openssl introuvable dans le PATH). "
                    "HSTS, mixed content et HTTP/2 restent vérifiés."
                ),
                url=self.target,
            )

        # Vérifs basées sur requests/curl, fonctionnent sans openssl.
        self._check_hsts()
        self._check_mixed_content()
        self._check_http2(hostname, port)

        return self._result

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _extract_hostname(target: str) -> str:
        """Extract hostname from target URL (e.g. https://example.com/path)."""
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        # Strip port if present
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        return hostname

    @staticmethod
    def _extract_port(target: str) -> int:
        """Extract port from target URL, defaulting to 443 for HTTPS."""
        parsed = urlparse(target)
        if parsed.port:
            return parsed.port
        scheme = parsed.scheme or "https"
        return 443 if scheme == "https" else 80

    def _run_openssl(self, hostname: str, port: int,
                     extra_args: Optional[List[str]] = None,
                     timeout: int = 15) -> str:
        """Run openssl s_client and return combined stdout+stderr."""
        cmd = [
            "openssl", "s_client",
            "-connect", f"{hostname}:{port}",
            "-servername", hostname,
        ]
        if extra_args:
            cmd.extend(extra_args)

        try:
            proc = subprocess.run(
                cmd,
                input=b"\n",
                capture_output=True,
                timeout=timeout,
            )
            return (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
        except FileNotFoundError:
            self._result.add_finding(
                message="OpenSSL not found on system",
                severity="MEDIUM",
                evidence="openssl binary is not available, SSL/TLS checks limited",
            )
            return ""
        except subprocess.TimeoutExpired:
            return ""
        except Exception as exc:
            return f"Error: {exc}"

    def _get_certificate_info(self, hostname: str, port: int) -> dict:
        """Fetch certificate details via openssl."""
        info: dict = {
            "not_before": None,
            "not_after": None,
            "issuer": "",
            "subject": "",
            "san": [],
            "raw": "",
        }

        output = self._run_openssl(hostname, port)
        if not output or "BEGIN CERTIFICATE" not in output:
            return info

        info["raw"] = output

        # Pipe cert through openssl x509 for parsing
        try:
            proc = subprocess.run(
                ["openssl", "x509", "-noout", "-dates", "-issuer", "-subject"],
                input=output.encode(),
                capture_output=True,
                timeout=10,
            )
            x509_out = proc.stdout.decode("utf-8", errors="replace")
        except Exception:
            return info

        # Parse notBefore / notAfter
        for line in x509_out.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith("notBefore="):
                info["not_before"] = line_stripped[len("notBefore="):]
            elif line_stripped.startswith("notAfter="):
                info["not_after"] = line_stripped[len("notAfter="):]
            elif line_stripped.startswith("issuer="):
                info["issuer"] = line_stripped[len("issuer="):]
            elif line_stripped.startswith("subject="):
                info["subject"] = line_stripped[len("subject="):]

        # Parse SAN
        try:
            san_proc = subprocess.run(
                ["openssl", "x509", "-noout", "-ext", "subjectAltName"],
                input=output.encode(),
                capture_output=True,
                timeout=10,
            )
            san_text = san_proc.stdout.decode("utf-8", errors="replace")
            # Extract DNS: entries
            for match in re.finditer(r"DNS:([^\s,]+)", san_text):
                info["san"].append(match.group(1))
        except Exception:
            pass

        return info

    # ── 1) Certificate validation ───────────────────────────────────────

    def _check_certificate_validity(self, cert_info: dict, hostname: str) -> None:
        """Check certificate expiration, issuer, and subject."""
        not_after_str = cert_info.get("not_after")
        if not not_after_str:
            self._result.add_finding(
                message="Could not retrieve certificate expiration date",
                severity="MEDIUM",
                evidence="openssl x509 did not return notAfter date",
                url=self.target,
            )
            return

        # Parse the date, openssl typically outputs like "notAfter=Dec 20 23:59:59 2025 GMT"
        try:
            expiry_dt = datetime.strptime(not_after_str.strip(), "%b %d %H:%M:%S %Y %Z")
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                # Alternative format: "notAfter=20251220120000Z"
                expiry_dt = datetime.strptime(not_after_str.strip(), "%Y%m%d%H%M%SZ")
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                self._result.add_finding(
                    message="Could not parse certificate expiration date",
                    severity="MEDIUM",
                    evidence=f"Unparseable date: {not_after_str}",
                    url=self.target,
                )
                return

        now = datetime.now(timezone.utc)
        days_left = (expiry_dt - now).days

        if days_left < 0:
            self._result.add_finding(
                message=f"Certificate EXPIRED {abs(days_left)} days ago",
                severity="CRITICAL",
                evidence=(
                    f"Expired on: {expiry_dt.strftime('%Y-%m-%d')}\n"
                    f"Days since expiry: {abs(days_left)}\n"
                    f"Issuer: {cert_info.get('issuer', 'N/A')}\n"
                    f"Subject: {cert_info.get('subject', 'N/A')}"
                ),
                url=self.target,
            )
        elif days_left <= 7:
            self._result.add_finding(
                message=f"Certificate expires in {days_left} days, critical renewal needed",
                severity="CRITICAL",
                evidence=(
                    f"Expires on: {expiry_dt.strftime('%Y-%m-%d')}\n"
                    f"Days remaining: {days_left}\n"
                    f"Issuer: {cert_info.get('issuer', 'N/A')}\n"
                    f"Subject: {cert_info.get('subject', 'N/A')}"
                ),
                url=self.target,
            )
        elif days_left <= 30:
            self._result.add_finding(
                message=f"Certificate expires in {days_left} days, renewal recommended",
                severity="HIGH",
                evidence=(
                    f"Expires on: {expiry_dt.strftime('%Y-%m-%d')}\n"
                    f"Days remaining: {days_left}\n"
                    f"Issuer: {cert_info.get('issuer', 'N/A')}\n"
                    f"Subject: {cert_info.get('subject', 'N/A')}"
                ),
                url=self.target,
            )
        elif days_left <= 60:
            self._result.add_finding(
                message=f"Certificate expires in {days_left} days",
                severity="MEDIUM",
                evidence=(
                    f"Expires on: {expiry_dt.strftime('%Y-%m-%d')}\n"
                    f"Days remaining: {days_left}\n"
                    f"Issuer: {cert_info.get('issuer', 'N/A')}\n"
                    f"Subject: {cert_info.get('subject', 'N/A')}"
                ),
                url=self.target,
            )

        # Check issuer, flag self-signed or unusual issuers
        issuer = cert_info.get("issuer", "")
        subject = cert_info.get("subject", "")
        if issuer and subject and issuer == subject:
            self._result.add_finding(
                message="Certificate appears to be self-signed (issuer == subject)",
                severity="HIGH",
                evidence=f"Issuer: {issuer}\nSubject: {subject}",
                url=self.target,
            )

    def _check_san(self, cert_info: dict, hostname: str) -> None:
        """Check that the target hostname is covered by the SAN list."""
        san_list = cert_info.get("san", [])
        if not san_list:
            self._result.add_finding(
                message="No Subject Alternative Names (SAN) found on certificate",
                severity="MEDIUM",
                evidence="Certificate has no SAN entries, may not be trusted by modern browsers",
                url=self.target,
            )
            return

        # Check if hostname is covered (with wildcard support)
        covered = False
        for san_entry in san_list:
            if san_entry == hostname:
                covered = True
                break
            # Wildcard match: *.example.com covers sub.example.com
            if san_entry.startswith("*."):
                wildcard_domain = san_entry[2:]  # remove "*."
                if hostname.endswith("." + wildcard_domain) or hostname == wildcard_domain:
                    covered = True
                    break

        if not covered:
            self._result.add_finding(
                message=f"Hostname '{hostname}' not found in certificate SAN list",
                severity="CRITICAL",
                evidence=f"SAN entries: {', '.join(san_list)}\nTarget: {hostname}",
                url=self.target,
            )

    # ── 2) Protocol versions ────────────────────────────────────────────

    def _check_protocol_versions(self, hostname: str, port: int) -> None:
        """Test support for TLS 1.0 through 1.3."""
        for proto_name, flag, severity_when_enabled in self._PROTOCOLS:
            extra = [flag]
            if proto_name in ("TLS 1.0", "TLS 1.1"):
                # OpenSSL 3 ne propose TLS 1.0 et 1.1 qu'au niveau de sécurité 0 :
                # sans ce réglage, le test n'atteint jamais le serveur.
                extra += ["-cipher", "DEFAULT@SECLEVEL=0"]
            output = self._run_openssl(hostname, port, extra_args=extra)

            # Handshake réussi = un cipher réellement négocié. Un refus du
            # serveur affiche aussi « Cipher is (NONE) » : la seule présence de
            # « Cipher is » signalait TLS 1.0 et 1.1 actifs sur un serveur qui
            # les refuse (faux HIGH du premier audit réel).
            handshake_ok = (self._negotiated_cipher(output) is not None
                            or ("BEGIN CERTIFICATE" in output
                                and "Cipher is (NONE)" not in output))
            not_supported = bool(
                "handshake failure" in output
                or "SSL_ERROR" in output
                or "no protocols available" in output
                or "no supported" in output.lower()
            )

            if proto_name in ("TLS 1.2", "TLS 1.3"):
                if handshake_ok:
                    self._result.add_finding(
                        message=f"{proto_name} supported",
                        severity="INFO",
                        evidence=f"{proto_name} handshake succeeded",
                        url=self.target,
                    )
                elif output and not not_supported:
                    # output vide = openssl local n'a pas pu tester (option
                    # inconnue, timeout) → indéterminé, on n'affirme rien.
                    self._result.add_finding(
                        message=f"{proto_name} not supported",
                        severity="MEDIUM",
                        evidence=f"{proto_name} handshake did not succeed",
                        url=self.target,
                    )
            else:
                # TLS 1.0 and 1.1, they should NOT be enabled
                if "no protocols available" in output:
                    # L'openssl local refuse de proposer ce protocole (niveau de
                    # sécurité d'OpenSSL 3) : rien n'est envoyé, rien n'est su.
                    self._result.add_finding(
                        message=(f"{proto_name} non testable : l'openssl local refuse "
                                 "de proposer ce protocole"),
                        severity="INFO",
                        evidence=("openssl s_client répond « no protocols available » "
                                  "avant tout échange avec le serveur. Tester avec un "
                                  "outil qui propose encore ce protocole (par exemple "
                                  "openssl avec -cipher 'DEFAULT@SECLEVEL=0')."),
                        url=self.target,
                        confidence="potential",
                    )
                elif handshake_ok:
                    self._result.add_finding(
                        message=f"{proto_name} is ENABLED (deprecated protocol)",
                        severity=severity_when_enabled,
                        evidence=f"{proto_name} handshake succeeded, should be disabled per RFC 8996",
                        url=self.target,
                    )

    # ── 3) Cipher suites ───────────────────────────────────────────────

    @staticmethod
    def _negotiated_cipher(output: str) -> Optional[str]:
        """Cipher réellement négocié par openssl, ou None si handshake échoué.

        openssl écrit une ligne canonique « New, <proto>, Cipher is <X> ».
        Un handshake sans cipher donne « Cipher is (NONE) » (avec parenthèses) :
        c'est le cas de rejet (bon), à ne PAS confondre avec un cipher accepté.
        """
        m = re.search(r"New,\s*[^,]+,\s*Cipher is\s+(\S+)", output)
        if not m:
            return None
        value = m.group(1).strip()
        if "NONE" in value.upper() or value in ("0000", "(NONE)"):
            return None
        return value

    @staticmethod
    def _cipher_in_family(family: str, cipher: str) -> bool:
        """True si le cipher négocié appartient bien à la famille faible testée.

        Confirmation indispensable : `-cipher NULL` peut, sans borne de version,
        laisser négocier un cipher fort, il ne faut alors rien signaler.
        """
        c = cipher.upper()
        if family == "NULL":
            return "NULL" in c
        if family == "aNULL":  # anonyme : pas d'authentification
            return c.startswith(("ADH", "AECDH")) or "ANON" in c
        if family == "EXPORT":
            return "EXP" in c
        if family == "RC4":
            return "RC4" in c
        if family == "3DES":
            return "3DES" in c or "DES-CBC3" in c
        if family == "DES":
            return "DES" in c and "3DES" not in c and "DES-CBC3" not in c
        return family.upper() in c

    def _check_weak_ciphers(self, hostname: str, port: int) -> None:
        """Test for weak/obsolete cipher suites (TLS ≤ 1.2 uniquement).

        On force `-no_tls1_3` : sinon TLS 1.3 négocie toujours un ciphersuite
        fort et masque le vrai test. On ne signale que si le cipher réellement
        négocié appartient à la famille faible demandée (zéro faux positif).
        """
        for cipher_name, severity in self._WEAK_CIPHERS.items():
            output = self._run_openssl(
                hostname, port,
                extra_args=["-cipher", cipher_name, "-no_tls1_3"],
            )

            negotiated = self._negotiated_cipher(output)
            if not negotiated:
                continue  # cipher faible rejeté = configuration saine
            if not self._cipher_in_family(cipher_name, negotiated):
                continue  # handshake abouti mais avec un cipher fort → pas un faux positif

            self._result.add_finding(
                message=f"Weak cipher group '{cipher_name}' accepted (negotiated {negotiated})",
                severity=severity,
                evidence=(
                    f"Cipher group tested: {cipher_name}\n"
                    f"Cipher negotiated: {negotiated}\n"
                    f"Risk: {'No encryption' if cipher_name == 'NULL' else 'No authentication' if cipher_name == 'aNULL' else 'Trivially breakable' if cipher_name == 'EXPORT' else 'Known attacks / obsolete'}"
                ),
                url=self.target,
            )

    def _check_pfs(self, hostname: str, port: int) -> None:
        """Check for Perfect Forward Secrecy (ECDHE/DHE ou TLS 1.3).

        On force `-no_tls1_3` pour tester réellement ECDHE/DHE en TLS ≤ 1.2, et
        on lit le cipher RÉELLEMENT négocié via `_negotiated_cipher` (qui gère
        « (NONE) »). Un handshake rejeté ne doit jamais être lu comme « PFS OK ».
        """
        ecdhe_output = self._run_openssl(
            hostname, port, extra_args=["-cipher", "ECDHE", "-no_tls1_3"])
        ecdhe_cipher = self._negotiated_cipher(ecdhe_output)
        if ecdhe_cipher and "ECDHE" in ecdhe_cipher.upper():
            self._result.add_finding(
                message="Perfect Forward Secrecy (PFS) supported via ECDHE",
                severity="INFO",
                evidence=f"ECDHE cipher negotiated: {ecdhe_cipher}",
                url=self.target,
            )
            return

        dhe_output = self._run_openssl(
            hostname, port, extra_args=["-cipher", "DHE", "-no_tls1_3"])
        dhe_cipher = self._negotiated_cipher(dhe_output)
        if dhe_cipher and "DHE" in dhe_cipher.upper():
            self._result.add_finding(
                message="Perfect Forward Secrecy (PFS) supported via DHE",
                severity="INFO",
                evidence=f"DHE cipher negotiated: {dhe_cipher}",
                url=self.target,
            )
            return

        # TLS 1.3 assure toujours la PFS (clés éphémères), à vérifier avant
        # de conclure à une absence de PFS.
        tls13_cipher = self._negotiated_cipher(self._run_openssl(hostname, port))
        if tls13_cipher and tls13_cipher.upper().startswith("TLS_"):
            self._result.add_finding(
                message="Perfect Forward Secrecy (PFS) supported via TLS 1.3",
                severity="INFO",
                evidence=f"TLS 1.3 cipher negotiated: {tls13_cipher}",
                url=self.target,
            )
            return

        # Aucun cipher éphémère : si une connexion TLS ≤ 1.2 aboutit tout de même
        # avec un échange de clé statique, il n'y a pas de PFS.
        base_cipher = self._negotiated_cipher(
            self._run_openssl(hostname, port, extra_args=["-no_tls1_3"]))
        if base_cipher:
            self._result.add_finding(
                message="No Perfect Forward Secrecy (PFS), static key exchange only",
                severity="HIGH",
                evidence=(
                    f"No ECDHE/DHE/TLS1.3 cipher negotiated\n"
                    f"Default cipher: {base_cipher}\n"
                    f"Impact: If private key is compromised, past sessions can be decrypted"
                ),
                url=self.target,
            )

    # ── 4) HSTS ─────────────────────────────────────────────────────────

    def _check_hsts(self) -> None:
        """Check Strict-Transport-Security header."""
        try:
            resp = self.http_head("")
        except Exception:
            # Fallback: try GET if HEAD fails
            try:
                resp = self.http_get("")
            except Exception as exc:
                self._result.add_finding(
                    message="Could not check HSTS, connection failed",
                    severity="MEDIUM",
                    evidence=f"Error: {exc}",
                    url=self.target,
                )
                return

        hsts_header = resp.headers.get("Strict-Transport-Security", "")

        if not hsts_header:
            self._result.add_finding(
                message="HSTS (Strict-Transport-Security) header is MISSING",
                severity="HIGH",
                evidence=(
                    "No Strict-Transport-Security header found in response.\n"
                    "Risk: Users may be vulnerable to SSL stripping attacks (e.g. SSLstrip).\n"
                    "Recommendation: Set: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
                ),
                url=self.target,
            )
            return

        # Parse directives
        max_age_match = re.search(r"max-age=(\d+)", hsts_header, re.IGNORECASE)
        has_include_subdomains = "includesubdomains" in hsts_header.lower()

        # Evaluate max-age
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age == 0:
                self._result.add_finding(
                    message="HSTS max-age is 0, HSTS effectively disabled",
                    severity="HIGH",
                    evidence=f"max-age=0 detected\nFull header: {hsts_header}",
                    url=self.target,
                )
            elif max_age < 86400:  # < 1 day
                self._result.add_finding(
                    message=f"HSTS max-age too short ({max_age}s, less than 1 day)",
                    severity="MEDIUM",
                    evidence=f"max-age={max_age}\nFull header: {hsts_header}",
                    url=self.target,
                )
            elif max_age < 2592000:  # < 30 days
                self._result.add_finding(
                    message=f"HSTS max-age below recommended minimum ({max_age}s, < 30 days)",
                    severity="LOW",
                    evidence=f"max-age={max_age}\nFull header: {hsts_header}",
                    url=self.target,
                )
        else:
            self._result.add_finding(
                message="HSTS header present but missing max-age directive",
                severity="HIGH",
                evidence=f"Header: {hsts_header}",
                url=self.target,
            )

        # includeSubDomains
        if not has_include_subdomains:
            self._result.add_finding(
                message="HSTS missing includeSubDomains directive",
                severity="MEDIUM",
                evidence=(
                    f"HSTS header: {hsts_header}\n"
                    "includeSubDomains not set, subdomains are not protected"
                ),
                url=self.target,
            )

    # ── 5) Mixed content ───────────────────────────────────────────────

    def _check_mixed_content(self) -> None:
        """Check if the HTTPS page loads HTTP resources (mixed content)."""
        try:
            resp = self.http_get("/")
        except Exception as exc:
            self._result.add_finding(
                message="Could not check mixed content, homepage fetch failed",
                severity="MEDIUM",
                evidence=f"Error: {exc}",
                url=self.target,
            )
            return

        html = resp.text

        # Find http:// resource URLs in common HTML attributes
        # src="http://...", href="http://...", srcset="http://..."
        http_urls = set()

        # Sous-ressources chargées en HTTP sur une page HTTPS = mixed content.
        # NB : le href d'une balise <a> est un simple lien hypertexte, PAS du
        # mixed content, on ne matche donc que les attributs de sous-ressources.
        for match in re.finditer(
            r'(?:src|srcset|data-src|poster)="(http://[^"]+)"',
            html,
            re.IGNORECASE,
        ):
            http_urls.add(match.group(1))
        # Feuilles de style / préchargements : <link ... href="http://...">
        for match in re.finditer(
            r'<link\b[^>]*?\bhref="(http://[^"]+)"',
            html,
            re.IGNORECASE,
        ):
            http_urls.add(match.group(1))

        # Also check inline styles with url(http://...)
        for match in re.finditer(
            r"url\(['\"]?(http://[^)'\"]+)['\"]?\)",
            html,
            re.IGNORECASE,
        ):
            http_urls.add(match.group(1))

        if http_urls:
            sorted_urls = sorted(http_urls)
            evidence_lines = [
                f"Found {len(sorted_urls)} HTTP resource(s) on HTTPS page:",
            ]
            # Show first 20 for evidence
            for url in sorted_urls[:20]:
                evidence_lines.append(f"  - {url}")
            if len(sorted_urls) > 20:
                evidence_lines.append(f"  ... and {len(sorted_urls) - 20} more")

            self._result.add_finding(
                message=f"Mixed content detected, {len(sorted_urls)} HTTP resource(s) loaded on HTTPS page",
                severity="HIGH",
                evidence="\n".join(evidence_lines),
                url=self.target,
            )

        # Check Content-Security-Policy for upgrade-insecure-requests
        csp = resp.headers.get("Content-Security-Policy", "")
        if csp and "upgrade-insecure-requests" in csp.lower():
            self._result.add_finding(
                message="Content-Security-Policy includes upgrade-insecure-requests (mitigates mixed content)",
                severity="INFO",
                evidence=f"CSP: {csp}",
                url=self.target,
            )

    # ── 6) OCSP stapling ────────────────────────────────────────────────

    @staticmethod
    def _certificate_ocsp_uri(output: str) -> Optional[str]:
        """URL OCSP du certificat présenté dans une sortie d'openssl s_client :
        "" si le certificat n'en publie aucune, None si elle n'est pas lisible
        (certificat absent de la sortie, openssl indisponible)."""
        m = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
                      output or "", re.S)
        if not m:
            return None
        try:
            proc = subprocess.run(["openssl", "x509", "-noout", "-ocsp_uri"],
                                  input=m.group(0), capture_output=True, text=True,
                                  timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.strip()

    def _check_ocsp_stapling(self, hostname: str, port: int) -> None:
        """Check if OCSP stapling is enabled."""
        output = self._run_openssl(
            hostname, port,
            extra_args=["-status"],
        )

        if not output:
            return

        # Check for OCSP response
        if "OCSP Response Status: successful" in output:
            # Extract response details
            ocsp_section = ""
            in_ocsp = False
            for line in output.splitlines():
                if "OCSP response" in line or "OCSP Response" in line:
                    in_ocsp = True
                if in_ocsp:
                    ocsp_section += line + "\n"
                    if line.strip().startswith("---") and "OCSP" not in ocsp_section:
                        break

            # Check nextUpdate
            next_update_match = re.search(r"nextUpdate:\s*(.+)", output)
            next_update_str = next_update_match.group(1) if next_update_match else "unknown"

            # Check cert status
            cert_status = "good"
            if "Cert Status: good" in output:
                cert_status = "good"
            elif "Cert Status: revoked" in output:
                cert_status = "revoked"

            if cert_status == "revoked":
                self._result.add_finding(
                    message="OCSP stapling indicates certificate is REVOKED",
                    severity="CRITICAL",
                    evidence=f"OCSP Status: revoked\nnextUpdate: {next_update_str}\n\nOCSP section:\n{ocsp_section[:500]}",
                    url=self.target,
                )
            else:
                self._result.add_finding(
                    message="OCSP stapling is enabled and working",
                    severity="INFO",
                    evidence=f"OCSP Response Status: successful\nCert Status: {cert_status}\nnextUpdate: {next_update_str}",
                    url=self.target,
                )

        elif ("OCSP response: no response sent" in output
              and self._certificate_ocsp_uri(output) == ""):
            # Certificat sans URL OCSP : rien à agrafer. Let's Encrypt a retiré
            # OCSP de ses certificats en mai 2025 et fermé ses répondeurs le
            # 6 août 2025 (https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life).
            self._result.add_finding(
                message=("Pas d'agrafage OCSP : normal, le certificat ne publie aucune "
                         "URL OCSP (révocation par CRL)"),
                severity="INFO",
                evidence=("Le certificat présenté ne contient pas d'adresse de répondeur "
                          "OCSP (openssl x509 -ocsp_uri vide) : le serveur n'a rien à "
                          "agrafer."),
                url=self.target,
            )
        elif "OCSP response: no response sent" in output:
            self._result.add_finding(
                message="OCSP stapling is disabled, no OCSP response sent",
                severity="MEDIUM",
                evidence=(
                    "Server did not send an OCSP response during TLS handshake.\n"
                    "Impact: Browser must fetch OCSP responder directly (privacy leak, extra latency).\n"
                    "Recommendation: Enable OCSP stapling on the web server."
                ),
                url=self.target,
            )

        elif "OCSP Response Status:" in output:
            status_match = re.search(r"OCSP Response Status:\s*(.+)", output)
            status_value = status_match.group(1).strip() if status_match else "unknown"
            self._result.add_finding(
                message=f"OCSP stapling issue, response status: {status_value}",
                severity="MEDIUM",
                evidence=f"OCSP Response Status: {status_value}\n\nFull output snippet:\n{output[:500]}",
                url=self.target,
            )

    # ── 7) HTTP/2 support ───────────────────────────────────────────────

    def _check_http2(self, hostname: str, port: int) -> None:
        """Check if HTTP/2 is supported via ALPN."""
        # Method 1: Try curl with --http2
        try:
            proc = subprocess.run(
                [
                    "curl", "-sI", "--http2",
                    f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}",
                    "--connect-timeout", "10",
                ],
                capture_output=True,
                timeout=15,
            )
            curl_output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")

            # Check if HTTP/2 was used
            if "HTTP/2" in curl_output and "200" in curl_output:
                self._result.add_finding(
                    message="HTTP/2 supported",
                    severity="INFO",
                    evidence="curl --http2 succeeded with HTTP/2 negotiation via ALPN",
                    url=self.target,
                )
                return
            elif "HTTP/1.1" in curl_output or "HTTP/1.0" in curl_output:
                # curl fell back to HTTP/1.1, try to detect if server supports HTTP/2 via ALPN
                pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Method 2: Check via openssl ALPN negotiation
        try:
            proc = subprocess.run(
                [
                    "openssl", "s_client",
                    "-connect", f"{hostname}:{port}",
                    "-servername", hostname,
                    "-alpn", "h2",
                ],
                input=b"\n",
                capture_output=True,
                timeout=15,
            )
            alpn_output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")

            # Check ALPN selection
            if 'ALPN protocol: h2' in alpn_output or 'ALPN, protocol h2' in alpn_output:
                self._result.add_finding(
                    message="HTTP/2 supported (ALPN negotiation)",
                    severity="INFO",
                    evidence="OpenSSL ALPN negotiation selected h2 (HTTP/2)",
                    url=self.target,
                )
            elif 'ALPN protocol:' in alpn_output or 'ALPN, protocol ' in alpn_output:
                alpn_match = re.search(r"ALPN.*?(http[\w/-]+)", alpn_output, re.IGNORECASE)
                alpn_value = alpn_match.group(1) if alpn_match else "non-h2 protocol"
                self._result.add_finding(
                    message=f"HTTP/2 not supported, ALPN selected: {alpn_value}",
                    severity="LOW",
                    evidence=f"OpenSSL ALPN negotiation selected: {alpn_value}",
                    url=self.target,
                )
            else:
                self._result.add_finding(
                    message="HTTP/2 not detected (no ALPN h2 negotiation)",
                    severity="LOW",
                    evidence=(
                        "Neither curl --http2 nor openssl ALPN h2 negotiation detected HTTP/2.\n"
                        "Note: Some servers require HTTP/1.1 upgrade to negotiate HTTP/2."
                    ),
                    url=self.target,
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._result.add_finding(
                message="Could not check HTTP/2 support",
                severity="LOW",
                evidence="openssl/curl not available or timed out",
                url=self.target,
            )
