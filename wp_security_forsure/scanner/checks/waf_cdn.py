"""Detect WAF / CDN services in front of the target.

Inherits from BaseCheck. Covers:
  1) Cloudflare, cf-ray, server: cloudflare, cf-cache-status, alt-svc h3
  2) Sucuri, X-Sucuri-ID, X-Sucuri-Cache headers
  3) Fastly, X-Served-By, X-Timer, X-Cache headers
  4) Akamai, server: AkamaiGHost, X-Akamai-Transformed headers
  5) ModSecurity : en-têtes sec-* / x-mod-security sur une page normale
  6) Wordfence, wfvt_ cookie, wordfenceVerifiedHuman, "Blocked by Wordfence"
  7) Generic WAF : page de challenge / CAPTCHA servie sur la page d'accueil
  8) Rate limiting, 3 rapid requests, 429 status, Retry-After header
  9) CDN geographic, X-Vary, CDN-specific variation headers

All findings are INFO severity, informational for the auditor, not vulnerabilities.

Détection PUREMENT PASSIVE : en-têtes, cookies et pages servies normalement.
Aucune charge d'attaque (SQLi, XSS, traversée), aucun en-tête malformé ni
aucune méthode TRACE n'est envoyé pour provoquer une réaction du WAF.
"""

import re
from typing import List, Optional

from .base import BaseCheck, CheckResult


class WafCdnCheck(BaseCheck):
    """Detect WAF and CDN services protecting the target."""

    name = "waf_cdn"
    title = "WAF / CDN Detection"
    description = (
        "Detects the presence and type of Web Application Firewall (WAF) and/or "
        "Content Delivery Network (CDN) protecting the target WordPress site. "
        "Vendor-specific headers, challenge pages, rate limiting, and response "
        "anomalies are checked."
    )
    severity = "INFO"
    access_tier = 1  # accueil et wp-login.php
    depends_on: List[str] = []

    # ── Public API ───────────────────────────────────────────────────────

    def __init__(self, target: str, config: dict, session):
        super().__init__(target, config, session)

    def run(self) -> CheckResult:
        """Execute all WAF / CDN detection checks."""
        # Page d'accueil servie normalement (base de toutes les détections)
        headers_normal = self._get_headers("/")
        body_normal = self._get_body("/")

        self._check_cloudflare(headers_normal)
        self._check_sucuri(headers_normal)
        self._check_fastly(headers_normal)
        self._check_akamai(headers_normal)
        self._check_modsecurity()
        self._check_wordfence(headers_normal)
        self._check_generic_waf()
        self._check_rate_limiting()
        self._check_cdn_geographic(headers_normal)

        return self._result

    # ── 1. Cloudflare ────────────────────────────────────────────────────

    def _check_cloudflare(self, headers: dict) -> None:
        """Detect Cloudflare CDN/WAF via response headers and alt-svc."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        evidence_parts = []

        # cf-ray header
        if "cf-ray" in headers_lower:
            evidence_parts.append(f"cf-ray: {headers_lower['cf-ray']}")

        # server: cloudflare
        server = headers_lower.get("server", "")
        if "cloudflare" in server.lower():
            evidence_parts.append(f"server: {server}")

        # cf-cache-status
        if "cf-cache-status" in headers_lower:
            evidence_parts.append(
                f"cf-cache-status: {headers_lower['cf-cache-status']}"
            )

        if evidence_parts:
            self._result.add_finding(
                message="Cloudflare detected via response headers",
                severity="INFO",
                evidence="; ".join(evidence_parts),
                url=self.target,
            )
            return

        # alt-svc h3 check (Cloudflare advertises HTTP/3)
        try:
            resp = self.http_get("/")
            alt_svc = resp.headers.get("alt-svc", "")
            if "h3=" in alt_svc:
                self._result.add_finding(
                    message="Cloudflare likely detected via alt-svc HTTP/3 advertisement",
                    severity="INFO",
                    evidence=f"alt-svc: {alt_svc}",
                    url=self.target,
                )
        except Exception:
            pass

    # ── 2. Sucuri ────────────────────────────────────────────────────────

    def _check_sucuri(self, headers: dict) -> None:
        """Detect Sucuri WAF/CDN via response headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        evidence_parts = []

        if "x-sucuri-id" in headers_lower:
            evidence_parts.append(
                f"X-Sucuri-ID: {headers_lower['x-sucuri-id']}"
            )
        if "x-sucuri-cache" in headers_lower:
            evidence_parts.append(
                f"X-Sucuri-Cache: {headers_lower['x-sucuri-cache']}"
            )
        server = headers_lower.get("server", "")
        if "sucuri" in server.lower():
            evidence_parts.append(f"server: {server}")

        if evidence_parts:
            self._result.add_finding(
                message="Sucuri detected via response headers",
                severity="INFO",
                evidence="; ".join(evidence_parts),
                url=self.target,
            )

    # ── 3. Fastly ────────────────────────────────────────────────────────

    def _check_fastly(self, headers: dict) -> None:
        """Detect Fastly CDN via response headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        evidence_parts = []

        if "x-served-by" in headers_lower:
            evidence_parts.append(
                f"X-Served-By: {headers_lower['x-served-by']}"
            )
        if "x-timer" in headers_lower:
            evidence_parts.append(
                f"X-Timer: {headers_lower['x-timer']}"
            )
        if "x-cache" in headers_lower:
            evidence_parts.append(
                f"X-Cache: {headers_lower['x-cache']}"
            )
        if "surrogate-key" in headers_lower:
            evidence_parts.append(
                f"Surrogate-Key: {headers_lower['surrogate-key']}"
            )

        if evidence_parts:
            self._result.add_finding(
                message="Fastly detected via response headers",
                severity="INFO",
                evidence="; ".join(evidence_parts),
                url=self.target,
            )

    # ── 4. Akamai ────────────────────────────────────────────────────────

    def _check_akamai(self, headers: dict) -> None:
        """Detect Akamai CDN/WAF via response headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        evidence_parts = []

        server = headers_lower.get("server", "")
        if "akamai" in server.lower():
            evidence_parts.append(f"server: {server}")
        if "x-akamai-transformed" in headers_lower:
            evidence_parts.append(
                f"X-Akamai-Transformed: {headers_lower['x-akamai-transformed']}"
            )
        if "x-akamai-request-id" in headers_lower:
            evidence_parts.append(
                f"X-Akamai-Request-ID: {headers_lower['x-akamai-request-id']}"
            )

        if evidence_parts:
            self._result.add_finding(
                message="Akamai detected via response headers",
                severity="INFO",
                evidence="; ".join(evidence_parts),
                url=self.target,
            )

    # ── 5. ModSecurity ───────────────────────────────────────────────────

    def _check_modsecurity(self) -> None:
        """Détecte ModSecurity via ses en-têtes sur une page normale (passif)."""

        # Check for sec-* headers on normal request
        try:
            resp = self.http_get("/")
            sec_headers = [
                f"{k}: {v}"
                for k, v in resp.headers.items()
                if k.lower().startswith("sec-")
                or k.lower().startswith("x-mod-security")
            ]
            if sec_headers:
                self._result.add_finding(
                    message="ModSecurity detected via security headers",
                    severity="INFO",
                    evidence="; ".join(sec_headers),
                    url=self.target,
                )
                return
        except Exception:
            pass

    # ── 6. Wordfence ─────────────────────────────────────────────────────

    def _check_wordfence(self, headers: dict) -> None:
        """Detect Wordfence WAF via cookies and block page content."""
        # Check for wfvt_ cookie in response headers
        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie and "wfvt_" in set_cookie:
            self._result.add_finding(
                message="Wordfence detected via wfvt_ tracking cookie",
                severity="INFO",
                evidence=f"Set-Cookie contains wfvt_",
                url=self.target,
            )
            return

        # Check for wordfenceVerifiedHuman cookie
        if set_cookie and "wordfenceVerifiedHuman" in set_cookie:
            self._result.add_finding(
                message="Wordfence detected via wordfenceVerifiedHuman cookie",
                severity="INFO",
                evidence=f"Set-Cookie contains wordfenceVerifiedHuman",
                url=self.target,
            )
            return

        # Check for Wordfence 403 block page on wp-login.php
        try:
            resp = self.http_get("/wp-login.php")
            body = resp.text.lower()
            if "blocked by wordfence" in body or "generated by wordfence" in body:
                self._result.add_finding(
                    message="Wordfence detected via 403 block page content",
                    severity="INFO",
                    evidence="Response body contains 'Blocked by Wordfence' or "
                    "'Generated by Wordfence'",
                    url=f"{self.target}/wp-login.php",
                )
        except Exception:
            pass

    # ── 7. Generic WAF Detection ─────────────────────────────────────────

    def _check_generic_waf(self) -> None:
        """Détecte une page de challenge de WAF servie normalement (passif).

        Aucune requête malveillante n'est envoyée : seule la page d'accueil,
        telle que servie à un visiteur, est analysée. Seuls les marqueurs
        propres à une page de challenge d'éditeur comptent : le mot
        « captcha » ou un widget reCAPTCHA de formulaire ne prouvent pas un
        WAF, et un faux CAPTCHA ClickFix serait alors présenté comme une
        protection (voir le check client_injection).
        """
        baseline_body = ""

        try:
            resp_normal = self.http_get("/")
            baseline_body = resp_normal.text.lower()
        except Exception:
            self._result.add_finding(
                message="Could not fetch baseline response for generic WAF detection",
                severity="INFO",
                evidence="Baseline request failed",
                url=self.target,
            )
            return

        # Marqueurs de page de challenge d'éditeur (Cloudflare, SiteGround).
        challenge_keywords = [
            "cf-browser-verification",
            "challenge-platform",
            "cf-challenge",
            "_cf_chl_opt",
            "sgcaptcha",
        ]
        found_challenges = [
            kw for kw in challenge_keywords if kw in baseline_body
        ]
        if found_challenges:
            self._result.add_finding(
                message="Challenge page detected (WAF vendor marker), WAF likely present",
                severity="INFO",
                evidence=f"Keywords found: {', '.join(found_challenges)}",
                url=self.target,
            )

    # ── 8. Rate Limiting Detection ───────────────────────────────────────

    def _check_rate_limiting(self) -> None:
        """Send 3 rapid requests to check for rate limiting (429 / Retry-After).

        `no_cache=True` : ces 3 requêtes vers la même URL doivent chacune
        toucher le réseau, un rate limiter ne se déclenche typiquement qu'à
        partir de la 2e/3e requête, donc servir la réponse mise en cache de la
        1re empêcherait de jamais observer le 429.
        """
        for i in range(3):
            try:
                resp = self.http_get("/", no_cache=True)
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After", "N/A")
                    self._result.add_finding(
                        message=f"Rate limiting detected, HTTP 429 on request {i + 1}",
                        severity="INFO",
                        evidence=f"Retry-After: {retry_after}",
                        url=self.target,
                    )
                    return
                # Some WAFs return 503 instead of 429
                if resp.status_code == 503:
                    retry_after = resp.headers.get("Retry-After", "N/A")
                    self._result.add_finding(
                        message=f"Rate limiting likely detected, HTTP 503 on "
                        f"request {i + 1}",
                        severity="INFO",
                        evidence=f"Retry-After: {retry_after}",
                        url=self.target,
                    )
                    return
            except Exception:
                continue

    # ── 9. CDN Geographic Detection ──────────────────────────────────────

    def _check_cdn_geographic(self, headers: dict) -> None:
        """Check CDN-specific headers that indicate geographic/content variation."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        evidence_parts = []

        # Vary header, CDNs use it to serve region/cookie-specific content
        vary = headers_lower.get("vary", "")
        if vary:
            evidence_parts.append(f"Vary: {vary}")

        # CDN-specific variation headers
        for hdr in [
            "x-vary",
            "x-geo",
            "x-location",
            "x-edge-location",
            "x-region",
            "content-language",
        ]:
            if hdr in headers_lower:
                evidence_parts.append(
                    f"{hdr}: {headers_lower[hdr]}"
                )

        if evidence_parts:
            self._result.add_finding(
                message="CDN geographic / variation headers detected",
                severity="INFO",
                evidence="; ".join(evidence_parts),
                url=self.target,
            )

    # ── Helpers ──────────────────────────────────────────────────────────

    def _get_headers(self, path: str) -> dict:
        """Fetch response headers for a given path. Returns {} on failure."""
        try:
            resp = self.http_head(path)
            return dict(resp.headers)
        except Exception:
            try:
                resp = self.http_get(path)
                return dict(resp.headers)
            except Exception:
                return {}

    def _get_body(self, path: str) -> str:
        """Fetch response body for a given path. Returns '' on failure."""
        try:
            resp = self.http_get(path)
            return resp.text
        except Exception:
            return ""
