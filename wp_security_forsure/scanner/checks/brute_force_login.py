"""Check for WordPress login security weaknesses, 100% PASSIVE.

Contrainte non négociable : ce check ne doit JAMAIS soumettre d'identifiants,
JAMAIS flooder de tentatives de connexion, et JAMAIS déclencher de requête
pingback sortante. Chaque requête émise est une lecture (GET/HEAD) : aucun
appel XML-RPC n'est envoyé, pas même l'introspection system.listMethods.

Inherits from BaseCheck. Covers:
  1) Login page detection (wp-login.php, wp-admin redirect), read-only
  2) User enumeration via ?author=N (test IDs 1-5), read-only
  3) wp-json/wp/v2/users/ user leak, read-only
  4) XML-RPC surface : un GET sur xmlrpc.php qui répond « XML-RPC server
     accepts POST requests only. » prouve que le serveur XML-RPC est actif.
     Les méthodes exposées (system.multicall, pingback.ping,
     wp.getUsersBlogs, actives par défaut dans le cœur) ne sont pas
     évaluables passivement : constat INFO dédié. Ce check est l'unique
     propriétaire de la surface XML-RPC (wp_features ne la signale plus).
  5) Rate limiting, détection PASSIVE de signatures connues de protection
     anti-force-brute sur la page de login (Wordfence, Limit Login
     Attempts, Loginizer, iThemes/Solid Security, WP Cerber, AIOS,
     reCAPTCHA/hCaptcha, Cloudflare). Aucune tentative de connexion n'est
     jamais soumise.
  6) 2FA detection : plugin asset fingerprinting (assets devinés : niveau 2,
     --authorized ; sans lui, seuls les assets référencés par une page
     récupérée). Les empreintes PHP (fichier principal d'une extension) sont
     retirées : un GET les exécuterait (constat INFO « non évaluable »).
  7) Admin username presence, ?author=1 redirect check
  8) SSL enforcement, HTTP-to-HTTPS redirect on login page
"""

import re
from typing import Dict, List, Optional

import requests

from .base import BaseCheck, CheckResult
from .signatures import xmlrpc_server_active


class BruteForceLoginCheck(BaseCheck):
    """Check login security: enumeration, rate limiting, 2FA, XML-RPC, SSL."""

    name = "brute_force_login"
    title = "Brute Force & Login Protection"
    description = (
        "Checks for login page exposure, user enumeration vectors, "
        "XML-RPC abuse potential, rate limiting, 2FA presence, "
        "and SSL enforcement on the login page."
    )
    severity = "CRITICAL"
    depends_on: List[str] = []
    access_tier = 1  # mixte : assets 2FA devinés sous --authorized

    # ── Signatures passives de protection anti-force-brute ──────────────
    # Détectées uniquement dans le corps/en-têtes d'un simple GET de la page
    # de login, aucune tentative de connexion n'est jamais soumise.
    _BRUTEFORCE_PROTECTION_MARKERS: List[Dict[str, object]] = [
        {"name": "Wordfence", "body": ["wordfence"]},
        {"name": "Limit Login Attempts", "body": [
            "limit login attempts", "limit_login_attempts", "limit-login-attempts",
        ]},
        {"name": "Loginizer", "body": ["loginizer"]},
        {"name": "iThemes Security (Solid Security)", "body": [
            "ithemes security", "solid security", "better-wp-security",
        ]},
        {"name": "WP Cerber Security", "body": ["wp-cerber", "cerber security"]},
        {"name": "All In One WP Security", "body": ["all-in-one-wp-security", "aiowps"]},
        {"name": "reCAPTCHA", "body": ["g-recaptcha", "recaptcha"]},
        {"name": "hCaptcha", "body": ["h-captcha", "hcaptcha"]},
        {"name": "Cloudflare (challenge)", "body": [
            "checking your browser", "cf-browser-verification", "cf_chl_",
        ]},
    ]

    # ── 2FA plugin asset fingerprints ──────────────────────────────────
    _TWOFA_ASSETS: List[Dict] = [
        # wordfence
        {"path": "wp-content/plugins/wordfence/css/wordfence-2fa.css",
         "plugin": "Wordfence"},
        {"path": "wp-content/plugins/wordfence/js/wf.2fa.js",
         "plugin": "Wordfence"},
        # iThemes Security
        {"path": "wp-content/plugins/better-wp-security/core/modules/two-factor/js/frontend.js",
         "plugin": "iThemes Security (Solid Security)"},
        {"path": "wp-content/plugins/ithemes-security-pro/core/modules/two-factor/js/frontend.js",
         "plugin": "iThemes Security Pro"},
        # WP 2FA
        {"path": "wp-content/plugins/wp-2fa/admin/js/2fa-settings.js",
         "plugin": "WP 2FA"},
        # miniOrange 2FA
        {"path": "wp-content/plugins/miniorange-2-factor-authentication/includes/js/mo2fa_login.js",
         "plugin": "miniOrange 2FA"},
        # Jetpack SSO / 2FA
        {"path": "wp-content/plugins/jetpack/modules/sso/jetpack-sso-login.js",
         "plugin": "Jetpack SSO"},
        # Duo Security
        {"path": "wp-content/plugins/duo-wordpress/duo_wordpress.css",
         "plugin": "Duo Security"},
        # Limit Login Attempts Reloaded
        {"path": "wp-content/plugins/limit-login-attempts-reloaded/assets/js/limit-login-attempts.js",
         "plugin": "Limit Login Attempts Reloaded"},
        # Cerber Security
        {"path": "wp-content/plugins/wp-cerber/assets/css/cerber.css",
         "plugin": "WP Cerber Security"},
    ]

    # Extensions dont la seule empreinte connue était un fichier PHP (Google
    # Authenticator, Two Factor, Loginizer, WPS Hide Login, All In One WP
    # Security) : sondes retirées, un GET exécuterait le fichier.
    _TWOFA_PHP_ONLY: List[str] = [
        "Google Authenticator", "Two Factor (WP org)", "Loginizer",
        "WPS Hide Login", "All In One WP Security",
    ]

    def __init__(self, target: str, config: dict, session):
        super().__init__(target, config, session)

    # ── Public API ─────────────────────────────────────────────────────

    def run(self) -> CheckResult:
        """Execute all brute-force / login security checks (100% passif)."""
        self._check_login_page_detection()          # 1
        self._check_user_enumeration_author()       # 2
        self._check_rest_api_users()                # 3
        self._check_xmlrpc_surface()                # 4, introspection passive
        self._check_rate_limiting()                 # 5, détection de signature passive
        self._check_twofa_detection()                # 6
        self._check_admin_username()                # 7
        self._check_ssl_enforcement()                # 8
        return self._result

    # ── 1) Login page detection ────────────────────────────────────────

    def _check_login_page_detection(self) -> None:
        """Check wp-login.php accessibility and wp-admin redirect."""
        # wp-login.php
        resp = self._safe_get("wp-login.php")
        if resp is None:
            return

        status = resp.status_code
        final_url = resp.url
        content_type = resp.headers.get("Content-Type", "")

        if status == 200:
            # Check if it looks like a login form
            body_lower = resp.text.lower()
            is_login_form = any(
                kw in body_lower
                for kw in ["wp-submit", "user_login", "loginform", "log="]
            )
            if is_login_form:
                evidence = (
                    f"Default login page wp-login.php accessible (HTTP {status})\n"
                    f"Content-Type: {content_type} | Size: {len(resp.text)} bytes\n"
                    f"Final URL: {final_url}"
                )
                self._result.add_finding(
                    message="Default wp-login.php accessible",
                    severity="LOW",
                    evidence=evidence,
                    url=final_url,
                )
            else:
                evidence = (
                    f"wp-login.php returned HTTP {status} but no login form detected\n"
                    f"Content-Type: {content_type} | Final URL: {final_url}"
                )
                self._result.add_finding(
                    message="wp-login.php accessible (non-standard response)",
                    severity="LOW",
                    evidence=evidence,
                    url=final_url,
                )

        # wp-admin redirect check
        resp_admin = self._safe_get("wp-admin/", allow_redirects=False)
        if resp_admin is not None:
            if resp_admin.status_code in (301, 302, 307, 308):
                location = resp_admin.headers.get("Location", "")
                if "wp-login" in location or "login" in location.lower():
                    evidence = (
                        f"wp-admin redirects to login page\n"
                        f"HTTP {resp_admin.status_code} → {location}"
                    )
                    self._result.add_finding(
                        message="wp-admin redirects to wp-login.php",
                        severity="INFO",
                        evidence=evidence,
                        url=resp_admin.url,
                    )

    # ── 2) User enumeration via ?author=N ──────────────────────────────

    def _check_user_enumeration_author(self) -> None:
        """Test ?author=1 through ?author=5 for username leak."""
        found_users: List[Dict] = []

        for author_id in range(1, 6):
            resp = self._safe_get(f"?author={author_id}", allow_redirects=False)
            if resp is None:
                continue

            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("Location", "")
                # Typical pattern: /author/username/
                if "/author/" in location:
                    username = location.rstrip("/").rsplit("/", 1)[-1]
                    found_users.append({"id": author_id, "username": username, "url": location})
                # NB : une redirection SANS /author/ (ex. vers l'accueil) est
                # justement la MITIGATION de l'énumération (archives auteur
                # désactivées), on ne la compte PAS comme un utilisateur.

        if found_users:
            usernames = ", ".join(
                f"ID {u['id']} → {u['username']}" for u in found_users
            )
            evidence_lines = ["User enumeration via ?author=N:"]
            for u in found_users:
                evidence_lines.append(f"  ?author={u['id']} → {u['username']} ({u['url']})")
            evidence = "\n".join(evidence_lines)

            # Determine severity based on what was found
            is_admin = any(
                u["username"].lower() in ("admin", "administrator")
                for u in found_users
            )
            severity = "CRITICAL" if is_admin else "HIGH"

            self._result.add_finding(
                message=f"User enumeration via ?author=N ({len(found_users)} users found: {usernames})",
                severity=severity,
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/?author=1",
            )

    # ── 3) REST API user leak ──────────────────────────────────────────

    def _check_rest_api_users(self) -> None:
        """Check wp-json/wp/v2/users/ for user list exposure."""
        # Main endpoint
        resp = self._safe_get("wp-json/wp/v2/users")
        if resp is None:
            return

        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "")

        if status == 200 and "json" in content_type.lower():
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    users_info = []
                    for user in data:
                        uid = user.get("id", "?")
                        name = user.get("name", "?")
                        slug = user.get("slug", "?")
                        roles = user.get("roles", [])
                        role_str = ", ".join(roles) if roles else "unknown"
                        users_info.append(
                            f"  ID {uid}: {name} (slug: {slug}, roles: {role_str})"
                        )
                    evidence = (
                        f"REST API exposes user list ({len(data)} users found)\n"
                        f"Endpoint: wp-json/wp/v2/users\n"
                        + "\n".join(users_info)
                    )
                    severity = "CRITICAL"
                    self._result.add_finding(
                        message=f"REST API exposes user list ({len(data)} users)",
                        severity=severity,
                        evidence=evidence,
                        url=f"{self.target.rstrip('/')}/wp-json/wp/v2/users",
                    )
                elif isinstance(data, dict) and "code" in data:
                    # Blocked but with a message, still worth noting
                    code = data.get("code", "")
                    if "rest_user_cannot_list" in code:
                        # Properly restricted
                        pass
                    else:
                        evidence = (
                            f"REST API users endpoint returned code: {code}\n"
                            f"Response: {resp.text[:300]}"
                        )
                        self._result.add_finding(
                            message=f"REST API users endpoint returns: {code}",
                            severity="INFO",
                            evidence=evidence,
                            url=f"{self.target.rstrip('/')}/wp-json/wp/v2/users",
                        )
            except Exception:
                # Not valid JSON, might be blocked
                pass

        # Check individual user IDs too
        for uid in range(1, 4):
            resp = self._safe_get(f"wp-json/wp/v2/users/{uid}")
            if resp is None:
                continue
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict) and "id" in data:
                        name = data.get("name", "?")
                        slug = data.get("slug", "?")
                        evidence = (
                            f"Individual user endpoint exposed: wp-json/wp/v2/users/{uid}\n"
                            f"User: {name} (slug: {slug})"
                        )
                        self._result.add_finding(
                            message=(
                                f"REST API exposes individual user ID {uid}"
                                f" ({name})"
                            ),
                            severity="HIGH",
                            evidence=evidence,
                            url=f"{self.target.rstrip('/')}/wp-json/wp/v2/users/{uid}",
                        )
                except Exception:
                    pass

    # ── 4) XML-RPC surface (GET seul, aucun appel XML-RPC) ────────────────

    # Méthodes à risque exposées par défaut par le serveur XML-RPC du cœur.
    _XMLRPC_RISKY_DEFAULTS = ("system.multicall", "pingback.ping",
                              "wp.getUsersBlogs")

    def _check_xmlrpc_surface(self) -> None:
        """Établit passivement que XML-RPC est actif (GET xmlrpc.php).

        Le serveur XML-RPC de WordPress répond à tout GET par « XML-RPC server
        accepts POST requests only. » : cette signature suffit à prouver qu'il
        est actif, sans aucun appel. La liste des méthodes exposées exigerait
        un POST system.listMethods : elle est non évaluable passivement.
        """
        resp = self._safe_get("xmlrpc.php", allow_redirects=False)
        if resp is None:
            return

        status = resp.status_code
        if status in (401, 403, 404, 410):
            return  # Bloqué / absent : rien de plus à constater
        body = resp.text or ""
        url = f"{self.target.rstrip('/')}/xmlrpc.php"

        if not xmlrpc_server_active(body):
            if status in (200, 405) and not self._is_soft404(resp):
                self._result.add_finding(
                    message="xmlrpc.php répond sans la signature du serveur XML-RPC (non concluant)",
                    severity="INFO",
                    evidence=(
                        f"GET xmlrpc.php : HTTP {status}, signature « XML-RPC "
                        "server accepts POST requests only. » absente.\n"
                        f"Extrait de réponse : {body[:200]}"
                    ),
                    url=url,
                    confidence="potential",
                )
            return

        self._result.add_finding(
            message="XML-RPC activé (xmlrpc.php accessible)",
            severity="HIGH",
            evidence=(
                "XML-RPC endpoint accessible (xmlrpc.php)\n"
                f"GET xmlrpc.php : HTTP {status}, réponse « XML-RPC server "
                "accepts POST requests only. » (serveur XML-RPC de WordPress "
                "actif).\nDétection passive : aucun appel XML-RPC envoyé."
            ),
            url=url,
        )
        self._result.add_finding(
            message=(
                "Méthodes XML-RPC à risque non évaluables passivement "
                "(system.multicall, pingback.ping, wp.getUsersBlogs)"
            ),
            severity="INFO",
            evidence=(
                "Ces méthodes sont exposées par défaut par le cœur quand XML-RPC "
                "est actif (amplification de force brute, pingback sortant, "
                "validation d'identifiants hors wp-login.php). Les lister exige "
                "un POST system.listMethods, que le scanner n'envoie jamais.\n"
                "Recommandation : désactiver XML-RPC s'il n'est pas utilisé, ou "
                "retirer ces méthodes via le filtre xmlrpc_methods."
            ),
            url=url,
            confidence="potential",
        )

    # ── 5) Rate limiting, passive protection-signature detection ───────

    def _check_rate_limiting(self) -> None:
        """Détection PASSIVE d'une protection anti-force-brute.

        Ne soumet JAMAIS de tentative de connexion : un unique GET de la
        page de login est effectué, et son corps/en-têtes sont comparés à
        des signatures connues de plugins/services de protection
        anti-force-brute. Aucune boucle de connexions échouées n'est
        jamais envoyée.
        """
        # Sonde préalable : si la page de login n'existe pas (404) ou est
        # protégée (403), le test n'a pas de sens (login relocalisé).
        probe = self._safe_get("wp-login.php")
        if probe is None or probe.status_code in (404, 403):
            self._result.add_finding(
                message="wp-login.php introuvable/protégé, login probablement relocalisé (durcissement)",
                severity="INFO",
                evidence=(f"GET wp-login.php → HTTP "
                          f"{getattr(probe, 'status_code', 'no response')}. "
                          f"Test de rate-limit non concluant sur cet endpoint."),
                url=f"{self.target.rstrip('/')}/wp-login.php",
                confidence="confirmed",
            )
            return

        body_lower = (probe.text or "").lower()
        headers = probe.headers

        detected = []
        for marker in self._BRUTEFORCE_PROTECTION_MARKERS:
            if any(kw in body_lower for kw in marker["body"]):
                detected.append(marker["name"])

        # En-têtes révélateurs d'une protection / CDN de challenge.
        if ("cf-ray" in headers or "cf-mitigated" in headers) and "Cloudflare" not in detected:
            detected.append("Cloudflare")
        if headers.get("Retry-After") is not None:
            detected.append("En-tête Retry-After présent sur la page de login")
        if headers.get("X-RateLimit-Remaining") is not None:
            detected.append("En-tête X-RateLimit-Remaining présent sur la page de login")
        if probe.status_code == 429:
            detected.append("HTTP 429 dès le simple GET de la page de login")

        if detected:
            unique = list(dict.fromkeys(detected))
            evidence = (
                "Signature(s) de protection anti-force-brute détectée(s) "
                "PASSIVEMENT (simple GET de la page de login, aucune "
                "tentative de connexion soumise) :\n"
                + "\n".join(f"  - {d}" for d in unique)
            )
            self._result.add_finding(
                message=f"Protection anti-force-brute détectée ({', '.join(unique)})",
                severity="INFO",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-login.php",
                confidence="confirmed",
            )
        else:
            evidence = (
                "Aucune signature connue de protection anti-force-brute "
                "(Wordfence, Limit Login Attempts, Loginizer, iThemes/Solid "
                "Security, WP Cerber, All In One WP Security, reCAPTCHA, "
                "hCaptcha, Cloudflare) détectée dans le corps/en-têtes de la "
                "page de login.\n"
                "Détection passive uniquement, aucune tentative de connexion "
                "n'a été envoyée. Une protection peut exister sans signature "
                "visible depuis l'extérieur (ex. limite déclenchée seulement "
                "après plusieurs échecs réels)."
            )
            self._result.add_finding(
                message=(
                    "Aucune protection anti-force-brute détectée passivement, "
                    "à confirmer manuellement (non testé activement)"
                ),
                severity="MEDIUM",
                evidence=evidence,
                url=f"{self.target.rstrip('/')}/wp-login.php",
                confidence="potential",
            )

    # ── 6) 2FA detection ───────────────────────────────────────────────

    def _check_twofa_detection(self) -> None:
        """Probe common 2FA plugin asset paths (niveau 2 : --authorized)."""
        detected = []
        self.note_not_assessable(
            "Détection 2FA par le fichier PHP principal d'une extension ("
            + ", ".join(self._TWOFA_PHP_ONLY) + ")")
        if self.config.get("authorized"):
            assets = list(self._TWOFA_ASSETS)
        else:
            # Sans --authorized : seuls les assets déjà référencés par une page
            # récupérée ; l'absence de constat n'établit alors rien.
            assets = [a for a in self._TWOFA_ASSETS if self.may_request(a["path"])]
            self.note_unlinked_skipped(
                "recherche d'assets d'extensions 2FA (Wordfence, iThemes, WP 2FA, "
                "miniOrange, Jetpack SSO, Duo, Limit Login Attempts, WP Cerber)")

        for asset in assets:
            resp = self._safe_get(asset["path"])
            if resp is not None and resp.status_code == 200:
                detected.append(asset["plugin"])

        if not detected and not self.config.get("authorized"):
            return  # recherche non faite : rien à conclure
        if detected:
            unique_plugins = list(dict.fromkeys(detected))  # preserve order, dedupe
            evidence = (
                "2FA plugin(s) detected via asset fingerprinting:\n"
                + "\n".join(f"  - {p}" for p in unique_plugins)
            )
            self._result.add_finding(
                message=f"2FA plugin detected: {', '.join(unique_plugins)}",
                severity="INFO",
                evidence=evidence,
            )
        else:
            # Absence d'ASSETS 2FA connus ≠ absence de 2FA : un site durci bloque
            # l'accès direct aux fichiers de plugins (403), ou utilise un plugin
            # hors liste. Heuristique d'absence → LOW/potential, pas un HIGH.
            evidence = (
                "Aucun asset de plugin 2FA connu détecté via les chemins testés "
                "(Wordfence, iThemes, WP 2FA, miniOrange, Jetpack SSO, Duo, "
                "Limit Login Attempts, WP Cerber).\n"
                "NB : non concluant, accès plugins bloqué (403) ou plugin hors liste."
            )
            self._result.add_finding(
                message="Aucun plugin 2FA détecté via empreinte d'assets (non concluant)",
                severity="LOW",
                evidence=evidence,
                confidence="potential",
            )

    # ── 7) Admin username presence ────────────────────────────────────

    def _check_admin_username(self) -> None:
        """Check if 'admin' user exists via ?author=1 redirect."""
        resp = self._safe_get("?author=1", allow_redirects=False)
        if resp is None:
            return

        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if "/author/" in location:
                username = location.rstrip("/").rsplit("/", 1)[-1]
                if username.lower() in ("admin", "administrator"):
                    evidence = (
                        f"'admin' username confirmed via ?author=1\n"
                        f"HTTP {resp.status_code} → {location}"
                    )
                    self._result.add_finding(
                        message="'admin' username exists, primary brute-force target",
                        severity="CRITICAL",
                        evidence=evidence,
                        url=f"{self.target.rstrip('/')}/?author=1",
                    )
                # Else: user found but not 'admin', enumeration is already
                # reported by _check_user_enumeration_author (check #2), no
                # separate finding needed here.

    # ── 8) SSL enforcement ────────────────────────────────────────────

    def _check_ssl_enforcement(self) -> None:
        """Check if login page redirects HTTP to HTTPS."""
        # If target is already HTTPS, check that HTTP would redirect
        target_lower = self.target.lower()
        if target_lower.startswith("https://"):
            # Try HTTP version
            http_target = "http://" + self.target[len("https://"):]
            try:
                resp = self.http_get_url(
                    f"{http_target.rstrip('/')}/wp-login.php",
                    allow_redirects=False,
                )
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if location.startswith("https://"):
                        evidence = (
                            "HTTP → HTTPS redirect enforced on login page\n"
                            f"HTTP {resp.status_code} → {location}"
                        )
                        self._result.add_finding(
                            message="SSL enforced: HTTP login redirects to HTTPS",
                            severity="INFO",
                            evidence=evidence,
                        )
                    else:
                        evidence = (
                            f"HTTP wp-login.php redirects to non-HTTPS URL\n"
                            f"HTTP {resp.status_code} → {location}"
                        )
                        self._result.add_finding(
                            message="Login page redirects to non-HTTPS URL",
                            severity="HIGH",
                            evidence=evidence,
                        )
                elif resp.status_code == 200:
                    evidence = (
                        "Login page accessible over HTTP, "
                        "credentials transmitted in plaintext!\n"
                        f"HTTP {resp.status_code} on http://.../wp-login.php"
                    )
                    self._result.add_finding(
                        message="Login page accessible over HTTP (no redirect to HTTPS)",
                        severity="CRITICAL",
                        evidence=evidence,
                    )
            except Exception:
                # Cannot reach HTTP version, might be HTTP-only server or network issue
                pass

        elif target_lower.startswith("http://"):
            # Target is HTTP, check if it serves directly
            resp = self._safe_get("wp-login.php", allow_redirects=False)
            if resp is not None:
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if location.startswith("https://"):
                        evidence = (
                            "HTTP → HTTPS redirect enforced on login page\n"
                            f"HTTP {resp.status_code} → {location}"
                        )
                        self._result.add_finding(
                            message="SSL enforced: HTTP login redirects to HTTPS",
                            severity="INFO",
                            evidence=evidence,
                        )
                    else:
                        evidence = (
                            f"HTTP login page redirects to non-HTTPS destination\n"
                            f"HTTP {resp.status_code} → {location}"
                        )
                        self._result.add_finding(
                            message="Login page redirect target is not HTTPS",
                            severity="HIGH",
                            evidence=evidence,
                        )
                elif resp.status_code == 200:
                    evidence = (
                        "Login page served over plain HTTP, "
                        "credentials transmitted in plaintext!\n"
                        f"HTTP {resp.status_code} on {resp.url}"
                    )
                    self._result.add_finding(
                        message="Login page served over HTTP (no encryption)",
                        severity="CRITICAL",
                        evidence=evidence,
                    )

    # ── HTTP helpers ───────────────────────────────────────────────────

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
