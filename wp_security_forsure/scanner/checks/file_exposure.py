"""Check for exposed sensitive files on WordPress.

Inherits from BaseCheck. Uses HEAD-first-then-GET strategy with body content
indicator validation (not just HTTP status codes).

Categories checked:
  1) readme.html         , info disclosure (LOW)
  2) license.txt         , info disclosure (LOW)
  3) wp-config backups   , config exposure (CRITICAL)
  4) wp-content/debug.log, debug mode leak (HIGH)
  5) .git/config         , repo exposure (CRITICAL)
  6) .env / .env.local   , env secrets (CRITICAL)
  7) phpinfo files       , PHP info disclosure (HIGH)
  8) wp-config-sample.php, sample config (MEDIUM)
  9) wp-admin/install.php, install unlocked (CRITICAL)
 10) wp-content/uploads/ , dir listing (HIGH)
 11) backup directories  , backup access (CRITICAL)
 12) DB dumps in root    , credential leak (CRITICAL)
"""

from typing import Dict, List

from ..redact import redact_text
from .base import BaseCheck, CheckResult
from .signatures import is_already_installed


class FileExposureCheck(BaseCheck):
    """Check for exposed sensitive files and directories on WordPress."""

    name = "file_exposure"
    title = "Sensitive File & Directory Exposure"
    description = (
        "Checks for exposed WordPress files that leak configuration, "
        "credentials, debug information, or enable site takeover."
    )
    severity = "CRITICAL"
    access_tier = 1  # mixte : readme.html, license.txt ; le reste sous --authorized
    depends_on: List[str] = []

    # ── Category definitions ──────────────────────────────────────────
    # Each entry: paths, label_prefix, severity, indicators[], is_directory

    CATEGORIES: List[Dict] = [
        # 1) readme.html
        {
            "paths": ["readme.html"],
            "label": "readme.html",
            "severity": "LOW",
            "indicators": ["WordPress"],
            "is_directory": False,
        },
        # 2) license.txt
        {
            "paths": ["license.txt"],
            "label": "license.txt",
            "severity": "LOW",
            "indicators": ["WordPress", "GNU General Public License"],
            "is_directory": False,
        },
        # 3) wp-config.php backups, CRITICAL
        {
            "paths": [
                "wp-config.php.bak",
                "wp-config.php.old",
                "wp-config.php~",
                "wp-config.php.save",
                "wp-config.php.swp",
                "wp-config.old.php",
                "wp-config.txt",
            ],
            "label": "wp-config.php backup",
            "severity": "CRITICAL",
            "indicators": [
                "DB_NAME", "DB_USER", "DB_PASSWORD",
                "define(", "AUTH_KEY", "auth_key",
            ],
            "is_directory": False,
        },
        # 4) wp-content/debug.log, HIGH
        {
            "paths": ["wp-content/debug.log"],
            "label": "wp-content/debug.log",
            "severity": "HIGH",
            "indicators": [
                "PHP", "Fatal", "Error", "Warning",
                "Stack trace", "Notice", "Parse error",
            ],
            "is_directory": False,
        },
        # 5) .git/config, CRITICAL (also check .git/HEAD as quick confirmation)
        {
            "paths": [
                ".git/config",
                ".git/HEAD",
            ],
            "label": ".git exposure",
            "severity": "CRITICAL",
            "indicators": [
                "[remote", "[core", "repositoryformatversion",
                "ref:", "refs/heads",
            ],
            "is_directory": False,
        },
        # 6) .env / .env.local / env.php, CRITICAL
        {
            "paths": [
                ".env",
                ".env.local",
                "env.php",
            ],
            "label": "environment file",
            "severity": "CRITICAL",
            "indicators": [
                "DB_", "AUTH_KEY", "API_KEY", "SECRET",
                "APP_ENV", "DATABASE_URL", "WP_HOME",
            ],
            "is_directory": False,
        },
        # 7) phpinfo() files, HIGH
        {
            "paths": [
                "info.php",
                "phpinfo.php",
                "php_info.php",
                "p.php",
                "i.php",
                "test.php",
            ],
            "label": "phpinfo file",
            "severity": "HIGH",
            "indicators": [
                "phpinfo", "PHP Version", "<title>phpinfo",
                "PHP License", "PHP Credits",
            ],
            "is_directory": False,
        },
        # 8) wp-config-sample.php, MEDIUM
        {
            "paths": ["wp-config-sample.php"],
            "label": "wp-config-sample.php",
            "severity": "MEDIUM",
            "indicators": [
                "define(", "DB_NAME", "DB_USER",
                "authentication unique keys",
            ],
            "is_directory": False,
        },
        # 9) wp-admin/install.php, CRITICAL
        {
            "paths": ["wp-admin/install.php"],
            "label": "wp-admin/install.php",
            "severity": "CRITICAL",
            "indicators": [
                "installation", "site title", "admin email",
                "submit", "Welcome", "WordPress",
            ],
            "is_directory": False,
        },
        # 10) wp-content/uploads/, dir listing HIGH
        {
            "paths": ["wp-content/uploads/"],
            "label": "wp-content/uploads/",
            "severity": "HIGH",
            "indicators": [
                "Index of", "index of", "Directory listing",
                "<title>Index of", "Parent Directory",
            ],
            "is_directory": True,
        },
        # 11) Backup directories, CRITICAL
        {
            "paths": [
                "wp-content/backups/",
                "wp-content/ai1wm-backups/",
                "wp-content/updraft/",
            ],
            "label": "backup directory",
            "severity": "CRITICAL",
            "indicators": [
                "Index of", "index of", "Parent Directory",
                ".zip", ".gz", ".sql", ".tar",
            ],
            "is_directory": True,
        },
        # 12) Database dumps in webroot, CRITICAL
        {
            "paths": [
                "dump.sql",
                "site.sql",
                "backup.sql",
                "wp.sql",
                "db.sql",
                "export.sql",
                "wp_backup.sql",
                "wordpress.sql",
                "database.sql",
                "dump.sql.gz",
                "site.tar.gz",
                "backup.tar.gz",
                "wp.tar.gz",
            ],
            "label": "database dump in webroot",
            "severity": "CRITICAL",
            "indicators": [
                "INSERT INTO", "CREATE TABLE", "DROP TABLE",
                "wp_", "STRUCTURE", "Dump", "MySQL dump",
            ],
            "is_directory": False,
        },
    ]

    # ── Public API ────────────────────────────────────────────────────

    def run(self) -> CheckResult:
        """Execute the file exposure check across all categories."""
        authorized = self.config.get("authorized")
        skipped = []
        for category in self.CATEGORIES:
            for path in category["paths"]:
                # Sans --authorized : seuls les chemins de niveau 0 ou 1
                # (readme.html, license.txt) ; le reste est deviné.
                if not authorized and not self.may_request(path, "HEAD"):
                    skipped.append(path)
                    continue
                self._check_single_path(
                    path=path,
                    label=category["label"],
                    severity=category["severity"],
                    indicators=category["indicators"],
                    is_directory=category["is_directory"],
                )
        if skipped:
            self.note_unlinked_skipped(
                f"{len(skipped)} chemins sensibles devinés (sauvegardes de "
                "wp-config.php, .env, .git/, debug.log, phpinfo, dumps SQL, "
                "dossiers de sauvegarde, listing de wp-content/uploads/)")
        return self._result

    # ── Internal helpers ──────────────────────────────────────────────

    def _check_single_path(
        self,
        path: str,
        label: str,
        severity: str,
        indicators: List[str],
        is_directory: bool,
    ) -> None:
        """Check one path using HEAD-first-then-GET with body validation."""
        url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"

        # ── Step 1: HEAD request ──
        try:
            head_resp = self.http_head(path, allow_redirects=False)
        except Exception:
            return  # Connection error / timeout, skip silently

        if head_resp.status_code == 404:
            return  # File does not exist

        # ── Step 2: GET request ──
        try:
            get_resp = self.http_get(path)
        except Exception:
            return

        status = get_resp.status_code
        if status == 404:
            return

        # Site soft-404 : renvoie 200 + page d'accueil pour toute URL inexistante.
        # Si la réponse ≈ le témoin « ressource absente », ce n'est pas une vraie
        # exposition, on n'émet rien (évite les faux CRITICAL wp-config.bak/.git…).
        if self._is_soft404(get_resp):
            return

        content_type = get_resp.headers.get("Content-Type", "")
        body = get_resp.text
        content_length = len(body)

        # Ignore trivial responses (< 10 bytes)
        if content_length < 10:
            return

        # Build evidence snippet (first 600 chars). Secrets masqués à la
        # source (DB_PASSWORD, clés et sels, jetons...) : jamais recopiés.
        evidence_snippet = redact_text(body[:600]).strip()
        if len(evidence_snippet) > 600:
            evidence_snippet = evidence_snippet[:597] + "..."

        # ── Directory check (listing detection) ──
        if is_directory:
            self._check_directory(
                path=path, url=url, label=label, severity=severity,
                status=status, content_type=content_type,
                content_length=content_length, body=body,
                evidence_snippet=evidence_snippet,
                indicators=indicators,
            )
            return

        # ── Regular file check (content indicator matching) ──
        self._check_file(
            path=path, url=url, label=label, severity=severity,
            status=status, content_type=content_type,
            content_length=content_length, body=body,
            evidence_snippet=evidence_snippet,
            indicators=indicators,
        )

    def _check_directory(
        self, path: str, url: str, label: str, severity: str,
        status: int, content_type: str, content_length: int,
        body: str, evidence_snippet: str, indicators: List[str],
    ) -> None:
        """Evaluate a directory for listing or unexpected accessibility."""
        listing_keywords = ["Index of", "index of", "Directory listing",
                            "<title>Index of", "Parent Directory"]

        has_listing = any(kw in body for kw in listing_keywords)

        if has_listing:
            evidence = (
                f"Directory listing enabled on {path}\n"
                f"HTTP {status} | Content-Type: {content_type} "
                f"| Size: {content_length}\n"
                f"Snippet:\n{evidence_snippet}"
            )
            self._result.add_finding(
                message=(
                    f"{label}, Directory listing enabled ({severity})"
                ),
                severity=severity,
                evidence=evidence,
                url=url,
            )
        elif status in (200, 301, 302) and content_length > 50:
            # Accessible but no listing detected, heuristic only, no real
            # content indicator matched. 403 (accès refusé) est exclu : un
            # répertoire protégé n'est PAS une exposition.
            dir_severity = "HIGH" if severity == "CRITICAL" else "MEDIUM"
            evidence = (
                f"Directory accessible at {path}"
                f" (HTTP {status}, no listing)\n"
                f"Content-Type: {content_type} | Size: {content_length}\n"
                f"Snippet:\n{evidence_snippet}"
            )
            self._result.add_finding(
                message=(
                    f"{label}, accessible (HTTP {status}, "
                    f"no listing), à confirmer ({dir_severity})"
                ),
                severity=dir_severity,
                evidence=evidence,
                url=url,
                confidence="potential",
            )

    # Marqueurs de secrets / cookies de session dans un debug.log exposé.
    # Insensible à la casse. Leur présence => fuite exploitable (account
    # takeover), classe CVE-2024-44000 (LiteSpeed : Set-Cookie post-login
    # logué dans debug.log). On émet alors un CRITICAL distinct du HIGH.
    DEBUG_LOG_SECRET_MARKERS: List[str] = [
        "set-cookie",
        "wordpress_logged_in",
        "wordpress_sec",
        "auth_cookie",
        "db_password",
        "api_key",
        "authorization: bearer",
        "secret_key",
        "nonce",
        "pwd=",
        "password=",
    ]

    @staticmethod
    def _redact_secrets(text: str) -> str:
        """Masque les valeurs sensibles d'un snippet (cookies, tokens, mdp).

        Conserve la clé (preuve) mais remplace la valeur par [REDACTED] pour
        ne jamais recopier de secret exploitable dans le rapport.
        """
        import re
        # key=value (cookies de session, pwd=, password=, api_key=, nonce=…)
        text = re.sub(r"([A-Za-z0-9_.-]+=)[^\s;,&]+", r"\1[REDACTED]", text)
        # Authorization: Bearer <token>
        text = re.sub(r"(?i)(bearer\s+)\S+", r"\1[REDACTED]", text)
        return text

    def _check_debug_log_secrets(
        self, path: str, url: str, status: int,
        content_type: str, content_length: int, body: str,
    ) -> None:
        """Détecte des secrets / cookies de session dans un debug.log exposé.

        En complément du HIGH existant (marqueurs d'erreur PHP génériques),
        émet un CRITICAL distinct quand le corps contient des marqueurs de
        secrets ou de cookies de session, fuite exploitable (account
        takeover, classe CVE-2024-44000). Lecture GET seule, non destructif.
        """
        body_lower = body.lower()
        matched = [m for m in self.DEBUG_LOG_SECRET_MARKERS
                   if m in body_lower]
        if not matched:
            return  # Log d'erreurs génériques uniquement, reste HIGH.

        # Snippet borné ET caviardé : on prouve la fuite sans recopier de
        # secret complet (valeurs de cookies/tokens/mots de passe masquées).
        snippet = body[:300].strip()
        if len(body) > 300:
            snippet = snippet + "..."
        snippet = redact_text(self._redact_secrets(snippet))
        evidence = (
            f"debug.log exposé contient des secrets / cookies de session à {path}\n"
            f"HTTP {status} | Content-Type: {content_type} "
            f"| Size: {content_length}\n"
            f"Marqueurs sensibles: {', '.join(matched)}\n"
            f"Snippet (tronqué):\n{snippet}"
        )
        self._result.add_finding(
            message=(
                "wp-content/debug.log expose des cookies de session / secrets "
                "- account takeover possible (classe CVE-2024-44000) (CRITICAL)"
            ),
            severity="CRITICAL",
            evidence=evidence,
            url=url,
            confidence="confirmed",
        )

    def _check_file(
        self, path: str, url: str, label: str, severity: str,
        status: int, content_type: str, content_length: int,
        body: str, evidence_snippet: str, indicators: List[str],
    ) -> None:
        """Evaluate a regular file for sensitive content exposure."""
        # Cas spécial debug.log : fuite de secrets / cookies de session
        # => CRITICAL distinct, en plus du HIGH générique ci-dessous.
        if label == "wp-content/debug.log":
            self._check_debug_log_secrets(
                path=path, url=url, status=status,
                content_type=content_type,
                content_length=content_length, body=body,
            )

        if "install.php" in path and is_already_installed(body):
            self._result.add_finding(
                message="wp-admin/install.php, WordPress déjà installé (non exploitable)",
                severity="INFO",
                evidence="Écran 'Déjà installé', pas d'installation ouverte.",
                url=url,
                confidence="confirmed",
            )
            return

        if "install.php" in path:
            # Garde-fou dédié : le mot générique "WordPress" (un des
            # indicateurs de la catégorie) apparaît sur presque toutes les
            # pages WP, il ne peut pas, seul, confirmer une installation
            # ouverte. Voir _check_install_php_content.
            self._check_install_php_content(
                path=path, url=url, label=label, severity=severity,
                status=status, content_type=content_type,
                content_length=content_length, body=body,
                evidence_snippet=evidence_snippet, indicators=indicators,
            )
            return

        # Find which indicators matched
        body_lower = body.lower()
        matched = [ind for ind in indicators if ind.lower() in body_lower]

        if matched:
            evidence = (
                f"Exposed file detected at {path}\n"
                f"HTTP {status} | Content-Type: {content_type} "
                f"| Size: {content_length}\n"
                f"Matched indicators: {', '.join(matched)}\n"
                f"Snippet:\n{evidence_snippet}"
            )
            self._result.add_finding(
                message=f"{label}, Exposed ({severity})",
                severity=severity,
                evidence=evidence,
                url=url,
            )
        elif status == 200 and content_length > 100:
            # File is accessible but no content indicator matched, this is
            # a heuristic, not proof of exposure. Reported as "potential"
            # so it never counts toward a confirmed-CRITICAL score.
            evidence = (
                f"File accessible at {path}\n"
                f"HTTP {status} | Content-Type: {content_type} "
                f"| Size: {content_length}\n"
                f"Snippet:\n{evidence_snippet}"
            )
            self._result.add_finding(
                message=(
                    f"{label}, accessible (HTTP {status}, "
                    f"{content_length} bytes), à confirmer ({severity})"
                ),
                severity=severity,
                evidence=evidence,
                url=url,
                confidence="potential",
            )

    # Marqueurs propres à un vrai formulaire d'installation WP ouvert, pas
    # seulement le mot générique "WordPress" (présent sur presque toutes
    # les pages WP : footer, meta generator, readme...). Alignés sur le
    # garde-fou is_installed_form de
    # database_exposure.py::DatabaseExposureCheck._check_install_php.
    INSTALL_FORM_STRONG_MARKERS: List[str] = [
        "weblog_title", "admin_email", "user_name",
        "information needed", "five-minute",
    ]

    def _is_real_install_form(self, body_lower: str) -> bool:
        """True si le corps montre un vrai formulaire d'installation WP
        ouvert (pas juste une mention générique du mot 'WordPress')."""
        if any(m in body_lower for m in self.INSTALL_FORM_STRONG_MARKERS):
            return True
        if "installation" in body_lower:
            return True
        if (("welcome" in body_lower or "bienvenue" in body_lower)
                and "install" in body_lower):
            return True
        return False

    def _check_install_php_content(
        self, path: str, url: str, label: str, severity: str,
        status: int, content_type: str, content_length: int,
        body: str, evidence_snippet: str, indicators: List[str],
    ) -> None:
        """Évalue wp-admin/install.php avec un garde-fou dédié.

        Le mot générique "WordPress" (un des indicateurs de la catégorie)
        ne suffit jamais, seul, à confirmer une installation ouverte, il
        faut un vrai signal de formulaire d'installation (weblog_title,
        admin_email, "installation"...). Sans ce signal, la détection reste
        confidence="potential" ; sans même l'indicateur générique, on
        retombe sur le fallback "accessible, à confirmer" habituel.
        """
        body_lower = body.lower()
        matched = [ind for ind in indicators if ind.lower() in body_lower]

        if matched and self._is_real_install_form(body_lower):
            evidence = (
                f"Exposed file detected at {path}\n"
                f"HTTP {status} | Content-Type: {content_type} "
                f"| Size: {content_length}\n"
                f"Matched indicators: {', '.join(matched)}\n"
                f"Snippet:\n{evidence_snippet}"
            )
            self._result.add_finding(
                message=f"{label}, Exposed ({severity})",
                severity=severity,
                evidence=evidence,
                url=url,
            )
            return

        if matched:
            # Seuls des indicateurs génériques (ex. "WordPress" seul) ont
            # matché, pas de preuve d'un formulaire d'installation ouvert.
            evidence = (
                f"File accessible at {path}\n"
                f"HTTP {status} | Content-Type: {content_type} "
                f"| Size: {content_length}\n"
                f"Matched (generic) indicators: {', '.join(matched)}\n"
                f"Snippet:\n{evidence_snippet}"
            )
            self._result.add_finding(
                message=(
                    f"{label}, accessible mais aucun signal de formulaire "
                    f"d'installation confirmé, à confirmer ({severity})"
                ),
                severity=severity,
                evidence=evidence,
                url=url,
                confidence="potential",
            )
            return

        if status == 200 and content_length > 100:
            evidence = (
                f"File accessible at {path}\n"
                f"HTTP {status} | Content-Type: {content_type} "
                f"| Size: {content_length}\n"
                f"Snippet:\n{evidence_snippet}"
            )
            self._result.add_finding(
                message=(
                    f"{label}, accessible (HTTP {status}, "
                    f"{content_length} bytes), à confirmer ({severity})"
                ),
                severity=severity,
                evidence=evidence,
                url=url,
                confidence="potential",
            )
