"""Check for database and configuration exposure on WordPress.

Inherits from BaseCheck. Covers SQL dump files, plugin backup directories,
phpMyAdmin/Adminer detection, wp-config-sample.php exposure, install.php
lock status, environment file exposure, default table prefix detection,
and database error disclosure visible on an ordinary page (passive: no
injection payload is ever sent).

Flagged CRITICAL:
  - Exposed SQL dump files (with SQL content indicators)
  - phpMyAdmin/Adminer accessible (login form visible)
  - wp-admin/install.php unlocked (installation form displayed)
"""

import re
from typing import Dict, List, Optional, Set, Tuple

from ..redact import redact_text
from .base import BaseCheck, CheckResult
from .signatures import is_already_installed


class DatabaseExposureCheck(BaseCheck):
    """Check for database and configuration exposure on WordPress."""

    name = "database_exposure"
    title = "Database & Configuration Exposure"
    description = (
        "Checks for exposed SQL dump files, plugin backup directories, "
        "phpMyAdmin/Adminer installations, environment file leaks, "
        "default table prefix leakage, and database error disclosure."
    )
    severity = "CRITICAL"
    access_tier = 1  # mixte : dumps, sauvegardes, .env... sous --authorized
    depends_on: List[str] = []

    # ── SQL dump base filenames (without compression extensions) ──────
    SQL_DUMP_NAMES: List[str] = [
        "database.sql",
        "db.sql",
        "backup.sql",
        "dump.sql",
        "site.sql",
        "wordpress.sql",
        "export.sql",
        "mydb.sql",
        "wp.sql",
        "data.sql",
        "dumper.sql",
        "mysqldump.sql",
        "local.sql",
        "dev.sql",
        "prod.sql",
        "test.sql",
        "fresh.sql",
        "clean.sql",
    ]

    # Compression extensions to append to each SQL dump name
    COMPRESSED_EXTS: List[str] = [".gz", ".zip", ".tar.gz"]

    # SQL content indicators (body keywords that confirm it's a real dump)
    SQL_CONTENT_INDICATORS: List[str] = [
        "INSERT INTO",
        "CREATE TABLE",
        "DROP TABLE IF EXISTS",
        "DROP TABLE",
        "MySQL dump",
        "Dump completed",
        "-- Host:",
        "-- Database:",
        "SET SQL_MODE",
        "wp_posts",
        "wp_users",
        "wp_options",
        "wp_usermeta",
    ]

    # ── Plugin backup directory paths (under wp-content/) ─────────────
    PLUGIN_BACKUP_PATHS: List[str] = [
        "wp-content/ai1wm-backups/",
        "wp-content/updraft/",
        "wp-content/uploads/backupbuddy_backups/",
        "wp-content/backupwp/",
        "wp-content/uploads/wp-all-export/exports/",
    ]

    # ── phpMyAdmin / database admin tool paths ────────────────────────
    PHPMYADMIN_PATHS: List[str] = [
        "phpmyadmin/",
        "pma/",
        "adminer.php",
        "adminer",
        "phpmyadmin4/",
        "phpmyadmin5/",
        "phpMyAdmin/",
    ]

    # ── Environment file paths ────────────────────────────────────────
    ENV_FILE_PATHS: List[str] = [
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "env.php",
        "settings.php",
    ]

    # Signaux FORTS : texte qui n'apparaît quasiment jamais hors d'une vraie
    # erreur SQL renvoyée au client (message MySQL/PDO littéral, nom de
    # fonction, classe d'exception...). Match => confidence="confirmed".
    DB_ERROR_KEYWORDS_STRONG: List[str] = [
        "You have an error in your SQL syntax",
        "WordPress database error",
        "mysqli_",
        "mysql_fetch",
        "SQLSTATE",
        "Warning: mysql",
        "supplied argument is not a valid MySQL",
        "mysqli_sql_exception",
        "PDOException",
        "Unknown column",
        "Column not found",
    ]

    # Signaux FAIBLES : mots trop génériques pour prouver une fuite à eux
    # seuls (« MySQL », « Table », « database » apparaissent dans du texte
    # de page ordinaire, docs, « Table of Contents »...). Ne comptent que
    # si la page ressemble par ailleurs à une page d'erreur (co-occurrence
    # avec error/warning/fatal), et alors seulement confidence="potential".
    DB_ERROR_KEYWORDS_WEAK: List[str] = [
        "mysql",
        "Table ",
        "database",
        "SQL syntax",
        "syntax error",
        "Fatal error:",
        "db error",
    ]

    # Marqueurs indiquant que la page ressemble réellement à une page
    # d'erreur (et pas juste à du texte qui mentionne un mot de la liste
    # faible en passant).
    _DB_ERROR_CONTEXT_MARKERS: Tuple[str, ...] = ("error", "warning", "fatal")

    # Une requête SELECT ... FROM ... WHERE échoée dans la réponse est une
    # preuve forte de fuite de requête SQL, indépendamment des mots-clés.
    _SQL_STATEMENT_RE = re.compile(
        r"select\s+.{1,200}?\s+from\s+.{1,200}?\s+where",
        re.IGNORECASE | re.DOTALL,
    )

    # ── Public API ────────────────────────────────────────────────────

    def run(self) -> CheckResult:
        """Execute the database exposure check across all categories."""
        if self.config.get("authorized"):
            self._check_sql_dumps()
            self._check_plugin_backups()
            self._check_phpmyadmin()
            self._check_wp_config_sample()
            self._check_install_php()
            self._check_env_files()
        else:
            self.note_unlinked_skipped(
                "dumps SQL, dossiers de sauvegarde, phpMyAdmin et Adminer, "
                "wp-config-sample.php, wp-admin/install.php, fichiers .env")
        self._check_table_prefix()
        self._check_db_error_disclosure()
        return self._result

    # ── 1) SQL dump files in root ─────────────────────────────────────

    def _check_sql_dumps(self) -> None:
        """Check for SQL dump files (and compressed variants) in web root."""
        # Build all path variants programmatically
        paths: List[str] = []
        for name in self.SQL_DUMP_NAMES:
            paths.append(name)
            for ext in self.COMPRESSED_EXTS:
                paths.append(name + ext)

        for path in paths:
            _, body, status, content_type = self._head_then_get(path)
            if body is None:
                continue

            if self._is_sql_dump(body):
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"SQL dump file exposed at {path} (CRITICAL)"
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/{path.lstrip('/')}",
                )
            elif status == 200 and len(body) > 100:
                # Accessible file but no SQL indicator matched, heuristic
                # only, not proof. Reported as "potential".
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Potential SQL dump accessible at {path} "
                        f"- à confirmer (HIGH, {len(body)} bytes)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/{path.lstrip('/')}",
                    confidence="potential",
                )
            elif status not in (404, 403) and len(body) > 10:
                # 403 (accès refusé) est exclu : un chemin protégé n'est
                # pas une exposition.
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"SQL dump path exists at {path} "
                        f"- à confirmer (MEDIUM, HTTP {status})"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/{path.lstrip('/')}",
                    confidence="potential",
                )

    # ── 2) Plugin backup exposure ─────────────────────────────────────

    def _check_plugin_backups(self) -> None:
        """Check plugin backup directories for exposure / directory listing."""
        for path in self.PLUGIN_BACKUP_PATHS:
            _, body, status, content_type = self._head_then_get(path)
            if body is None:
                continue

            url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
            listing_keywords = [
                "Index of", "index of", "Directory listing",
                "<title>Index of", "Parent Directory",
            ]
            backup_keywords = [".wpress", ".sql", ".zip", ".gz", ".tar",
                               ".bak", ".sqlite"]

            has_listing = any(kw in body for kw in listing_keywords)
            is_backup_content = any(kw in body for kw in backup_keywords)

            if has_listing:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Plugin backup directory listing, "
                        f"{path} (CRITICAL)"
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                    url=url,
                )
            elif is_backup_content:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Plugin backup content exposed, "
                        f"{path} (HIGH)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=url,
                )
            elif status in (200, 301, 302) and len(body) > 50:
                # Accessible but no listing / backup content matched -
                # heuristic only. 403 (accès refusé) est exclu.
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Plugin backup path accessible, "
                        f"{path} (HTTP {status}), à confirmer (MEDIUM)"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=url,
                    confidence="potential",
                )

    # ── 3) phpMyAdmin / database admin detection ──────────────────────

    def _check_phpmyadmin(self) -> None:
        """Check for phpMyAdmin, Adminer, and other DB admin tools."""
        phpmyadmin_indicators = [
            "phpMyAdmin", "pma_password", "pma_username",
            "phpmyadmin", "PHPMYADMIN",
        ]
        # NB : « Login »/« System » sont trop génériques (présents sur toute page
        # d'authentification). On garde des marqueurs spécifiques à Adminer.
        adminer_indicators = [
            "Adminer", "adminer",
            "auth[driver]", "auth[server]",
        ]

        # Combine indicators: phpMyAdmin indicators flag HIGH,
        # Adminer indicators flag CRITICAL
        for path in self.PHPMYADMIN_PATHS:
            _, body, status, content_type = self._head_then_get(path)
            if body is None:
                continue

            url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
            body_lower = body.lower()

            is_phpmyadmin = any(
                ind.lower() in body_lower
                for ind in phpmyadmin_indicators
            )
            is_adminer = any(
                ind.lower() in body_lower
                for ind in adminer_indicators
            )

            if is_adminer:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Adminer accessible at {path} "
                        f"(CRITICAL, single-file DB admin, no auth)"
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                    url=url,
                )
            elif is_phpmyadmin:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"phpMyAdmin accessible at {path} "
                        f"(HIGH, login form exposed)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=url,
                )
            elif status == 200 and len(body) > 100:
                # Accessible but no phpMyAdmin/Adminer indicator matched -
                # heuristic only.
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Potential DB admin tool at {path} "
                        f"- à confirmer (HIGH, HTTP {status}, {len(body)} bytes)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=url,
                    confidence="potential",
                )
            elif status not in (404, 403) and len(body) > 10:
                # 403 (accès refusé) est exclu : un chemin protégé n'est
                # pas une exposition.
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"DB admin path exists at {path} "
                        f"- à confirmer (MEDIUM, HTTP {status})"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=url,
                    confidence="potential",
                )

    # ── 4) wp-config-sample.php exposure ──────────────────────────────

    def _check_wp_config_sample(self) -> None:
        """Check if wp-config-sample.php is accessible."""
        path = "wp-config-sample.php"
        _, body, status, content_type = self._head_then_get(path)
        if body is None:
            return

        url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"

        # Sample config indicators, placeholder values
        sample_indicators = [
            "define(", "DB_NAME", "database_name_here",
            "username_here", "password_here",
            "table_prefix", "AUTH_KEY",
            "authentication unique keys",
        ]
        body_lower = body.lower()
        matched = [ind for ind in sample_indicators
                   if ind.lower() in body_lower]

        if matched:
            evidence = self._build_evidence(path, status, content_type, body)
            self._result.add_finding(
                message=(
                    f"wp-config-sample.php exposed at {path} "
                    f"(MEDIUM, reveals structure, salts, default prefix)"
                ),
                severity="MEDIUM",
                evidence=evidence,
                url=url,
            )
        elif status == 200 and len(body) > 50:
            # Accessible but no sample-config indicator matched, heuristic
            # only.
            evidence = self._build_evidence(path, status, content_type, body)
            self._result.add_finding(
                message=(
                    f"wp-config-sample.php accessible at {path} "
                    f"- à confirmer (LOW, HTTP {status}, {len(body)} bytes)"
                ),
                severity="LOW",
                evidence=evidence,
                url=url,
                confidence="potential",
            )

    # ── 5) wp-admin/install.php (installation lock check) ──────────────

    def _check_install_php(self) -> None:
        """Check if wp-admin/install.php is unlocked (CRITICAL if so)."""
        path = "wp-admin/install.php"
        _, body, status, content_type = self._head_then_get(path)
        if body is None:
            return

        url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"

        if is_already_installed(body):
            self._result.add_finding(
                message="wp-admin/install.php accessible mais WordPress déjà installé (verrouillé)",
                severity="INFO",
                evidence=("La page renvoie l'écran 'Déjà installé', aucune installation "
                          "ouverte. Divulgation de version possible via les assets."),
                url=url,
                confidence="confirmed",
            )
            return

        # Installation form indicators
        install_indicators = [
            "WordPress", "Installation",
            "Welcome", "five-minute",
            "weblog_title", "admin_email",
            "site title", "Administration",
        ]
        body_lower = body.lower()
        matched = [ind for ind in install_indicators
                   if ind.lower() in body_lower]

        is_installed_form = (
            "installation" in body_lower
            or "weblog_title" in body_lower
        )

        if status in (301, 302):
            # Redirect means installation is locked, OK
            location = ""
            head_resp = self.http_head(path, allow_redirects=False)
            if "Location" in head_resp.headers:
                location = head_resp.headers["Location"]
            evidence = (
                f"install.php redirected to {location} "
                f"(HTTP {status}), installation is locked"
            )
            self._result.add_finding(
                message=(
                    f"wp-admin/install.php locked (redirect to {location})"
                ),
                severity="INFO",
                evidence=evidence,
                url=url,
            )
        elif is_installed_form and matched:
            evidence = self._build_evidence(path, status, content_type, body)
            self._result.add_finding(
                message=(
                    f"wp-admin/install.php ACCESSIBLE AND UNLOCKED "
                    f"(CRITICAL, anyone can complete WordPress installation)"
                ),
                severity="CRITICAL",
                evidence=evidence,
                url=url,
            )
        elif status == 200 and len(body) > 50:
            # Accessible but no installation-form indicator matched -
            # heuristic only, lock status unconfirmed.
            evidence = self._build_evidence(path, status, content_type, body)
            self._result.add_finding(
                message=(
                    f"wp-admin/install.php accessible at {path} "
                    f"- à confirmer (HIGH, HTTP {status}, {len(body)} bytes, "
                    f"may not be locked)"
                ),
                severity="HIGH",
                evidence=evidence,
                url=url,
                confidence="potential",
            )

    # ── 6) Environment files ──────────────────────────────────────────

    def _check_env_files(self) -> None:
        """Check for exposed environment / configuration files."""
        env_indicators = [
            "DB_", "AUTH_KEY", "SECURE_AUTH_KEY",
            "LOGGED_IN_KEY", "NONCE_KEY",
            "DATABASE_URL", "WP_HOME", "WP_SITEURL",
            "APP_ENV", "APP_SECRET", "API_KEY",
            "MYSQL_", "POSTGRES_", "REDIS_",
            # NB : « password » seul est trop générique (« Lost your password? »
            # d'une page de login). On exige des clés d'affectation réelles.
            "DB_PASSWORD", "DB_USER",
        ]

        for path in self.ENV_FILE_PATHS:
            _, body, status, content_type = self._head_then_get(path)
            if body is None:
                continue

            url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
            body_lower = body.lower()
            matched = [ind for ind in env_indicators
                       if ind.lower() in body_lower]

            if matched:
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Environment file exposed at {path} "
                        f"(CRITICAL, credentials visible)"
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                    url=url,
                )
            elif status == 200 and len(body) > 50:
                # Accessible but no env indicator matched, heuristic only.
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Environment file accessible at {path} "
                        f"- à confirmer (HIGH, HTTP {status}, {len(body)} bytes)"
                    ),
                    severity="HIGH",
                    evidence=evidence,
                    url=url,
                    confidence="potential",
                )
            elif status not in (404, 403) and len(body) > 10:
                # 403 (accès refusé) est exclu : un chemin protégé n'est
                # pas une exposition.
                evidence = self._build_evidence(path, status, content_type, body)
                self._result.add_finding(
                    message=(
                        f"Environment file path exists at {path} "
                        f"- à confirmer (MEDIUM, HTTP {status})"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=url,
                    confidence="potential",
                )

    # ── 7) Default table prefix detection ─────────────────────────────

    def _check_table_prefix(self) -> None:
        """Detect default wp_ table prefix via cookies and REST API."""
        # ── a) Cookie-based detection ──
        try:
            head_resp = self.http_head("", allow_redirects=False)
            set_cookie = head_resp.headers.get("Set-Cookie", "")
        except Exception:
            set_cookie = ""

        if not set_cookie:
            # Try GET if HEAD didn't return cookies
            try:
                get_resp = self.http_get("")
                set_cookie = get_resp.headers.get("Set-Cookie", "")
            except Exception:
                set_cookie = ""

        if set_cookie:
            # Check for wp-settings- pattern in Set-Cookie
            if "wp-settings-" in set_cookie or "wp_settings" in set_cookie:
                evidence = (
                    f"Default 'wp_' table prefix detected via cookies.\n"
                    f"Set-Cookie header contains: "
                    f"{redact_text(set_cookie[:300])}"
                )
                self._result.add_finding(
                    message=(
                        "Default wp_ table prefix detected via "
                        "WordPress cookies (MEDIUM)"
                    ),
                    severity="MEDIUM",
                    evidence=evidence,
                    url=self.target,
                )

        # ── b) REST API detection ──
        try:
            api_resp = self.http_get("wp-json/wp/v2/", allow_redirects=False)
            if api_resp.status_code in (200, 201):
                evidence = (
                    f"WordPress REST API accessible, confirms "
                    f"wp_ namespace.\n"
                    f"Status: {api_resp.status_code}\n"
                    f"Response snippet: {redact_text(api_resp.text[:300])}"
                )
                self._result.add_finding(
                    message=(
                        "WordPress REST API confirmed via wp-json "
                        "(LOW, confirms default namespace)"
                    ),
                    severity="LOW",
                    evidence=evidence,
                    url=f"{self.target.rstrip('/')}/wp-json/wp/v2/",
                )
        except Exception:
            pass

        # Also check wordpress_test_cookie in Set-Cookie
        if "wordpress_test_cookie" in set_cookie:
            evidence = (
                f"WordPress test cookie confirms WP presence.\n"
                f"Set-Cookie: {redact_text(set_cookie[:300])}"
            )
            self._result.add_finding(
                message=(
                    "WordPress presence confirmed via "
                    "wordpress_test_cookie (INFO)"
                ),
                severity="INFO",
                evidence=evidence,
                url=self.target,
            )

    # ── 8) Database error disclosure ──────────────────────────────────

    def _classify_db_error(
        self, body: str,
    ) -> Optional[Tuple[str, List[str]]]:
        """Classifie une réponse pour une fuite d'erreur SQL/DB réelle.

        Retourne (confidence, matched_keywords) ou None si rien de probant.
        Un signal FORT (texte de message d'erreur MySQL/PDO littéral, ou une
        requête SELECT…FROM…WHERE échoée) => "confirmed". Un signal FAIBLE
        seul (« mysql », « Table », « database »...) ne compte que si la
        page ressemble par ailleurs à une page d'erreur, et alors seulement
        "potential" : mentionner ces mots dans du texte ordinaire n'est pas
        une preuve de fuite.
        """
        body_lower = body.lower()

        strong_matched = [
            kw for kw in self.DB_ERROR_KEYWORDS_STRONG
            if kw.lower() in body_lower
        ]
        if self._SQL_STATEMENT_RE.search(body):
            strong_matched.append("SELECT…FROM…WHERE (échoé)")

        if strong_matched:
            return "confirmed", strong_matched

        weak_matched = [
            kw for kw in self.DB_ERROR_KEYWORDS_WEAK
            if kw.lower() in body_lower
        ]
        has_error_context = any(
            marker in body_lower for marker in self._DB_ERROR_CONTEXT_MARKERS
        )
        if weak_matched and has_error_context:
            return "potential", weak_matched

        return None

    def _check_db_error_disclosure(self) -> None:
        """Repère une erreur SQL divulguée sur une page ordinaire (accueil).

        Strictement passif : aucune charge d'injection n'est envoyée (la
        version publique du scanner n'émet aucune sonde active). Une page
        qui affiche déjà une erreur de base de données à tout visiteur
        trahit la structure des requêtes et la configuration de débogage.
        """
        label = "page d'accueil"
        try:
            resp = self.http_get("/")
            body = resp.text
        except Exception:
            return
        if not body:
            return
        classification = self._classify_db_error(body)
        if classification is None:
            return
        confidence, matched = classification
        keywords_str = ", ".join(sorted(matched))
        evidence = (
            f"Database error disclosure on {label}\n"
            f"HTTP {resp.status_code}\n"
            f"Matched error keywords: {keywords_str}\n"
            f"Snippet:\n{redact_text(body[:600]).strip()}"
        )
        message_suffix = (
            "(MEDIUM : SQL errors revealed)"
            if confidence == "confirmed"
            else "à confirmer (MEDIUM : indices faibles)"
        )
        self._result.add_finding(
            message=f"Database error disclosure on {label} {message_suffix}",
            severity="MEDIUM",
            evidence=evidence,
            url=self.target,
            confidence=confidence,
        )

    # ── Internal helpers ──────────────────────────────────────────────

    def _head_then_get(
        self, path: str,
    ) -> tuple:
        """HEAD-first-then-GET strategy.

        Returns (response, body_text, status_code, content_type).
        body_text is None if the file doesn't exist or can't be fetched.
        """
        # Step 1: HEAD
        try:
            head_resp = self.http_head(path, allow_redirects=False)
        except Exception:
            return (None, None, 0, "")

        if head_resp.status_code == 404:
            return (None, None, 404, "")

        # Step 2: GET
        try:
            get_resp = self.http_get(path)
        except Exception:
            return (None, None, 0, "")

        if get_resp.status_code == 404:
            return (None, None, 404, "")

        # Site soft-404 : 200 + page d'accueil pour toute URL inexistante.
        # Une réponse ≈ témoin « absent » n'est pas une vraie ressource : on
        # renvoie le même tuple « absent » que pour un vrai 404.
        if self._is_soft404(get_resp):
            return (None, None, 404, "")

        body = get_resp.text
        status = get_resp.status_code
        content_type = get_resp.headers.get("Content-Type", "")

        # Ignore trivial responses (< 10 bytes)
        if len(body) < 10:
            return (None, None, status, content_type)

        return (get_resp, body, status, content_type)

    def _is_sql_dump(self, body: str) -> bool:
        """Check if body content matches SQL dump indicators."""
        body_lower = body.lower()
        matches = sum(
            1 for ind in self.SQL_CONTENT_INDICATORS
            if ind.lower() in body_lower
        )
        # At least 2 indicators must match to reduce false positives
        return matches >= 2

    def _build_evidence(
        self, path: str, status: int,
        content_type: str, body: str,
    ) -> str:
        """Build an evidence string for a finding (secrets masqués)."""
        snippet = redact_text(body[:600]).strip()
        if len(body) > 600:
            snippet = snippet[:597] + "..."

        return (
            f"Path: {path}\n"
            f"HTTP {status} | Content-Type: {content_type} "
            f"| Size: {len(body)} bytes\n"
            f"Snippet:\n{snippet}"
        )
