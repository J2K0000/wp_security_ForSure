"""Check, Détection de plugins et thèmes nullés (piratés) installés à distance.

Check de niveau 2 (chemins devinés) : lancé seulement avec --authorized.
Le fichier principal PHP d'une extension n'est jamais demandé (un GET
l'exécuterait) : ses en-têtes (Version, Author, Author URI, licence) ne sont
pas évaluables de l'extérieur (constat INFO).

Détecte :
1. Version mismatch (readme.txt Stable tag vs fichier principal Version header)
2. Author URI pointing to known nulled distribution sites
3. Plugin slug not found on WordPress.org API (pour plugins gratuits)
4. Plugins marqués 'closed' sur wp.org mais encore installés
5. Author name mismatch / suspicious author URIs
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseCheck, CheckResult

logger = logging.getLogger(__name__)

# Sentinel : statut wp.org indéterminé (erreur réseau, rate-limit, non-200).
# À distinguer de None (= plugin définitivement absent du repository).
_WP_ORG_UNKNOWN = object()

# ── Sites de redistribution de nullés (blacklist) ──────────────────────────
NULLED_DOMAINS = {
    # GPL / Nulled sites
    "gplfreak.com", "gplfreak.net", "www.gplfreak.com",
    "gplpapa.com", "www.gplpapa.com",
    "gpldl.com", "gpldownload.com", "www.gpldl.com",
    "nulled.org", "nulledfree.com", "nulled.pro", "www.nulled.org",
    "freemiumdownloader.com", "freemiumwp.com", "www.freemiumdownloader.com",
    "pluginsgpl.net", "gplgpl.com",
    "wpnulled.org", "wpnulled.io",
    "nulled.to", "www.nulled.to",
    "babia.to", "www.babia.to",
    "leak.sx", "www.leak.sx",
    # General suspicious TLDs often used for nulled distribution
    "gplclub.org",
    "gplplus.com",
    "gplmaster.com",
    "themeforest.net.download",
    "wordpressnull.com",
    "nullwp.com",
}

# Patterns d'URI suspects (regex)
SUSPICIOUS_URI_PATTERNS = [
    re.compile(r"(?i)(gpl|freak|nulled|null|papa|babia|leak|freemium)"),
    re.compile(r"(?i)/nulled/"),
    re.compile(r"(?i)wp-?nulled?"),
    re.compile(r"(?i)plugin-?gpl?"),
]

# Patterns pour les versions qui ressemblent à des nullés
NULLED_VERSION_PATTERNS = [
    re.compile(r"(?i)nulled"),
    re.compile(r"(?i)null"),
    re.compile(r"(?i)patched"),
    re.compile(r"(?i)mod(ified|ded)?"),
    re.compile(r"(?i)free"),
    re.compile(r"(?i)gpl"),
    re.compile(r"^1\.0\.0$"),  # Stable tag laissé à 1.0.0 par les nullés
]

# ── Plugins premium fréquemment nullés ─────────────────────────────────────
# Chaque entrée contient :
#   slug             : identifiant du plugin
#   name             : nom lisible
#   official_author  : auteur officiel (insensible à la casse)
#   official_uri     : URI officiel (fragment)
#   paths            : chemins relatifs à tester (fichier principal, readme)
#   is_premium       : True = plugin premium (non présent sur wp.org)
#   wp_org_slug      : slug sur WordPress.org (si différent)

KNOWN_NULLED_PLUGINS = [
    {
        "slug": "elementor-pro",
        "name": "Elementor Pro",
        "official_author": "Elementor.com",
        "official_uri": "elementor.com",
        "main_file": "elementor-pro.php",
        "paths": [
            "wp-content/plugins/elementor-pro/",
            "wp-content/plugins/elementor-pro/elementor-pro.php",
            "wp-content/plugins/elementor-pro/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": None,
    },
    {
        "slug": "js_composer",
        "name": "WPBakery Page Builder",
        "official_author": "WPBakery",
        "official_uri": "wpbakery.com",
        "main_file": "js_composer.php",
        "paths": [
            "wp-content/plugins/js_composer/",
            "wp-content/plugins/js_composer/js_composer.php",
            "wp-content/plugins/js_composer/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": None,
    },
    {
        "slug": "revslider",
        "name": "Slider Revolution",
        "official_author": "ThemePunch",
        "official_uri": "themepunch.com",
        "main_file": "revslider.php",
        "paths": [
            "wp-content/plugins/revslider/",
            "wp-content/plugins/revslider/revslider.php",
            "wp-content/plugins/revslider/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": "revslider",
    },
    {
        "slug": "gravityforms",
        "name": "Gravity Forms",
        "official_author": "Gravity Forms",
        "official_uri": "gravityforms.com",
        "main_file": "gravityforms.php",
        "paths": [
            "wp-content/plugins/gravityforms/",
            "wp-content/plugins/gravityforms/gravityforms.php",
            "wp-content/plugins/gravityforms/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": None,
    },
    {
        "slug": "advanced-custom-fields-pro",
        "name": "Advanced Custom Fields PRO",
        "official_author": "WP Engine",
        "official_uri": "advancedcustomfields.com",
        "main_file": "acf.php",
        "paths": [
            "wp-content/plugins/advanced-custom-fields-pro/",
            "wp-content/plugins/advanced-custom-fields-pro/acf.php",
            "wp-content/plugins/advanced-custom-fields-pro/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": "advanced-custom-fields",
    },
    {
        "slug": "seo-by-rank-math-pro",
        "name": "Rank Math SEO Pro",
        "official_author": "Rank Math",
        "official_uri": "rankmath.com",
        "main_file": "rank-math-pro.php",
        "paths": [
            "wp-content/plugins/seo-by-rank-math-pro/",
            "wp-content/plugins/seo-by-rank-math-pro/rank-math-pro.php",
            "wp-content/plugins/seo-by-rank-math-pro/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": "seo-by-rank-math",
    },
    {
        "slug": "wp-rocket",
        "name": "WP Rocket",
        "official_author": "WP Media",
        "official_uri": "wp-rocket.me",
        "main_file": "wp-rocket.php",
        "paths": [
            "wp-content/plugins/wp-rocket/",
            "wp-content/plugins/wp-rocket/wp-rocket.php",
            "wp-content/plugins/wp-rocket/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": None,
    },
    {
        "slug": "woocommerce-subscriptions",
        "name": "WooCommerce Subscriptions",
        "official_author": "WooCommerce",
        "official_uri": "woocommerce.com",
        "main_file": "woocommerce-subscriptions.php",
        "paths": [
            "wp-content/plugins/woocommerce-subscriptions/",
            "wp-content/plugins/woocommerce-subscriptions/woocommerce-subscriptions.php",
            "wp-content/plugins/woocommerce-subscriptions/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": None,
    },
    {
        "slug": "unyson",
        "name": "Unyson (Framework)",
        "official_author": "ThemeFuse",
        "official_uri": "theme-fuse.com",
        "main_file": "unyson.php",
        "paths": [
            "wp-content/plugins/unyson/",
            "wp-content/plugins/unyson/unyson.php",
            "wp-content/plugins/unyson/readme.txt",
        ],
        "is_premium": False,
        "wp_org_slug": "unyson",
    },
    {
        "slug": "wordpress-seo-premium",
        "name": "Yoast SEO Premium",
        "official_author": "Team Yoast",
        "official_uri": "yoast.com",
        "main_file": "wordpress-seo-premium.php",
        "paths": [
            "wp-content/plugins/wordpress-seo-premium/",
            "wp-content/plugins/wordpress-seo-premium/wordpress-seo-premium.php",
            "wp-content/plugins/wordpress-seo-premium/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": "wordpress-seo",
    },
    {
        "slug": "ithemes-security-pro",
        "name": "iThemes Security Pro",
        "official_author": "iThemes",
        "official_uri": "ithemes.com",
        "main_file": "ithemes-security-pro.php",
        "paths": [
            "wp-content/plugins/ithemes-security-pro/",
            "wp-content/plugins/ithemes-security-pro/ithemes-security-pro.php",
            "wp-content/plugins/ithemes-security-pro/readme.txt",
        ],
        "is_premium": True,
        "wp_org_slug": "better-wp-security",
    },
    {
        "slug": "elementor",
        "name": "Elementor (Free)",
        "official_author": "Elementor.com",
        "official_uri": "elementor.com",
        "main_file": "elementor.php",
        "paths": [
            "wp-content/plugins/elementor/",
            "wp-content/plugins/elementor/elementor.php",
            "wp-content/plugins/elementor/readme.txt",
        ],
        "is_premium": False,
        "wp_org_slug": "elementor",
    },
    {
        "slug": "contact-form-7",
        "name": "Contact Form 7",
        "official_author": "Takayuki Miyoshi",
        "official_uri": "contactform7.com",
        "main_file": "wp-contact-form-7.php",
        "paths": [
            "wp-content/plugins/contact-form-7/",
            "wp-content/plugins/contact-form-7/wp-contact-form-7.php",
            "wp-content/plugins/contact-form-7/readme.txt",
        ],
        "is_premium": False,
        "wp_org_slug": "contact-form-7",
    },
    {
        "slug": "wordfence",
        "name": "Wordfence Security",
        "official_author": "Wordfence",
        "official_uri": "wordfence.com",
        "main_file": "wordfence.php",
        "paths": [
            "wp-content/plugins/wordfence/",
            "wp-content/plugins/wordfence/wordfence.php",
            "wp-content/plugins/wordfence/readme.txt",
        ],
        "is_premium": False,
        "wp_org_slug": "wordfence",
    },
]

# Thèmes premium fréquemment nullés
KNOWN_NULLED_THEMES = [
    {
        "slug": "Divi",
        "name": "Divi",
        "official_author": "Elegant Themes",
        "official_uri": "elegantthemes.com",
        "paths": [
            "wp-content/themes/Divi/",
            "wp-content/themes/Divi/style.css",
        ],
        "is_premium": True,
    },
    {
        "slug": "Avada",
        "name": "Avada",
        "official_author": "ThemeFusion",
        "official_uri": "theme-fusion.com",
        "paths": [
            "wp-content/themes/Avada/",
            "wp-content/themes/Avada/style.css",
        ],
        "is_premium": True,
    },
    {
        "slug": "betheme",
        "name": "Betheme",
        "official_author": "Muffin Group",
        "official_uri": "muffingroup.com",
        "paths": [
            "wp-content/themes/betheme/",
            "wp-content/themes/betheme/style.css",
        ],
        "is_premium": True,
    },
    {
        "slug": "the7",
        "name": "The7",
        "official_author": "Dream-Theme",
        "official_uri": "dream-theme.com",
        "paths": [
            "wp-content/themes/dt-the7/",
            "wp-content/themes/dt-the7/style.css",
        ],
        "is_premium": True,
    },
]


class NulledPluginsCheck(BaseCheck):
    """Vérifie la présence de plugins et thèmes nullés (piratés)."""

    name = "nulled_plugins"
    title = "Détection de Plugins & Thèmes Nullés"
    description = (
        "Recherche les plugins et thèmes nullés/piratés installés sur le site. "
        "Un plugin nullé contient quasi-certainement une backdoor, ce qui représente "
        "un risque de sécurité critique pour le site."
    )
    severity = "CRITICAL"
    access_tier = 2  # entièrement fait de chemins devinés : non lancé sans --authorized

    # Cache pour les réponses API WP.org (évite les doublons)
    _wp_org_cache: Dict[str, Optional[dict]] = {}

    def run(self) -> CheckResult:
        """Exécute la recherche de plugins nullés."""
        findings = []

        # 1. Vérifier les plugins premium fréquemment nullés
        for plugin in KNOWN_NULLED_PLUGINS:
            result = self._check_plugin(plugin)
            findings.extend(result)

        # 2. Vérifier les thèmes premium fréquemment nullés
        for theme in KNOWN_NULLED_THEMES:
            result = self._check_theme(theme)
            findings.extend(result)

        self.note_not_assessable(
            "En-têtes du fichier principal PHP des extensions (Version, Author, "
            "Author URI, clé de licence factice)")

        # Ajouter les findings au résultat
        for finding in findings:
            self._result.add_finding(
                message=finding["message"],
                severity=finding.get("severity", "CRITICAL"),
                evidence=finding.get("evidence", ""),
                url=finding.get("url", ""),
                confidence=finding.get("confidence", "confirmed"),
            )

        return self._result

    # ── Core detection methods ────────────────────────────────────────────

    def _check_plugin(self, plugin: dict) -> List[dict]:
        """Vérifie un plugin spécifique pour les signes de nulled."""
        slug = plugin["slug"]
        findings = []
        evidence_parts = []

        # Tester si le plugin existe sur le site (un des chemins)
        exists, base_path = self._plugin_exists(slug, plugin.get("paths", []))
        if not exists:
            return []

        plugin_name = plugin["name"]

        # ── Fichier principal : jamais demandé ─────────────────────────
        # C'est un fichier PHP sous wp-content/plugins/ : un GET l'exécuterait.
        # Ses en-têtes restent inconnus (constat INFO dans run()).
        main_headers = {}
        main_content = None

        # ── Récupérer readme.txt ─────────────────────────────────────
        readme_stable_tag = None
        readme_content = None
        readme_path = plugin["paths"][2] if len(plugin["paths"]) > 2 else (
            f"wp-content/plugins/{slug}/readme.txt"
        )

        readme_content = self._fetch_url(readme_path)
        if readme_content:
            readme_stable_tag = self._extract_stable_tag(readme_content)
            if readme_stable_tag:
                evidence_parts.append(f"readme Stable tag: {readme_stable_tag}")

        # ── 1. Version Mismatch ──────────────────────────────────────
        version_issues = self._check_version_mismatch(
            plugin, main_headers, readme_stable_tag, readme_content
        )
        findings.extend(version_issues)

        # ── 2. Author URI Check ──────────────────────────────────────
        author_issues = self._check_author_uri(plugin, main_headers)
        findings.extend(author_issues)

        # ── 3. Author Name Mismatch ──────────────────────────────────
        author_name_issues = self._check_author_name(plugin, main_headers)
        findings.extend(author_name_issues)

        # ── 4. WP.org API Check ──────────────────────────────────────
        wp_org_issues = self._check_wp_org(plugin, main_headers, readme_stable_tag)
        findings.extend(wp_org_issues)

        # ── 5. Suspicious content in readme/files ────────────────────
        if readme_content:
            suspicious_content = self._check_suspicious_content(
                readme_content, plugin_name, slug
            )
            if suspicious_content:
                findings.append({
                    "message": suspicious_content,
                    "severity": "HIGH",
                    "evidence": f"Contenu suspect détecté dans le fichier readme.txt de {plugin_name}",
                    "url": self._build_url(readme_path),
                })

        # ── 6. Nulled version patterns in Stable tag ──────────────────
        if readme_stable_tag:
            for pattern in NULLED_VERSION_PATTERNS:
                if pattern.search(readme_stable_tag):
                    findings.append({
                        "message": (
                            f"Le plugin {plugin_name} a une version suspecte "
                            f"dans readme.txt : '{readme_stable_tag}', typique des nullés"
                        ),
                        "severity": "HIGH",
                        "evidence": f"Stable tag: {readme_stable_tag} (match: {pattern.pattern})",
                        "url": self._build_url(readme_path),
                    })
                    break

        # ── 7. Vérifier la présence de fichiers de licence pour premium ──
        if plugin.get("is_premium", False) and main_content:
            lic_issues = self._check_license_files(plugin, main_content)
            findings.extend(lic_issues)

        return findings

    def _check_theme(self, theme: dict) -> List[dict]:
        """Vérifie un thème spécifique pour les signes de nulled."""
        slug = theme["slug"]
        findings = []

        # Tester si le thème existe
        style_path = theme["paths"][1] if len(theme["paths"]) > 1 else (
            f"wp-content/themes/{slug}/style.css"
        )

        style_content = self._fetch_url(style_path)
        if not style_content:
            return []

        theme_name = theme["name"]
        style_headers = self._parse_theme_headers(style_content)
        evidence_parts = [f"{k}: {v}" for k, v in style_headers.items()]

        # ── Author check ────────────────────────────────────────────
        author = style_headers.get("Author", "")
        author_uri = style_headers.get("Author URI", "")

        # Author name mismatch
        official_author = theme.get("official_author", "")
        if official_author and author:
            # Nettoyer
            author_clean = author.strip().lower()
            official_clean = official_author.strip().lower()
            if author_clean != official_clean:
                # Vérifier s'il ressemble à un site de nullés
                if self._is_suspicious_author(author_clean):
                    findings.append({
                        "message": (
                            f"Le thème {theme_name} a un auteur suspect : "
                            f"'{author}' (officiel: '{official_author}')"
                        ),
                        "severity": "CRITICAL",
                        "evidence": f"Author: {author} vs officiel: {official_author}",
                        "url": self._build_url(style_path),
                    })
                else:
                    findings.append({
                        "message": (
                            f"Le thème {theme_name} a un auteur différent "
                            f"de l'officiel : '{author}' (attendu: '{official_author}')"
                        ),
                        "severity": "MEDIUM",
                        "evidence": f"Author: {author} vs officiel: {official_author}",
                        "url": self._build_url(style_path),
                    })

        # Author URI suspicious
        if author_uri:
            uri_issues = self._check_uri_suspicious(
                author_uri, theme_name, "Author URI", style_path
            )
            if uri_issues:
                uri_issues[0]["severity"] = "CRITICAL"
                findings.extend(uri_issues)

        # Vérifier si l'URI officiel est absent ou modifié
        official_uri = theme.get("official_uri", "")
        if official_uri and author_uri:
            if official_uri not in author_uri.lower():
                if not self._is_suspicious_uri(author_uri):  # déjà signalé ci-dessus
                    findings.append({
                        "message": (
                            f"Le thème {theme_name} a un Author URI modifié : "
                            f"'{author_uri}' (officiel: devrait contenir '{official_uri}')"
                        ),
                        "severity": "HIGH",
                        "evidence": f"Author URI: {author_uri} vs officiel: *{official_uri}*",
                        "url": self._build_url(style_path),
                    })

        # ── Version check from style.css ─────────────────────────────
        # Les thèmes peuvent aussi avoir readme.txt
        readme_path = f"wp-content/themes/{slug}/readme.txt"
        readme_content = self._fetch_url(readme_path)
        style_version = style_headers.get("Version", "")

        if readme_content:
            stable_tag = self._extract_stable_tag(readme_content)
            if stable_tag and style_version and stable_tag != style_version:
                findings.append({
                    "message": (
                        f"Version mismatch pour le thème {theme_name} : "
                        f"readme.txt dit '{stable_tag}' mais style.css dit '{style_version}'"
                    ),
                    "severity": "HIGH",
                    "evidence": f"Stable tag: {stable_tag} != Version: {style_version}",
                    "url": self._build_url(style_path),
                })

        return findings

    # ── Helper: Version mismatch detection ────────────────────────────────

    def _check_version_mismatch(
        self,
        plugin: dict,
        headers: dict,
        stable_tag: Optional[str],
        readme_content: Optional[str],
    ) -> List[dict]:
        """Vérifie les incohérences de version (readme.txt vs main file)."""
        findings = []
        slug = plugin["slug"]
        plugin_name = plugin["name"]
        version_header = headers.get("Version", "")

        if not version_header and not stable_tag:
            return []

        # Version dans readme.txt (Stable tag) vs Version header
        if stable_tag and version_header and stable_tag.strip() != version_header.strip():
            # Un écart Stable tag / Version a des causes légitimes (readme non
            # régénéré, canal beta/RC, plugin premium), heuristique, pas une
            # preuve de nullé → MEDIUM/potential.
            findings.append({
                "message": (
                    f"Version mismatch pour {plugin_name} : "
                    f"readme.txt (Stable tag) = '{stable_tag}' "
                    f"mais en-tête Version = '{version_header}'"
                ),
                "severity": "MEDIUM",
                "evidence": f"Stable tag: {stable_tag} | Version header: {version_header}",
                "url": self._build_url(f"wp-content/plugins/{slug}/readme.txt"),
                "confidence": "potential",
            })

        # Stable tag = 1.0.0 (souvent laissé par défaut par les nullés)
        if stable_tag and stable_tag.strip() == "1.0.0" and version_header and version_header.strip() != "1.0.0":
            findings.append({
                "message": (
                    f"Le plugin {plugin_name} a un Stable tag à 1.0.0 dans readme.txt "
                    f"mais une version '{version_header}' dans le code, typique des nullés"
                ),
                "severity": "HIGH",
                "evidence": f"Stable tag: {stable_tag} (défaut) vs Version: {version_header}",
                "url": self._build_url(f"wp-content/plugins/{slug}/readme.txt"),
            })

        return findings

    # ── Helper: Author URI check ──────────────────────────────────────────

    def _check_author_uri(self, plugin: dict, headers: dict) -> List[dict]:
        """Vérifie si l'Author URI pointe vers un site de nullés."""
        findings = []
        slug = plugin["slug"]
        plugin_name = plugin["name"]
        author_uri = headers.get("Author URI", "")

        if not author_uri:
            return []

        # Vérifier les domaines de la blacklist
        parsed = urlparse(author_uri)
        domain = parsed.netloc.lower()

        # Enlever www. pour la comparaison
        if domain.startswith("www."):
            domain = domain[4:]

        if domain in NULLED_DOMAINS:
            findings.append({
                "message": (
                    f"Author URI du plugin {plugin_name} pointe vers un site "
                    f"de nullés connu : {author_uri}"
                ),
                "severity": "CRITICAL",
                "evidence": f"Author URI: {author_uri} (domaine blacklisté: {domain})",
                "url": self._build_url(f"wp-content/plugins/{slug}/{plugin.get('main_file', slug + '.php')}"),
            })
            return findings

        # Vérifier les patterns suspects dans l'URI
        return self._check_uri_suspicious(
            author_uri, plugin_name, "Author URI",
            f"wp-content/plugins/{slug}/{plugin.get('main_file', slug + '.php')}"
        )

    def _check_uri_suspicious(
        self, uri: str, item_name: str, field_name: str, file_path: str
    ) -> List[dict]:
        """Vérifie si une URI est suspecte (patterns de nullés)."""
        uri_lower = uri.lower()

        for pattern in SUSPICIOUS_URI_PATTERNS:
            if pattern.search(uri_lower):
                return [{
                    "message": (
                        f"Le champ {field_name} de {item_name} contient un pattern "
                        f"suspect : '{uri}'"
                    ),
                    "severity": "HIGH",
                    "evidence": f"{field_name}: {uri} (match: {pattern.pattern})",
                    "url": self._build_url(file_path),
                }]

        return []

    # ── Helper: Author name mismatch ─────────────────────────────────────

    def _check_author_name(self, plugin: dict, headers: dict) -> List[dict]:
        """Vérifie si le nom de l'auteur correspond à l'officiel."""
        findings = []
        official_author = plugin.get("official_author", "")
        author = headers.get("Author", "")

        if not official_author or not author:
            return []

        author_clean = author.strip().lower()
        official_clean = official_author.strip().lower()

        # Comparaison TOLÉRANTE : les en-têtes réels varient (ex. « Elementor.com »
        # vs « Elementor »). Si l'un contient l'autre, c'est le même auteur.
        def _same_author(a, b):
            a = a.replace(".com", "").replace(",", " ").strip()
            b = b.replace(".com", "").replace(",", " ").strip()
            return a == b or a in b or b in a

        # Vérifier si l'auteur modifié ressemble à un nullé
        if author_clean != official_clean and not _same_author(author_clean, official_clean):
            if self._is_suspicious_author(author_clean):
                findings.append({
                    "message": (
                        f"Le plugin {plugin['name']} a un auteur suspect : "
                        f"'{author}' (officiel: '{official_author}')"
                    ),
                    "severity": "CRITICAL",
                    "evidence": f"Author: {author} vs officiel: {official_author}",
                    "url": self._build_url(
                        f"wp-content/plugins/{plugin['slug']}/{plugin.get('main_file', plugin['slug'] + '.php')}"
                    ),
                })
            else:
                findings.append({
                    "message": (
                        f"Le plugin {plugin['name']} a un auteur différent "
                        f"de l'officiel : '{author}' (attendu: '{official_author}')"
                    ),
                    "severity": "MEDIUM",
                    "evidence": f"Author: {author} vs officiel: {official_author}",
                    "confidence": "potential",
                    "url": self._build_url(
                        f"wp-content/plugins/{plugin['slug']}/{plugin.get('main_file', plugin['slug'] + '.php')}"
                    ),
                })

        return findings

    def _is_suspicious_uri(self, uri: str) -> bool:
        """Vérifie si une URI est suspecte (nullé)."""
        uri_lower = uri.lower()
        parsed = urlparse(uri)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        if domain in NULLED_DOMAINS:
            return True
        for pattern in SUSPICIOUS_URI_PATTERNS:
            if pattern.search(uri_lower):
                return True
        return False

    def _is_suspicious_author(self, author: str) -> bool:
        """Vérifie si un nom d'auteur est suspect (nullé)."""
        suspicious_authors = {
            "gplfreak", "gplpapa", "gpldl", "nulled", "nulled team",
            "freemium", "gplgpl", "pluginsgpl", "wpnulled",
            "gpl master", "gpl club",
        }
        author_lower = author.strip().lower()
        if author_lower in suspicious_authors:
            return True

        for pattern in SUSPICIOUS_URI_PATTERNS:
            if pattern.search(author_lower):
                return True

        return False

    # ── Helper: WordPress.org API ────────────────────────────────────────

    def _check_wp_org(
        self,
        plugin: dict,
        headers: dict,
        stable_tag: Optional[str],
    ) -> List[dict]:
        """Vérifie le statut du plugin sur WordPress.org."""
        findings = []
        slug = plugin["slug"]
        plugin_name = plugin["name"]
        wp_org_slug = plugin.get("wp_org_slug") or slug

        # Ne pas vérifier les plugins premium connus (pas sur wp.org)
        if plugin.get("is_premium", False) and plugin.get("wp_org_slug") is None:
            return []

        # Appel API WordPress.org
        api_data = self._fetch_wp_org_plugin(wp_org_slug)
        if api_data is _WP_ORG_UNKNOWN:
            # Statut indéterminé (réseau/rate-limit) : ne rien conclure.
            return findings
        if api_data is None:
            # Plugin not found on wp.org
            if not plugin.get("is_premium", False):
                # Un plugin gratuit devrait être sur wp.org. L'absence est un
                # signal fort de risque (plugin non maintenu / falsifié / nullé),
                # mais ce n'est PAS une preuve directe de backdoor → potential.
                findings.append({
                    "message": (
                        f"Le plugin gratuit {plugin_name} n'est pas trouvé "
                        f"sur WordPress.org (slug: {wp_org_slug}), plugin "
                        f"probablement non maintenu ou falsifié, à vérifier "
                        f"manuellement (aucune mise à jour de sécurité garantie)"
                    ),
                    "severity": "CRITICAL",
                    "evidence": (
                        f"API WordPress.org: plugin '{wp_org_slug}' not found. "
                        f"Un plugin gratuit devrait être dans le repository officiel. "
                        f"Ceci est une heuristique d'absence, pas une preuve de compromission."
                    ),
                    "url": f"https://api.wordpress.org/plugins/info/1.0/{wp_org_slug}.json",
                    "confidence": "potential",
                })
            elif plugin.get("wp_org_slug") is not None:
                # Plugin premium AVEC un slug wp.org = plugin retiré du repo.
                # Le retrait prouve l'absence de mises à jour de sécurité
                # officielles (plugin non maintenu), PAS la présence d'une
                # backdoor → potential, à vérifier manuellement.
                findings.append({
                    "message": (
                        f"Le plugin {plugin_name} (slug: {wp_org_slug}) a été "
                        f"retiré du repository WordPress.org, plugin non maintenu, "
                        f"plus aucune mise à jour de sécurité officielle. À vérifier "
                        f"manuellement : ceci ne prouve pas, à lui seul, une compromission"
                    ),
                    "severity": "CRITICAL",
                    "evidence": (
                        f"Plugin '{wp_org_slug}' n'existe plus sur WordPress.org. "
                        f"Plugin retiré = fermé (closed) sans notification publique. "
                        f"Version installée ne recevra aucun correctif de sécurité. "
                        f"Le retrait ne prouve pas, à lui seul, une compromission active."
                    ),
                    "url": f"https://api.wordpress.org/plugins/info/1.0/{wp_org_slug}.json",
                    "confidence": "potential",
                })
            return findings

        # Plugin trouvé, vérifier s'il est fermé
        if api_data.get("closed", False):
            # 'closed' = non maintenu, pas de MAJ sécurité. Ce n'est pas une
            # preuve de backdoor → potential, à vérifier manuellement.
            findings.append({
                "message": (
                    f"Le plugin {plugin_name} est marqué comme FERMÉ (closed) "
                    f"sur WordPress.org mais est toujours installé, plugin non "
                    f"maintenu, aucune mise à jour de sécurité. À vérifier "
                    f"manuellement : le statut 'closed' seul ne prouve pas une compromission"
                ),
                "severity": "CRITICAL",
                "evidence": (
                    f"Plugin '{wp_org_slug}' est 'closed' sur WordPress.org. "
                    f"Plus aucune mise à jour de sécurité n'est publiée."
                ),
                "url": f"https://wordpress.org/plugins/{wp_org_slug}/",
                "confidence": "potential",
            })

        # Comparer la version
        wp_org_version = api_data.get("version", "")
        installed_version = stable_tag or headers.get("Version", "")

        if wp_org_version and installed_version:
            # Si la version installée > version wp.org, c'est suspect
            # (sauf pour premium où c'est normal)
            if self._version_compare(installed_version, wp_org_version) > 0:
                if not plugin.get("is_premium", False):
                    findings.append({
                        "message": (
                            f"Le plugin gratuit {plugin_name} a une version installée "
                            f"({installed_version}) supérieure à la version officielle "
                            f"sur WordPress.org ({wp_org_version}), modification suspecte"
                        ),
                        "severity": "HIGH",
                        "evidence": (
                            f"Version installée: {installed_version} "
                            f"| Version WP.org: {wp_org_version}"
                        ),
                        "url": f"https://wordpress.org/plugins/{wp_org_slug}/",
                    })

        return findings

    def _fetch_wp_org_plugin(self, slug: str) -> Optional[dict]:
        """Interroge l'API WordPress.org pour un slug de plugin."""
        # Cache hit ?
        if slug in self._wp_org_cache:
            return self._wp_org_cache[slug]

        url = f"https://api.wordpress.org/plugins/info/1.0/{slug}.json"
        try:
            resp = self.http_get_url(url, timeout=15)
        except Exception as e:
            logger.warning(f"WP.org API error for slug '{slug}': {e}")
            self._wp_org_cache[slug] = _WP_ORG_UNKNOWN  # réseau : indéterminé
            return _WP_ORG_UNKNOWN

        if resp.status_code != 200:
            # 404/429/5xx : ne prouve PAS l'absence du plugin → indéterminé
            self._wp_org_cache[slug] = _WP_ORG_UNKNOWN
            return _WP_ORG_UNKNOWN
        try:
            data = resp.json()
        except Exception:
            self._wp_org_cache[slug] = _WP_ORG_UNKNOWN
            return _WP_ORG_UNKNOWN
        # 200 + erreur/null = plugin définitivement absent du repository.
        if not data or "error" in data:
            self._wp_org_cache[slug] = None
            return None
        self._wp_org_cache[slug] = data
        return data

    # ── Helper: License files for premium plugins ────────────────────────

    def _check_license_files(self, plugin: dict, main_content: str) -> List[dict]:
        """Vérifie la présence d'indices de licence absente/factice."""
        findings = []
        slug = plugin["slug"]
        plugin_name = plugin["name"]

        license_indicators = [
            # Licence absente ou commentée
            (r"(?i)(license|licence)\s*(key|check|verify|status)", "gestion de licence"),
            (r"(?i)(edd_sl_|license_key)", "EDD software licensing"),
            (r"(?i)(purchase_code|purchasecode)", "purchase code"),
        ]

        for pattern, label in license_indicators:
            if not re.search(pattern, main_content):
                continue

        # Chercher les licence keys factices (00...00)
        fake_license_keys = re.findall(
            r"(?i)(['\"](?:0{16,}|[0]{8,}-[0]{4,}-[0]{4,}-[0]{4,}-[0]{8,})['\"])",
            main_content
        )
        if fake_license_keys:
            findings.append({
                "message": (
                    f"Le plugin {plugin_name} contient une licence factice "
                    f"({fake_license_keys[0]}), typique des nullés"
                ),
                "severity": "CRITICAL",
                "evidence": f"Licence key factice trouvée: {fake_license_keys[0]}",
                "url": self._build_url(
                    f"wp-content/plugins/{slug}/{plugin.get('main_file', slug + '.php')}"
                ),
            })

        return findings

    # ── Helper: Suspicious content ───────────────────────────────────────

    def _check_suspicious_content(
        self, content: str, plugin_name: str, slug: str
    ) -> Optional[str]:
        """Vérifie le contenu pour des marqueurs de nullés."""
        content_lower = content.lower()

        # Marqueurs de nullés dans le contenu
        nulled_markers = [
            "nulled", "gplfreak", "gplpapa", "gpldl", "babia.to",
            "nulled.to", "freemium", "wpnulled",
            "nulled by", "nulled version", "gpl version",
            "premium plugins nulled",
        ]

        for marker in nulled_markers:
            if marker in content_lower:
                return (
                    f"Le fichier readme.txt de {plugin_name} contient le marqueur "
                    f"de nullé '{marker}'"
                )

        # Description vide ou générique
        desc_match = re.search(r"(?i)Description:\s*(.*)", content)
        if desc_match:
            desc = desc_match.group(1).strip()
            generic_descriptions = [
                "wordpress plugin", "best plugin", "plugin for wordpress",
                "wordpress plugins", "a wordpress plugin",
            ]
            if desc.lower().strip() in generic_descriptions and len(desc) < 30:
                return (
                    f"Le plugin {plugin_name} a une description générique "
                    f"dans readme.txt : '{desc}', possible nullé"
                )

        return None

    # ── File/network helpers ─────────────────────────────────────────────

    def _plugin_exists(self, slug: str, paths: List[str]) -> Tuple[bool, Optional[str]]:
        """Vérifie si le plugin existe sur le site (chemins non PHP seulement :
        un fichier PHP deviné sous wp-content/ n'est jamais demandé)."""
        for path in paths:
            if not self.may_request(path, "HEAD"):
                continue
            try:
                resp = self.http_head(path)
                if resp.status_code == 200:
                    return True, path
                # Certains serveurs ne répondent pas au HEAD, essayer GET
                resp = self.http_get(path)
                if resp.status_code == 200:
                    return True, path
            except Exception:
                continue
        return False, None

    def _fetch_url(self, path: str) -> Optional[str]:
        """Récupère le contenu textuel d'un chemin."""
        try:
            resp = self.http_get(path)
            if resp.status_code == 200 and resp.text:
                return resp.text
            return None
        except Exception:
            return None

    def _build_url(self, path: str) -> str:
        """Construit une URL absolue à partir d'un chemin relatif."""
        return f"{self.target.rstrip('/')}/{path.lstrip('/')}"

    # ── Parsing helpers ──────────────────────────────────────────────────

    def _parse_plugin_headers(self, content: str) -> Dict[str, str]:
        """Extrait les en-têtes du fichier principal d'un plugin."""
        headers = {}
        patterns = {
            "Plugin Name": r"(?i)Plugin\s*Name:\s*(.+)",
            "Plugin URI": r"(?i)Plugin\s*URI:\s*(.+)",
            "Description": r"(?i)Description:\s*(.+)",
            "Version": r"(?i)Version:\s*(.+)",
            "Author": r"(?i)Author:\s*(.+)",
            "Author URI": r"(?i)Author\s*URI:\s*(.+)",
            "Text Domain": r"(?i)Text\s*Domain:\s*(.+)",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                headers[key] = match.group(1).strip()

        return headers

    def _parse_theme_headers(self, content: str) -> Dict[str, str]:
        """Extrait les en-têtes du style.css d'un thème."""
        headers = {}
        patterns = {
            "Theme Name": r"(?i)Theme\s*Name:\s*(.+)",
            "Theme URI": r"(?i)Theme\s*URI:\s*(.+)",
            "Description": r"(?i)Description:\s*(.+)",
            "Version": r"(?i)Version:\s*(.+)",
            "Author": r"(?i)Author:\s*(.+)",
            "Author URI": r"(?i)Author\s*URI:\s*(.+)",
            "Text Domain": r"(?i)Text\s*Domain:\s*(.+)",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                headers[key] = match.group(1).strip()

        return headers

    def _extract_stable_tag(self, content: str) -> Optional[str]:
        """Extrait le Stable tag d'un readme.txt."""
        match = re.search(r"(?i)Stable\s*tag:\s*(\S+)", content)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def _version_compare(v1: str, v2: str) -> int:
        """Compare deux versions. Retourne -1, 0, ou 1."""
        try:
            parts1 = [int(x) for x in re.split(r"[.\-]", v1) if x.isdigit()]
            parts2 = [int(x) for x in re.split(r"[.\-]", v2) if x.isdigit()]
            # Remplir pour même longueur
            while len(parts1) < len(parts2):
                parts1.append(0)
            while len(parts2) < len(parts1):
                parts2.append(0)
            for a, b in zip(parts1, parts2):
                if a < b:
                    return -1
                if a > b:
                    return 1
            return 0
        except (ValueError, TypeError):
            return 0
