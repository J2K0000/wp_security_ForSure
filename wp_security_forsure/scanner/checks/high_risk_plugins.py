"""Check, Notable Attack-Surface WordPress Plugins.

Reports the presence of WordPress plugins that are commonly targeted by
attackers because of their large attack surface (page builders, e-commerce,
form handlers, migration/backup tools, etc.).

This check is purely informational: it does NOT compare installed versions
against any hardcoded "safe" version and does NOT reference specific CVEs.
Actual CVE/version-vulnerability matching against live vulnerability
databases is the responsibility of the ``vulnerability_scan`` check, which
queries wpvulnerability.net for each detected component.

Detection strategy:
  1. Prefer the shared inventory produced by the ``fingerprint`` check
     (``self.context["inventory"]``), when available.
  2. Otherwise, fall back to a best-effort HTTP probe:
       a. readme.txt  → "Stable tag: X.Y.Z"
       b. style.css   → "Version: X.Y.Z"
     If neither yields a version the plugin is assumed absent.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseCheck

# ---------------------------------------------------------------------------
# Plugin definitions, notable attack surface only (no CVE/version data)
# ---------------------------------------------------------------------------

PluginDef = Dict[str, Any]

NOTABLE_PLUGINS: List[PluginDef] = [
    {"name": "Elementor", "slug": "elementor", "reason": "page builder"},
    {"name": "Elementor Pro", "slug": "elementor-pro", "reason": "page builder"},
    {"name": "Contact Form 7", "slug": "contact-form-7", "reason": "form handler / file upload"},
    {"name": "WooCommerce", "slug": "woocommerce", "reason": "e-commerce / checkout"},
    {"name": "Slider Revolution", "slug": "revslider", "reason": "page builder / file upload"},
    {"name": "Jetpack", "slug": "jetpack", "reason": "broad functionality / remote connection"},
    {"name": "Yoast SEO", "slug": "wordpress-seo", "reason": "widely deployed, large codebase"},
    {"name": "Wordfence Security", "slug": "wordfence", "reason": "security plugin, high privilege"},
    {"name": "WPBakery", "slug": "js_composer", "reason": "page builder"},
    {"name": "Gravity Forms", "slug": "gravityforms", "reason": "form handler / file upload"},
    {"name": "WPML", "slug": "sitepress-multilingual-cms", "reason": "widely deployed, large codebase"},
    {"name": "All-in-One WP Migration", "slug": "all-in-one-wp-migration", "reason": "backup / migration, file handling"},
    {"name": "UpdraftPlus", "slug": "updraftplus", "reason": "backup / migration, file handling"},
    {"name": "Really Simple SSL", "slug": "really-simple-ssl", "reason": "security-adjacent, admin-level actions"},
    {"name": "Advanced Custom Fields", "slug": "advanced-custom-fields", "reason": "widely deployed, large codebase"},
    {"name": "Rank Math SEO", "slug": "seo-by-rank-math", "reason": "widely deployed, large codebase"},
    {"name": "WP Rocket", "slug": "wp-rocket", "reason": "widely deployed, caching/admin actions"},
]


# ---------------------------------------------------------------------------
# Version helpers (used only for the fallback HTTP-based presence probe)
# ---------------------------------------------------------------------------

_STABLE_TAG_RE = re.compile(
    r"stable\s*tag\s*[:\s=]+\s*v?(\d+\.\d+(?:\.\d+)*(?:[.-]?\w+)?)",
    re.IGNORECASE,
)
_VERSION_CSS_RE = re.compile(
    r"(?:Version|version)\s*[:\s=]+\s*v?(\d+\.\d+(?:\.\d+)*(?:[.-]?\w+)?)",
)


def _parse_version(text: str) -> Optional[str]:
    """Return the first semantic version found in *text*, or *None*."""
    m = _STABLE_TAG_RE.search(text)
    if m:
        return m.group(1)
    m = _VERSION_CSS_RE.search(text)
    if m:
        return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Check class
# ---------------------------------------------------------------------------

class HighRiskPluginsCheck(BaseCheck):
    """Reports notable attack-surface WordPress plugins detected on target.

    Informational only, no version-vulnerability verdicts, no CVE claims.
    """

    name = "high_risk_plugins"
    title = "Notable Attack-Surface WordPress Plugins"
    description = (
        "Reports the presence of commonly-targeted WordPress plugins "
        "(page builders, e-commerce, form handlers, backup/migration "
        "tools). Purely informational, CVE/version-vulnerability "
        "matching is handled by the vulnerability_scan check."
    )
    severity = "INFO"
    access_tier = 0  # mixte : inventaire, repli readme.txt deviné sous --authorized

    # ────────────────────────────────────────────────────────────────
    def run(self):
        inv = (self.context or {}).get("inventory")
        if inv and inv.get("plugins"):
            self._report_from_inventory(inv)
        elif self.config.get("authorized"):
            # Repli : readme.txt / style.css devinés (niveau 2).
            for plugin in NOTABLE_PLUGINS:
                self._check_plugin_http(plugin)
        else:
            self.note_unlinked_skipped(
                "repli par readme.txt et style.css devinés des "
                f"{len(NOTABLE_PLUGINS)} extensions à forte surface d'attaque "
                "(inventaire de la page vide)")
        return self._result

    # ────────────────────────────────────────────────────────────────
    def _report_from_inventory(self, inv: Dict[str, Any]) -> None:
        notable_slugs = {p["slug"]: p for p in NOTABLE_PLUGINS}
        for comp in inv.get("plugins", []):
            slug = comp.get("slug")
            plugin = notable_slugs.get(slug)
            if not plugin:
                continue
            version = comp.get("version")
            self._add_info_finding(plugin, version, comp.get("source") or "inventory")

    # ────────────────────────────────────────────────────────────────
    def _check_plugin_http(self, plugin: PluginDef) -> None:
        slug: str = plugin["slug"]
        version, source = self._detect_version(slug)
        if version is None:
            return  # plugin not installed or version undetectable, skip
        self._add_info_finding(plugin, version, source)

    # ────────────────────────────────────────────────────────────────
    def _add_info_finding(self, plugin: PluginDef, version: Optional[str], source: str) -> None:
        name = plugin["name"]
        slug = plugin["slug"]
        reason = plugin.get("reason", "notable attack surface")
        version_str = f" {version}" if version else ""
        evidence = (
            f"Detected via: {source}\n"
            f"Reason flagged: {reason}\n"
            f"Note: no CVE/version-vulnerability check performed here, "
            f"see the vulnerability_scan check for known-vulnerability matching."
        )
        self._result.add_finding(
            message=f"{name}{version_str} detected (notable attack-surface plugin).",
            severity="INFO",
            evidence=evidence,
            url=f"{self.target}/wp-content/plugins/{slug}/",
            confidence="confirmed",
        )

    # ────────────────────────────────────────────────────────────────
    def _detect_version(self, slug: str) -> Tuple[Optional[str], str]:
        """Try to detect plugin presence/version via HTTP.

        Returns (version, source_description) or (None, "").
        """
        # 1. readme.txt , most reliable for free / many premium plugins
        ver = self._version_from_readme(slug)
        if ver:
            return ver, "readme.txt"

        # 2. style.css , fallback for page-builder / cache plugins
        ver = self._version_from_style(slug)
        if ver:
            return ver, "style.css"

        return None, ""

    # ────────────────────────────────────────────────────────────────
    def _version_from_readme(self, slug: str) -> Optional[str]:
        """Fetch readme.txt and extract version from 'Stable tag:' line."""
        try:
            resp = self.http_get(f"wp-content/plugins/{slug}/readme.txt")
            if resp.status_code != 200:
                return None
            return _parse_version(resp.text)
        except Exception:
            return None

    # ────────────────────────────────────────────────────────────────
    def _version_from_style(self, slug: str) -> Optional[str]:
        """Fetch style.css and extract version from header."""
        try:
            resp = self.http_get(f"wp-content/plugins/{slug}/style.css")
            if resp.status_code != 200:
                return None
            return _parse_version(resp.text)
        except Exception:
            return None
