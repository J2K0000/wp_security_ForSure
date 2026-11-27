"""Tables de données statiques pour RestApiCheck (wp_security_forsure.scanner.checks.rest_api).

Isolées dans un module à part pour que rest_api.py reste concentré sur la
logique des sous-checks : ces listes/motifs sont de la donnée pure (aucun
comportement), pas des concepts qu'on modifie en lisant le code du check.

Ce module ne définit aucune sous-classe de BaseCheck : il n'est pas un check
en soi, juste des constantes partagées. La découverte des checks
(scanner.engine._discover_checks) l'importe comme n'importe quel module de
checks/ mais n'y trouve rien à enregistrer, sans effet de bord.
"""

from typing import Dict, List, Tuple
import re


# ── Known risky plugin namespace patterns ─────────────────────────────
RISKY_NAMESPACE_PATTERNS: Dict[str, str] = {
    "contact-form-7": "Contact Form 7, file upload bypass (historical)",
    "elementor": "Elementor, various CVEs",
    "wpdiscuz": "wpDiscuz, comment injection",
    "woocommerce": "WooCommerce, massive attack surface",
    "yoast": "Yoast SEO, SEO data leakage",
    "jetpack": "Jetpack, token leakage (historical)",
    "rankmath": "Rank Math, schema injection",
    "wordfence": "Wordfence, AI prompt injection (novel)",
    "wpgb": "Gridbuilder, SQL injection (historical)",
    "wplms": "WPLMS, privilege escalation",
    "simple-jwt-login": "Simple JWT Login, critical auth bypass",
    "wp-statistics": "WP Statistics, data exposure",
    "sassy-social-share": "Sassy Social Share, unauthenticated options update",
    "wp-file-manager": "WP File Manager, Critical RCE (CVE-2020-25213)",
    "wpforms": "WPForms, form entry leakage",
    "really-simple-ssl": "Really Simple SSL, low risk",
    "litespeed": "LiteSpeed Cache, cache manipulation",
    "akismet": "Akismet, low risk (spam checking)",
}

# Core namespaces to skip for custom endpoint analysis. Préfixes de namespace
# enregistrés par le cœur (wp-includes/rest-api.php, create_initial_rest_routes,
# et wp_oembed_register_route pour oembed/1.0) ; wp-abilities/v1 depuis 6.9.
CORE_NAMESPACE_PREFIXES: Tuple[str, ...] = (
    "oembed/", "wp/v", "wp/site-health", "wp/block", "wp/pattern",
    "wp-site-health/", "wp-block-editor/", "wp-abilities/", "batch/",
)

# JSONP callback parameter names
JSONP_PARAMS: List[str] = [
    "_jsonp", "callback", "jsonp", "jsoncallback", "fn", "cb", "format",
]

# ── Broken Access Control (BAC), endpoints REST tiers à sonder ────────
# Liste HEURISTIQUE, non exhaustive : endpoints de plugins courants qui
# DEVRAIENT exiger une authentification mais que du code « vibe-codé » expose
# fréquemment sans permission_callback. On sonde en aveugle ; un WP_Error
# (endpoint protégé) ou un 401/403/404 est traité comme sain.
BAC_ENDPOINTS: List[str] = [
    # Core : /wp/v2/settings DOIT exiger l'authentification (admin).
    "wp-json/wp/v2/settings",
    # Namespaces tiers génériques plausibles (plugins de forms, membres, LMS,
    # export/import, réglages…). Purement heuristique.
    "wp-json/contact-form-7/v1/contact-forms",
    "wp-json/wpforms/v1/forms",
    "wp-json/ninja-forms/v1/submissions",
    "wp-json/give-api/v2/donations",
    "wp-json/wc/v3/orders",
    "wp-json/wc/store/v1/cart",
    "wp-json/members/v1/users",
    "wp-json/tutor/v1/course",
    "wp-json/newsletter/v1/subscribers",
]

# Motif de route « sensible » pour l'analyse dynamique de /wp-json/ (racine).
BAC_SENSITIVE_ROUTE = re.compile(
    r"(?i)(settings|config|users|export|import|data|logs|debug|admin"
    r"|options|secret|token|key)"
)

# Bornes réseau : nombre max de GET émis par _check_bac_endpoints.
BAC_MAX_REQUESTS = 20
