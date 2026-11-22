"""Listes curées des plugins/thèmes WordPress les plus répandus.
Utilisées par fingerprint pour une sonde active bornée (readme.txt/style.css)
sur les sites cache-optimisés où le passif ne voit pas les chemins d'assets."""
import re

COMMON_PLUGINS = [
    "akismet", "contact-form-7", "wordpress-seo", "elementor", "elementor-pro",
    "wpforms-lite", "jetpack", "woocommerce", "all-in-one-seo-pack", "wordfence",
    "litespeed-cache", "wp-super-cache", "w3-total-cache", "wp-fastest-cache",
    "autoptimize", "sg-cachepress", "classic-editor", "really-simple-ssl",
    "updraftplus", "wordpress-importer", "redirection", "google-site-kit",
    "mailchimp-for-wp", "tablepress", "advanced-custom-fields", "duplicate-post",
    "wp-mail-smtp", "nextgen-gallery", "ninja-forms", "essential-addons-for-elementor-lite",
    "all-in-one-wp-migration", "wp-optimize", "wp-smushit", "ewww-image-optimizer",
    "imagify", "seo-by-rank-math", "the-events-calendar", "polylang", "loco-translate",
    "cookie-law-info", "complianz-gdpr", "header-footer-elementor",
    "happy-elementor-addons", "premium-addons-for-elementor", "backwpup", "duplicator",
    "wpvivid-backuprestore", "better-wp-security", "all-in-one-wp-security-and-firewall",
    "limit-login-attempts-reloaded", "two-factor", "wps-hide-login", "disable-comments",
    "breadcrumb-navxt", "custom-post-type-ui", "acf-extended", "profile-builder",
    "ultimate-member", "buddypress", "bbpress", "learnpress", "tutor", "lifterlms",
    "paid-memberships-pro", "woocommerce-gateway-stripe", "woocommerce-paypal-payments",
    "mailpoet", "newsletter", "fluentform", "forminator", "formidable",
    "code-snippets", "insert-headers-and-footers", "wp-reset", "query-monitor",
    "health-check", "sucuri-scanner", "malcare-security", "wpforms", "wp-pagenavi",
    "yith-woocommerce-wishlist", "woo-gutenberg-products-block", "wp-google-maps",
    "wp-store-locator", "google-analytics-for-wordpress", "pixelyoursite",
    "shortpixel-image-optimiser", "smush", "wp-rocket", "kadence-blocks",
    "spectra", "otter-blocks", "elementskit-lite",
]

COMMON_THEMES = [
    "astra", "oceanwp", "generatepress", "kadence", "hello-elementor", "neve",
    "storefront", "blocksy", "sydney", "hestia", "customify", "zakra",
    "twentytwentyone", "twentytwentytwo", "twentytwentythree", "twentytwentyfour",
    "twentytwentyfive", "twentytwenty", "twentynineteen", "twentyseventeen",
    "divi", "avada", "flatsome", "betheme", "phlox",
]

# Namespaces REST natifs de WordPress (core) exposés sur /wp-json, jamais des
# plugins. On ne matche que le préfixe avant le premier "/" (ex. "wp/v2" -> "wp").
CORE_REST_NAMESPACES = {
    "oembed", "wp", "wp-site-health", "wp-block-editor", "batch",
    "wp-block-directory", "akismet-nonce",
}

# Préfixes de namespace REST connus qui ne correspondent pas directement au
# slug du plugin sur wordpress.org, mapping explicite requis pour la
# confirmation via readme.txt. Tout préfixe absent de cette table (et non
# core) est utilisé tel quel comme slug candidat.
NAMESPACE_TO_SLUG = {
    "yoast": "wordpress-seo",
    "wc": "woocommerce",
    "woocommerce": "woocommerce",
    "wc-admin": "woocommerce",
    "wc-analytics": "woocommerce",
    "rankmath": "seo-by-rank-math",
    "jetpack": "jetpack",
    "akismet": "akismet",
    "contact-form-7": "contact-form-7",
    "elementor": "elementor",
    "wpforms": "wpforms-lite",
    "acf": "advanced-custom-fields",
    "wordfence": "wordfence",
    "wp-rocket": "wp-rocket",
    "polylang": "polylang",
    "pll": "polylang",
    "ninja-forms": "ninja-forms",
    "gf": "gravityforms",
    "gravityforms": "gravityforms",
    "wpml": "sitepress-multilingual-cms",
    "tribe": "the-events-calendar",
    "buddypress": "buddypress",
    "bp": "buddypress",
    "bbpress": "bbpress",
    "learnpress": "learnpress",
    "mailpoet": "mailpoet",
    "redirection": "redirection",
    "wp-2fa": "wp-2fa",
}

# Signatures des balises <meta name="generator"> que certains plugins
# s'attribuent eux-mêmes, souvent avec leur propre version en clair. C'est
# un signal aussi fort qu'un readme.txt (auto-déclaré par le plugin) et
# obtenu gratuitement depuis le HTML de la home déjà en main, sans requête
# supplémentaire, contrairement à la sonde active _probe_common.
# Chaque entrée est (regex compilée, slug). Le groupe 1, quand il matche,
# porte la version ; il est optionnel pour les plugins qui n'exposent que
# leur nom (Rank Math, WPBakery...), dans ce cas la version reste None.
# Elementor Pro est volontairement une entrée séparée d'Elementor : les deux
# peuvent apparaître dans la même balise generator ("Elementor X; ...,
# Elementor Pro Y") et doivent produire deux composants distincts.
PLUGIN_GENERATOR_SIGNATURES = [
    (re.compile(r"^Yoast SEO(?:\s+Premium)?(?:\s+([0-9][\w.\-]*))?", re.I), "wordpress-seo"),
    (re.compile(r"^WooCommerce(?:\s+([0-9][\w.\-]*))?", re.I), "woocommerce"),
    (re.compile(r"\bElementor Pro\s+([0-9][\w.\-]*)", re.I), "elementor-pro"),
    (re.compile(r"\bElementor\s+([0-9][\w.\-]*)", re.I), "elementor"),
    (re.compile(r"Slider Revolution\s+([0-9][\w.\-]*)", re.I), "revslider"),
    (re.compile(r"^Rank Math(?:\s+([0-9][\w.\-]*))?", re.I), "seo-by-rank-math"),
    (re.compile(r"^WPBakery(?:\s+Page\s+Builder)?(?:\s+([0-9][\w.\-]*))?", re.I), "js_composer"),
    (re.compile(r"^All[\s\-]?in[\s\-]?One\s+SEO(?:\s+Pack)?(?:\s+([0-9][\w.\-]*))?", re.I),
     "all-in-one-seo-pack"),
    (re.compile(r"^Jetpack(?:\s+([0-9][\w.\-]*))?", re.I), "jetpack"),
]
