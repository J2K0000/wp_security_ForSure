"""Check for third-party script risks on WordPress sites.

Inherits from BaseCheck. Covers 10 detection categories:

  1) Script extraction        , parse homepage HTML for <script src=>
  2) Script categorization    , classify each external script by purpose
  3) SRI (Subresource Integrity), verify crossorigin scripts have integrity attr
  4) Mixed content detection  , HTTP scripts loaded on HTTPS page
  5) Known compromised CDNs   , polyfill.io, bootcdn, staticfile, etc.
  6) Suspicious domain detection, typosquatting, unknown TLDs, unknown origins
  7) Crypto miner detection   , Coinhive, CoinImp, Crypto-Loot, etc.
  8) Data exfiltration risks  , sendBeacon, unexpected origin callbacks
  9) Excessive privilege      , geolocation, camera, microphone API access
 10) Script count analysis    , >20 external scripts flagged
"""

import re
from typing import Dict, List, Optional, Tuple

from .base import BaseCheck, CheckResult
from ..vulndb.matcher import _cmp


class ThirdPartyScriptsCheck(BaseCheck):
    """Analyze third-party scripts loaded by a WordPress site."""

    name = "third_party_scripts"
    title = "Third-Party Scripts & Integrations Risk Assessment"
    description = (
        "Analyzes all external scripts loaded by the WordPress site, "
        "checking for supply-chain risks, compromised CDNs, crypto miners, "
        "missing Subresource Integrity, mixed content, data exfiltration "
        "patterns, excessive browser API privileges, and suspicious domains."
    )
    severity = "HIGH"
    access_tier = 0  # accueil et scripts tiers qu'il cite
    depends_on: List[str] = []

    # ── Script categorization patterns ──────────────────────────────

    CATEGORY_PATTERNS: Dict[str, List[str]] = {
        "analytics": [
            "google-analytics.com", "googletagmanager.com", "facebook.net",
            "pixel", "hotjar.com", "matomo.org", "clicky.com",
            "mixpanel.com", "amplitude.com", "heap.io", "segment.io",
            "plausible.io", "analytics", "gtag", "ga.js", "analytics.js",
        ],
        "advertising": [
            "doubleclick.net", "adsystem.com", "adform.net", "criteo.com",
            "criteo.net", "outbrain.com", "taboola.com", "pubmatic.com",
            "openx.net", "rubiconproject.com", "adservice", "adserver",
        ],
        "cdn": [
            "cdnjs.cloudflare.com", "ajax.googleapis.com", "cdn.jsdelivr.net",
            "unpkg.com", "polyfill.io", "code.jquery.com",
            "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
            "bootcdn.net", "bootcss.com", "staticfile.net", "staticfile.org",
            "cdn.cloudflare.com", "jquery",
        ],
        "social": [
            "platform.twitter.com", "connect.facebook.net",
            "platform.linkedin.com", "instagram.com", "pinterest.com",
            "tiktok.com", "snapchat.com", "twitter.com", "fbq(",
        ],
        "utility": [
            "recaptcha.net", "maps.googleapis.com", "player.vimeo.com",
            "wistia.com", "typekit.net", "use.typekit.com",
            "youtube.com", "youtu.be", "googleapis.com",
        ],
        "fonts": [
            "fonts.googleapis.com", "fonts.gstatic.com",
            "use.typekit.com", "fast.fonts.net", "fontawesome.com",
            "font-awesome", "fontawesome",
        ],
        "payments": [
            "stripe.com", "paypal.com", "js.braintreegateway.com",
            "adyen.com", "mollie.com", "square.com", "authorize.net",
        ],
    }

    # ── Known compromised CDN domains (supply-chain attacks) ────────

    COMPROMISED_CDN_PATTERNS: List[str] = [
        "polyfill.io",           # June 2024 supply-chain attack, 100K+ sites
        "cdn.polyfill.io",
        "bootcdn.net",           # Chinese CDN compromised since 2023
        "bootcss.com",
        "staticfile.net",
        "staticfile.org",
        "unionadjs.com",         # Union Ads JS malware
        "xhsbpza.com",
        "union.macoms.la",
        "newcrbpc.com",
        "googie-anaiytics.com",  # Typosquatted analytics used in polyfill.io attack
        "kuurza.com",
    ]

    # ── Crypto miner patterns (script URLs and inline JS keywords) ──

    CRYPTO_MINER_URL_PATTERNS: List[str] = [
        "coinhive.com", "coin-hive.com", "coinimp.com",
        "cryptoloot.pro", "minero.cc", "webminepool.com",
        "authedmine.com", "jsecoin.com", "minescript",
        "afksystem.com", "realtimecrypto.pro", "ipob.net",
        "ppoi.org", "releaseshub.com", "minexmr.com",
        "pool.minexmr.com", "webminerpool.com", "wpmine.com",
        "phoenixminer.com", "miner.minerate.com",
        "jquery1234.com",  # Known Coinimp delivery domain
    ]

    # Signatures SPÉCIFIQUES de mineurs. Les termes génériques (throttle,
    # hashrate, isRunning, Miner, Anonymous, SiteKey, _Client) sont retirés :
    # ils sont ubiquitaires en JS légitime (lodash, lazy-load…) → faux positifs.
    CRYPTO_MINER_INLINE_PATTERNS: List[str] = [
        "cryptonight", "cryptonight-lite", "cryptonight-heavy",
        "coinimp", "coinhive", "coin-hive",
        "startMiner", "stopMiner", "setThrottle", "getThrottle",
    ]

    # ── Suspicious TLDs (high risk / uncommon) ──────────────────────

    SUSPICIOUS_TLDS: List[str] = [
        ".xyz", ".top", ".gq", ".ml", ".cf", ".click",
        ".download", ".date", ".men", ".work", ".trade",
        ".loan", ".win", ".bid", ".gdn", ".science",
        ".tk", ".ga", ".cf", ".ml", ".gq",
    ]

    # ── Known good domains (whitelist for suspicious domain check) ──

    KNOWN_GOOD_DOMAINS: List[str] = [
        "google-analytics.com", "googletagmanager.com",
        "facebook.net", "connect.facebook.net",
        "cdnjs.cloudflare.com", "jsdelivr.net", "cdn.jsdelivr.net",
        "unpkg.com", "code.jquery.com",
        "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
        "fonts.googleapis.com", "fonts.gstatic.com",
        "stripe.com", "paypal.com",
        "js.braintreegateway.com", "maps.googleapis.com",
        "recaptcha.net", "player.vimeo.com",
        "hotjar.com", "matomo.org", "plausible.io",
        "platform.twitter.com", "platform.linkedin.com",
        "wistia.com", "typekit.net", "use.typekit.com",
        "fast.fonts.net", "fontawesome.com",
        "stats.wp.com", "s.w.org", "pixel.wp.com",
        "ajax.googleapis.com", "apis.google.com",
        "www.google.com", "googleads.g.doubleclick.net",
        "tpc.googlesyndication.com", "pagead2.googlesyndication.com",
        "www.youtube.com", "youtube.com",
        "vimeo.com", "player.vimeo.com",
        "soundcloud.com", "w.soundcloud.com",
        "adyen.com", "checkoutshopper-live.adyen.com",
        "mollie.com", "square.com", "authorize.net",
    ]

    # ── Typosquatting pattern pairs (legitimate -> suspicious regex) ─

    TYPOSQUAT_PATTERNS: List[Tuple[str, str, str]] = [
        # (legitimate_domain, suspicious_regex, description)
        (r"google\-analytics\.com", r"goog[la1e]-?[a4n]a?lytics?\.[a-z]+",
         "Google Analytics typosquatting"),
        (r"google", r"googl[^e]|g00gle|go0gle",
         "Google brand typosquatting"),
        (r"facebook", r"faceboo?k[^.]|faceb00k|facebok",
         "Facebook brand typosquatting"),
        (r"paypal", r"paypa[^l]|pay-pal|paypa1",
         "PayPal typosquatting"),
        (r"stripe\.com", r"str1pe|str[i1]p[eo][^.]",
         "Stripe typosquatting"),
        (r"jsdelivr", r"jsde1ivr|jsdel1vr|jsdeliv1r|jsdel!vr",
         "jsDelivr typosquatting"),
        (r"cloudflare", r"cl0udflare|clowdflare|cloudphlare|cl0udfl[a4]re",
         "Cloudflare typosquatting"),
    ]

    # ── Data exfiltration patterns ──────────────────────────────────

    DATA_EXFIL_PATTERNS: List[Tuple[str, str]] = [
        (r"navigator\.sendBeacon", "navigator.sendBeacon()"),
        (r"navigator\.sendBeacon\s*\([^)]*\)",
         "navigator.sendBeacon() call"),
    ]

    # ── Excessive privilege (browser API) patterns ──────────────────

    PRIVILEGE_PATTERNS: List[Tuple[str, str, str]] = [
        # (regex, description, severity)
        (r"navigator\.geolocation|getCurrentPosition|watchPosition",
         "Geolocation API access", "HIGH"),
        (r"getUserMedia|mediaDevices\.getUserMedia|navigator\.mediaDevices",
         "Camera/Microphone access", "CRITICAL"),
        # Le presse-papiers sert aussi à un bouton « copier » ordinaire ; seule la
        # passe --render voit une écriture réelle (ClickFix). Simple mention ici.
        (r"navigator\.clipboard", "Clipboard API access", "LOW"),
        (r"getDisplayMedia|captureStream",
         "Screen capture access", "CRITICAL"),
    ]

    # ── Maximum allowed external scripts before flagging ────────────

    MAX_EXTERNAL_SCRIPTS: int = 20

    # ── Base statique de libs JS front vulnérables (façon retire.js) ─
    #
    # Angle mort : les libs JS embarquées par thèmes/plugins/CDN (jQuery, etc.)
    # ont des CVE connues qui N'apparaissent PAS dans le flux CVE des plugins WP.
    # Détection boîte noire : on énumère les <script src> réellement servis, on
    # extrait (nom, version) du nom de fichier/URL, puis on matche contre les
    # plages ci-dessous (offline, aucune requête vers une base externe).
    #
    # Chaque entrée :
    #   name      : nom lisible de la lib
    #   match     : regex d'extraction de version (group 1) essayées dans l'ordre.
    #               Elles identifient AUSSI la lib (préfixe du nom de fichier).
    #   vulnerable: plages vulnérables. Clés possibles par plage :
    #                 "lt"/"le"  = borne max (exclue / incluse)
    #                 "ge"/"gt"  = borne min (incluse / exclue), intervalle
    #                 "all"      = True → toute version (lib EOL)
    #                 "label"/"note"/"cve" = libellé, description, référence
    #   reco      : recommandation de remédiation
    #
    # Ordre : les noms les plus spécifiques (jquery-migrate) avant les génériques
    # (jquery) pour éviter qu'un jquery-migrate soit pris pour du jquery.
    VULNERABLE_JS_LIBS: List[Dict] = [
        {
            "name": "jquery-migrate",
            "match": [
                r"jquery-migrate-(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
                r"jquery-migrate(?:\.min)?\.js\?(?:[^\"']*&)?ver=(\d+\.\d+(?:\.\d+)?)",
            ],
            "vulnerable": [
                {"lt": "1.4.1", "label": "< 1.4.1",
                 "cve": "jquery-migrate advisory",
                 "note": "XSS (interprétation de sélecteurs héritée de jQuery)"},
            ],
            "reco": "Mettre à jour jquery-migrate vers 1.4.1+ ou le retirer.",
        },
        {
            "name": "jquery",
            "match": [
                r"/jquery/(\d+\.\d+\.\d+)/",                                  # /ajax/libs/jquery/3.3.1/
                r"jquery-(\d+\.\d+(?:\.\d+)?)(?:\.slim)?(?:\.min)?\.js",       # jquery-3.3.1.min.js
                r"jquery(?:\.slim)?(?:\.min)?\.js\?(?:[^\"']*&)?ver=(\d+\.\d+(?:\.\d+)?)",  # jquery.min.js?ver=1.12.4
            ],
            "vulnerable": [
                {"lt": "1.6.3", "label": "< 1.6.3", "cve": "CVE-2011-4969",
                 "note": "XSS via location.hash"},
                {"lt": "1.9.0", "label": "< 1.9.0", "cve": "CVE-2012-6708",
                 "note": "XSS (interprétation de sélecteurs)"},
                {"lt": "3.4.0", "label": "< 3.4.0", "cve": "CVE-2019-11358",
                 "note": "prototype pollution ($.extend en deep-copy)"},
                {"lt": "3.5.0", "label": "< 3.5.0",
                 "cve": "CVE-2020-11022 / CVE-2020-11023",
                 "note": "XSS (htmlPrefilter / manipulation du DOM)"},
            ],
            "reco": "Mettre à jour jQuery vers 3.5.0+ (idéalement la dernière 3.x).",
        },
        {
            "name": "bootstrap",
            "match": [
                r"/bootstrap/(\d+\.\d+\.\d+)/",
                r"bootstrap[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
                r"bootstrap(?:\.bundle)?(?:\.min)?\.js\?(?:[^\"']*&)?ver=(\d+\.\d+(?:\.\d+)?)",
            ],
            "vulnerable": [
                {"lt": "3.4.1", "label": "< 3.4.1", "cve": "CVE-2019-8331",
                 "note": "XSS (data-template / tooltip / popover)"},
                {"ge": "4.0.0", "lt": "4.3.1", "label": "4.0.0–4.3.0",
                 "cve": "CVE-2019-8331",
                 "note": "XSS (data-template / tooltip / popover)"},
            ],
            "reco": "Mettre à jour Bootstrap vers 3.4.1+ ou 4.3.1+.",
        },
        {
            "name": "angular",
            "match": [
                r"/angular\.js/(\d+\.\d+\.\d+)/",
                r"angular-(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
                r"angular(?:\.min)?\.js\?(?:[^\"']*&)?ver=(\d+\.\d+(?:\.\d+)?)",
            ],
            "vulnerable": [
                {"all": True, "label": "toutes versions (EOL)",
                 "cve": "AngularJS 1.x EOL",
                 "note": "AngularJS 1.x en fin de vie (janv. 2022), plus aucun "
                         "correctif de sécurité"},
            ],
            "reco": "Migrer hors d'AngularJS 1.x (framework non maintenu).",
        },
        {
            "name": "lodash",
            "match": [
                r"/lodash\.js/(\d+\.\d+\.\d+)/",
                r"lodash[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
                r"lodash(?:\.min)?\.js\?(?:[^\"']*&)?ver=(\d+\.\d+(?:\.\d+)?)",
            ],
            "vulnerable": [
                {"lt": "4.17.21", "label": "< 4.17.21",
                 "cve": "CVE-2021-23337 / CVE-2020-8203",
                 "note": "prototype pollution / injection de commande (template)"},
            ],
            "reco": "Mettre à jour lodash vers 4.17.21+.",
        },
        {
            "name": "moment",
            "match": [
                r"/moment\.js/(\d+\.\d+\.\d+)/",
                r"moment[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
                r"moment(?:\.min)?\.js\?(?:[^\"']*&)?ver=(\d+\.\d+(?:\.\d+)?)",
            ],
            "vulnerable": [
                {"lt": "2.29.4", "label": "< 2.29.4", "cve": "CVE-2022-31129",
                 "note": "ReDoS (déni de service par expression régulière)"},
            ],
            "reco": "Mettre à jour moment.js vers 2.29.4+.",
        },
        {
            "name": "handlebars",
            "match": [
                r"/handlebars\.js/(\d+\.\d+\.\d+)/",
                r"handlebars[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
                r"handlebars(?:\.runtime)?(?:\.min)?\.js\?(?:[^\"']*&)?ver=(\d+\.\d+(?:\.\d+)?)",
            ],
            "vulnerable": [
                {"lt": "4.7.7", "label": "< 4.7.7",
                 "cve": "CVE-2021-23369 / CVE-2021-23383",
                 "note": "prototype pollution / RCE via compilation de template"},
            ],
            "reco": "Mettre à jour Handlebars vers 4.7.7+.",
        },
    ]

    # ═══════════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════════

    def run(self) -> CheckResult:
        """Execute all third-party script checks."""
        self._check_extract_and_categorize()
        self._check_sri()
        self._check_mixed_content()
        self._check_compromised_cdns()
        self._check_suspicious_domains()
        self._check_crypto_miners()
        self._check_data_exfiltration()
        self._check_excessive_privilege()
        self._check_vulnerable_js_libraries()
        self._check_script_count()
        return self._result

    # ═══════════════════════════════════════════════════════════════
    # Helper: fetch homepage HTML
    # ═══════════════════════════════════════════════════════════════

    def _get_homepage(self) -> Optional[str]:
        """Fetch homepage HTML. Returns text or None on failure."""
        try:
            resp = self.http_get("/")
        except Exception:
            return None
        if resp.status_code != 200 or not resp.text:
            return None
        return resp.text

    def _extract_script_tags(self, body: str) -> List[str]:
        """Extract full <script> tags from HTML."""
        return re.findall(r"<script[^>]*>.*?</script>", body, re.DOTALL | re.IGNORECASE)

    def _extract_external_scripts(self, body: str) -> List[Tuple[str, str]]:
        """Extract (src_url, full_script_tag) for all external scripts.

        Returns list of (url, tag) tuples for scripts with http/https src.
        """
        results: List[Tuple[str, str]] = []
        tags = self._extract_script_tags(body)
        for tag in tags:
            src_match = re.search(
                r'src\s*=\s*["\'](https?://[^"\']+)["\']',
                tag, re.IGNORECASE
            )
            if src_match:
                results.append((src_match.group(1), tag))
        return results

    def _extract_all_src_urls(self, body: str) -> List[str]:
        """Extract all src= URLs pointing to http/https resources."""
        return re.findall(
            r'src\s*=\s*["\']https?://[^"\']+["\']',
            body, re.IGNORECASE
        )

    def _get_domain(self, url: str) -> str:
        """Extract the domain from a URL."""
        return url.split("://")[-1].split("/")[0].lower()

    def _get_target_domain(self) -> str:
        """Get the target site's domain."""
        return self._get_domain(self.target)

    def _categorize_script(self, url: str) -> str:
        """Categorize a script URL into a purpose category."""
        url_lower = url.lower()
        for category, patterns in self.CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if pattern in url_lower:
                    return category
        return "unknown"

    # ═══════════════════════════════════════════════════════════════
    # 1 & 2, Script Extraction & Categorization
    # ═══════════════════════════════════════════════════════════════

    def _check_extract_and_categorize(self) -> None:
        """Extract all external scripts and categorize them."""
        body = self._get_homepage()
        if not body:
            return

        external_scripts = self._extract_external_scripts(body)
        if not external_scripts:
            self._result.add_finding(
                message="No external scripts detected on homepage",
                severity="INFO",
                evidence="No <script src=...> tags pointing to external URLs found",
                url=self.target,
            )
            return

        # Categorize each script
        categories: Dict[str, List[str]] = {}
        for url, tag in external_scripts:
            category = self._categorize_script(url)
            categories.setdefault(category, []).append(url)

        # Build evidence report
        total = sum(len(v) for v in categories.values())
        category_lines = []
        for cat in ["analytics", "advertising", "cdn", "social", "utility",
                     "fonts", "payments", "unknown"]:
            urls = categories.get(cat, [])
            if urls:
                for u in urls:
                    category_lines.append(f"  [{cat.upper():12s}] {u}")
            else:
                category_lines.append(f"  [{cat.upper():12s}] (none)")

        evidence = (
            f"External scripts found: {total}\n"
            + "\n".join(category_lines)
        )

        # Scripts non catégorisés : un script externe non reconnu n'est pas une
        # vulnérabilité en soi. On AGRÈGE en un seul finding INFO/potential (au
        # lieu d'un MEDIUM par script, qui noyait le rapport), revue manuelle.
        unknown = categories.get("unknown", [])
        if unknown:
            domains = sorted({self._get_domain(u) for u in unknown})
            self._result.add_finding(
                message=(
                    f"{len(unknown)} script(s) tiers non catégorisés "
                    f"({len(domains)} domaine(s)), à revoir manuellement"
                ),
                severity="INFO",
                evidence="Domaines non reconnus :\n"
                         + "\n".join(f"  - {d}" for d in domains[:30]),
                url=self.target,
                confidence="potential",
            )

        # Flag payment scripts at HIGH (high scrutiny)
        payment_urls = categories.get("payments", [])
        for url in payment_urls:
            self._result.add_finding(
                message=f"Payment script detected, verify integrity: {url}",
                severity="MEDIUM",
                evidence="Payment scripts handle sensitive financial data and "
                         "should be reviewed for supply-chain integrity",
                url=url,
            )

        self._result.add_finding(
            message=f"Script categorization complete, {total} external scripts found",
            severity="INFO",
            evidence=evidence,
            url=self.target,
        )

    # ═══════════════════════════════════════════════════════════════
    # 3, Subresource Integrity (SRI) Check
    # ═══════════════════════════════════════════════════════════════

    def _check_sri(self) -> None:
        """Check that crossorigin scripts have integrity attributes.

        Missing SRI on cross-origin scripts = supply-chain risk (HIGH).
        """
        body = self._get_homepage()
        if not body:
            return

        # Extract raw <script> tags (not just inner content)
        script_tags = re.findall(r"<script\s[^>]*>", body, re.IGNORECASE)
        if not script_tags:
            script_tags = re.findall(r"<script[^>]+>", body, re.IGNORECASE)

        for tag in script_tags:
            src_match = re.search(
                r'src\s*=\s*["\'](https?://[^"\']+)["\']',
                tag, re.IGNORECASE
            )
            if not src_match:
                continue

            src_url = src_match.group(1)
            has_crossorigin = bool(re.search(r'crossorigin', tag, re.IGNORECASE))
            has_integrity = bool(re.search(
                r'integrity\s*=\s*["\'][^"\']+["\']',
                tag, re.IGNORECASE
            ))
            integrity_empty = bool(re.search(
                r'integrity\s*=\s*["\']\s*["\']',
                tag, re.IGNORECASE
            ))

            if has_crossorigin and not has_integrity:
                self._result.add_finding(
                    message=(
                        f"Missing Subresource Integrity (SRI), crossorigin "
                        f"script without integrity attribute"
                    ),
                    severity="HIGH",
                    evidence=(
                        f"Script tag: {tag[:300]}\n"
                        f"Script src: {src_url}\n"
                        f"crossorigin attribute present but no integrity hash, "
                        f"supply-chain risk: compromised CDN could serve malicious JS"
                    ),
                    url=src_url,
                )
            elif has_crossorigin and integrity_empty:
                self._result.add_finding(
                    message=(
                        f"Empty integrity attribute on crossorigin script, "
                        f"no actual protection"
                    ),
                    severity="HIGH",
                    evidence=(
                        f"Script tag: {tag[:300]}\n"
                        f"Script src: {src_url}\n"
                        f"integrity attribute exists but is empty string"
                    ),
                    url=src_url,
                )

    # ═══════════════════════════════════════════════════════════════
    # 4, Mixed Content Detection
    # ═══════════════════════════════════════════════════════════════

    def _check_mixed_content(self) -> None:
        """Detect HTTP scripts loaded on HTTPS pages (HIGH).

        Modern browsers block active mixed content (scripts), causing breakage.
        """
        body = self._get_homepage()
        if not body:
            return

        # Only relevant if target is HTTPS
        if not self.target.lower().startswith("https://"):
            return

        http_srcs = re.findall(
            r'src\s*=\s*["\']http://[^"\']+["\']',
            body, re.IGNORECASE
        )

        for attr in http_srcs:
            url_match = re.search(r'["\'](http://[^"\']+)["\']', attr)
            if not url_match:
                continue
            http_url = url_match.group(1)

            # Extract the script src value from the full attribute
            src_match = re.search(
                r'src\s*=\s*["\']http://[^"\']+["\']',
                attr, re.IGNORECASE
            )
            if not src_match:
                continue

            self._result.add_finding(
                message=(
                    f"Mixed content detected, HTTP script loaded on HTTPS page"
                ),
                severity="HIGH",
                evidence=(
                    f"HTTP script src: {http_url}\n"
                    f"Browsers will block this script, breaking site functionality"
                ),
                url=http_url,
            )

    # ═══════════════════════════════════════════════════════════════
    # 5, Known Compromised CDN Detection
    # ═══════════════════════════════════════════════════════════════

    def _check_compromised_cdns(self) -> None:
        """Check for known compromised CDN domains (CRITICAL)."""
        body = self._get_homepage()
        if not body:
            return

        external_scripts = self._extract_external_scripts(body)
        if not external_scripts:
            return

        compromised_found = False
        for url, tag in external_scripts:
            domain = self._get_domain(url)
            for compromised in self.COMPROMISED_CDN_PATTERNS:
                if compromised in domain:
                    compromised_found = True
                    self._result.add_finding(
                        message=(
                            f"Known compromised CDN detected: {domain}, "
                            f"supply-chain attack risk"
                        ),
                        severity="CRITICAL",
                        evidence=(
                            f"Script URL: {url}\n"
                            f"Compromised domain: {domain}\n"
                            f"Matched pattern: {compromised}\n"
                            f"This domain has been involved in supply-chain "
                            f"attacks (malware injection, data theft, "
                            f"redirect to malicious sites). IMMEDIATE REMEDIATION REQUIRED."
                        ),
                        url=url,
                    )

        if not compromised_found:
            self._result.add_finding(
                message="No known compromised CDN domains detected",
                severity="INFO",
                evidence="All script domains scanned, none match known compromised CDN list",
                url=self.target,
            )

    # ═══════════════════════════════════════════════════════════════
    # 6, Suspicious Domain Detection
    # ═══════════════════════════════════════════════════════════════

    def _check_suspicious_domains(self) -> None:
        """Detect typosquatted domains, unknown TLDs, and unknown origins."""
        body = self._get_homepage()
        if not body:
            return

        external_scripts = self._extract_external_scripts(body)
        target_domain = self._get_target_domain()

        for url, tag in external_scripts:
            domain = self._get_domain(url)

            # Skip own domain / subdomains
            if domain == target_domain:
                continue
            if domain.endswith("." + target_domain) and target_domain.count(".") >= 1:
                continue

            # 6a. Check if it's a known-good domain
            is_known_good = False
            for good in self.KNOWN_GOOD_DOMAINS:
                # Suffixe : www.googletagmanager.com correspond à googletagmanager.com
                if domain == good or domain.endswith("." + good):
                    is_known_good = True
                    break

            if is_known_good:
                continue

            # 6b. Check for typosquatting patterns
            typosquat_found = False
            for legit_pattern, squatted_regex, desc in self.TYPOSQUAT_PATTERNS:
                if re.search(squatted_regex, domain, re.IGNORECASE):
                    typosquat_found = True
                    self._result.add_finding(
                        message=(
                            f"Possible typosquatted domain detected: {domain} "
                            f"- {desc}"
                        ),
                        severity="HIGH",
                        evidence=(
                            f"Script URL: {url}\n"
                            f"Suspicious domain: {domain}\n"
                            f"Pattern: {squatted_regex}\n"
                            f"Description: {desc}"
                        ),
                        url=url,
                        confidence="potential",
                    )
                    break

            if typosquat_found:
                continue

            # 6c. Check for suspicious TLDs
            tld_suspicious = False
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    tld_suspicious = True
                    self._result.add_finding(
                        message=(
                            f"Script loaded from suspicious TLD domain: {domain}"
                        ),
                        severity="HIGH",
                        evidence=(
                            f"Script URL: {url}\n"
                            f"Domain: {domain}\n"
                            f"Suspicious TLD: {tld}\n"
                            f"Unusual TLDs are commonly used for malicious domains"
                        ),
                        url=url,
                    )
                    break

            if tld_suspicious:
                continue

            # 6d. Unknown domain that's not in known-good list, heuristique
            # (origine non whitelistée != malveillant) → INFO/potential.
            self._result.add_finding(
                message=(
                    f"Unknown third-party script origin: {domain}"
                ),
                severity="INFO",
                confidence="potential",
                evidence=(
                    f"Script URL: {url}\n"
                    f"Unknown domain: {domain}\n"
                    f"This domain is not in the known-good whitelist, review and "
                    f"verify its legitimacy"
                ),
                url=url,
            )

    # ═══════════════════════════════════════════════════════════════
    # 7, Crypto Miner Detection
    # ═══════════════════════════════════════════════════════════════

    def _check_crypto_miners(self) -> None:
        """Scan for known crypto miner JS patterns (CRITICAL)."""
        body = self._get_homepage()
        if not body:
            return

        miner_found = False

        # 7a. Check external script URLs for miner domains
        external_scripts = self._extract_external_scripts(body)
        for url, tag in external_scripts:
            domain = self._get_domain(url)
            for miner_pattern in self.CRYPTO_MINER_URL_PATTERNS:
                if miner_pattern in domain:
                    miner_found = True
                    self._result.add_finding(
                        message=(
                            f"Crypto miner script detected: {domain}"
                        ),
                        severity="CRITICAL",
                        evidence=(
                            f"Script URL: {url}\n"
                            f"Miner domain: {domain}\n"
                            f"Matched pattern: {miner_pattern}\n"
                            f"Crypto miners consume CPU resources without user "
                            f"consent. IMMEDIATE REMEDIATION REQUIRED."
                        ),
                        url=url,
                    )
                    break

        # 7b. Check inline scripts for miner JS keywords
        inline_scripts = re.findall(
            r"<script[^>]*>(.*?)</script>",
            body, re.DOTALL | re.IGNORECASE
        )

        for script_content in inline_scripts:
            script_content_lower = script_content.lower()
            for pattern in self.CRYPTO_MINER_INLINE_PATTERNS:
                if re.search(pattern, script_content_lower, re.IGNORECASE):
                    # Avoid false-positives on common words like "anonymous"
                    if pattern == "Anonymous" and "CoinImp" not in script_content and "coinimp" not in script_content_lower:
                        if "Anonymous" not in script_content:  # distinct class name check
                            continue
                    # Avoid false-positives on "SiteKey" in reCAPTCHA
                    if pattern == "SiteKey" and "recaptcha" not in script_content_lower:
                        continue

                    miner_found = True
                    # Extract a snippet around the match
                    snippet = ""
                    match_obj = re.search(pattern, script_content, re.IGNORECASE)
                    if match_obj:
                        start = max(0, match_obj.start() - 40)
                        end = min(len(script_content), match_obj.end() + 40)
                        snippet = script_content[start:end]

                    self._result.add_finding(
                        message=(
                            f"Possible crypto miner pattern in inline script: "
                            f"'{pattern}'"
                        ),
                        severity="CRITICAL",
                        evidence=(
                            f"Matched pattern: {pattern}\n"
                            f"Snippet: ...{snippet}..."
                        ),
                        url=self.target,
                    )
                    break

        if not miner_found:
            self._result.add_finding(
                message="No crypto miner scripts detected",
                severity="INFO",
                evidence="All script URLs and inline scripts scanned, no miner patterns found",
                url=self.target,
            )

    # ═══════════════════════════════════════════════════════════════
    # 8, Data Exfiltration Risks
    # ═══════════════════════════════════════════════════════════════

    def _check_data_exfiltration(self) -> None:
        """Check for data exfiltration patterns in scripts."""
        body = self._get_homepage()
        if not body:
            return

        # 8a. Check inline scripts for navigator.sendBeacon
        inline_scripts = re.findall(
            r"<script[^>]*>(.*?)</script>",
            body, re.DOTALL | re.IGNORECASE
        )

        for script_content in inline_scripts:
            for pattern, label in self.DATA_EXFIL_PATTERNS:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                if matches:
                    for match in matches[:2]:
                        # Extract context around the match
                        match_text = match if isinstance(match, str) else str(match)
                        idx = script_content.find(match_text[:50])
                        if idx >= 0:
                            start = max(0, idx - 40)
                            end = min(len(script_content), idx + len(match_text[:50]) + 60)
                            snippet = script_content[start:end]
                        else:
                            snippet = match_text[:120]

                        self._result.add_finding(
                            message=(
                                f"Data exfiltration risk, {label} detected "
                                f"in inline script"
                            ),
                            severity="HIGH",
                            evidence=(
                                f"Pattern: {pattern}\n"
                                f"Snippet: ...{snippet}...\n"
                                f"navigator.sendBeacon can be used to send data "
                                f"to external servers without triggering standard "
                                f"network request monitoring"
                            ),
                            url=self.target,
                        )

        # 8b. Check for scripts loading from unexpected domains
        external_scripts = self._extract_external_scripts(body)
        target_domain = self._get_target_domain()

        for url, tag in external_scripts:
            domain = self._get_domain(url)

            # Skip same-domain scripts
            if domain == target_domain:
                continue
            if domain.endswith("." + target_domain) and target_domain.count(".") >= 1:
                continue

            # Skip known-good domains
            is_known = any(good in domain for good in self.KNOWN_GOOD_DOMAINS)
            if is_known:
                continue

            # We've already flagged unknown domains in section 6,
            # so here we note the exfiltration vector aspect
            self._result.add_finding(
                message=(
                    f"Script from {domain} could exfiltrate data, "
                    f"third-party code has full DOM access"
                ),
                severity="MEDIUM",
                confidence="potential",
                evidence=(
                    f"Script URL: {url}\n"
                    f"External domain: {domain}\n"
                    f"Third-party scripts execute with the same privileges as "
                    f"first-party code and can exfiltrate cookies, tokens, "
                    f"form data, and page content"
                ),
                url=url,
            )

    # ═══════════════════════════════════════════════════════════════
    # 9, Excessive Privilege (Browser API Abuse)
    # ═══════════════════════════════════════════════════════════════

    def _check_excessive_privilege(self) -> None:
        """Check for scripts accessing sensitive browser APIs."""
        body = self._get_homepage()
        if not body:
            return

        # 9a. Check inline scripts for API access
        inline_scripts = re.findall(
            r"<script[^>]*>(.*?)</script>",
            body, re.DOTALL | re.IGNORECASE
        )

        for script_content in inline_scripts:
            for pattern, description, severity in self.PRIVILEGE_PATTERNS:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                if matches:
                    idx = script_content.lower().find(description[:20].lower())
                    if idx >= 0:
                        start = max(0, idx - 40)
                        end = min(len(script_content), idx + 80)
                        snippet = script_content[start:end]
                    else:
                        # Try to find one of the matched patterns
                        for m in matches[:1]:
                            m_text = m if isinstance(m, str) else str(m)
                            idx2 = script_content.lower().find(m_text[:30].lower())
                            if idx2 >= 0:
                                start = max(0, idx2 - 40)
                                end = min(len(script_content), idx2 + 80)
                                snippet = script_content[start:end]
                                break
                        else:
                            snippet = "(pattern matched, context unavailable)"

                    self._result.add_finding(
                        message=(
                            f"Excessive browser privilege request, "
                            f"{description} detected in inline script"
                        ),
                        severity=severity,
                        evidence=(
                            f"Sensitive API: {description}\n"
                            f"Pattern: {pattern}\n"
                            f"Snippet: ...{snippet}...\n"
                            f"Third-party scripts should not access {description.lower()} "
                            f"as it enables user tracking or surveillance"
                        ),
                        url=self.target,
                        # Nom d'API trouvé dans le code, pas un usage observé.
                        confidence="potential",
                    )

        # 9b. Check external scripts by downloading and scanning content
        external_scripts = self._extract_external_scripts(body)
        for url, tag in external_scripts:
            domain = self._get_domain(url)
            target_domain = self._get_target_domain()

            # Skip same-domain scripts
            if domain == target_domain:
                continue
            if domain.endswith("." + target_domain) and target_domain.count(".") >= 1:
                continue

            try:
                resp = self.http_get_url(url)
                if resp.status_code == 200 and resp.text:
                    script_body = resp.text
                    for pattern, description, severity in self.PRIVILEGE_PATTERNS:
                        if re.search(pattern, script_body, re.IGNORECASE):
                            self._result.add_finding(
                                message=(
                                    f"Excessive browser privilege request, "
                                    f"{description} in external script from {domain}"
                                ),
                                severity=severity,
                                evidence=(
                                    f"Script URL: {url}\n"
                                    f"Sensitive API: {description}\n"
                                    f"External script loaded from {domain} "
                                    f"accesses {description.lower()}"
                                ),
                                url=url,
                                confidence="potential",
                            )
            except Exception:
                # Skip scripts that can't be fetched
                pass

    # ═══════════════════════════════════════════════════════════════
    # 10, Script Count Analysis
    # ═══════════════════════════════════════════════════════════════

    def _check_script_count(self) -> None:
        """Flag if more than MAX_EXTERNAL_SCRIPTS external scripts loaded."""
        body = self._get_homepage()
        if not body:
            return

        external_scripts = self._extract_external_scripts(body)
        script_count = len(external_scripts)

        if script_count == 0:
            return

        if script_count > self.MAX_EXTERNAL_SCRIPTS:
            self._result.add_finding(
                message=(
                    f"Excessive number of external scripts loaded "
                    f"({script_count} found, max recommended: "
                    f"{self.MAX_EXTERNAL_SCRIPTS})"
                ),
                severity="MEDIUM",
                evidence=(
                    f"Total external scripts: {script_count}\n"
                    f"Recommended maximum: {self.MAX_EXTERNAL_SCRIPTS}\n"
                    f"Excess: {script_count - self.MAX_EXTERNAL_SCRIPTS}\n\n"
                    f"Each external script increases:\n"
                    f"  - Attack surface (supply-chain vector per script)\n"
                    f"  - Page load time\n"
                    f"  - Data exposure (cookies, referrer, IP)\n"
                    f"  - JavaScript bundle size\n\n"
                    f"Scripts:\n"
                    + "\n".join(f"  {s[0]}" for s in external_scripts)
                ),
                url=self.target,
            )
        else:
            self._result.add_finding(
                message=f"External script count within acceptable range ({script_count})",
                severity="INFO",
                evidence=f"Total external scripts: {script_count} (limit: {self.MAX_EXTERNAL_SCRIPTS})",
                url=self.target,
            )

    # ═══════════════════════════════════════════════════════════════
    # 11, Bibliothèques JS front vulnérables (façon retire.js)
    # ═══════════════════════════════════════════════════════════════

    def _extract_all_script_srcs(self, body: str) -> List[str]:
        """Tous les src= des <script>, quelle que soit l'origine.

        Contrairement à _extract_external_scripts (http(s) absolus uniquement),
        on couvre AUSSI les scripts same-origin et relatifs : les libs WP sont
        souvent servies depuis le domaine du site
        (/wp-includes/js/jquery/jquery.min.js?ver=...).
        """
        return re.findall(
            r'<script\b[^>]*?\ssrc\s*=\s*["\']([^"\']+)["\']',
            body, re.IGNORECASE
        )

    def _match_js_lib(self, url: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Reconnaît (entrée de lib, version) depuis une URL de script.

        Renvoie (None, None) si aucune lib connue n'est identifiée ou si la
        version n'est pas extractible → pas de faux positif.
        """
        for entry in self.VULNERABLE_JS_LIBS:
            for pat in entry["match"]:
                m = re.search(pat, url, re.IGNORECASE)
                if m:
                    return entry, m.group(1)
        return None, None

    @staticmethod
    def _version_in_range(version: str, rng: Dict) -> bool:
        """True si `version` tombe dans la plage vulnérable `rng` (via _cmp)."""
        if rng.get("all"):
            return True
        try:
            if "ge" in rng and _cmp(version, rng["ge"]) < 0:
                return False
            if "gt" in rng and _cmp(version, rng["gt"]) <= 0:
                return False
            if "lt" in rng and not (_cmp(version, rng["lt"]) < 0):
                return False
            if "le" in rng and _cmp(version, rng["le"]) > 0:
                return False
        except Exception:
            # Version non comparable → on n'affirme rien (pas de faux positif).
            return False
        return True

    def _worst_vulnerable_range(self, entry: Dict, version: str) -> Optional[Dict]:
        """Parmi les plages qui matchent, garde celle au correctif le plus large
        (borne max la plus élevée) : un seul finding par lib, le plus englobant.
        """
        best = None
        best_max = None
        for rng in entry["vulnerable"]:
            if not self._version_in_range(version, rng):
                continue
            rmax = rng.get("lt") or rng.get("le")
            if best is None:
                best, best_max = rng, rmax
            elif rmax and (best_max is None or _cmp(rmax, best_max) > 0):
                best, best_max = rng, rmax
        return best

    def _check_vulnerable_js_libraries(self) -> None:
        """Détecte les libs JS front à version vulnérable servies sur la home."""
        body = self._get_homepage()
        if not body:
            return

        srcs = self._extract_all_script_srcs(body)
        if not srcs:
            return

        detected: List[Tuple[str, str, str]] = []   # (nom, version, url)
        seen_vuln = set()                            # (nom, version) déjà signalés

        for src in srcs:
            entry, version = self._match_js_lib(src)
            if not entry or not version:
                continue
            name = entry["name"]
            detected.append((name, version, src))

            rng = self._worst_vulnerable_range(entry, version)
            if not rng:
                continue
            key = (name, version)
            if key in seen_vuln:
                continue
            seen_vuln.add(key)

            label = rng.get("label", "")
            note = rng.get("note", "")
            cve = rng.get("cve", "")
            # Toutes les plages applicables à cette version, pas seulement la plus
            # large : évite de masquer une CVE d'une AUTRE classe (ex. prototype
            # pollution jQuery < 3.4.0 sous la XSS < 3.5.0 qui est plus englobante).
            autres = [r for r in entry["vulnerable"]
                      if self._version_in_range(version, r) and r is not rng]
            autres_line = ""
            if autres:
                autres_line = (
                    "Autres CVE applicables à cette version : "
                    + " ; ".join(f"{r.get('cve', '')} ({r.get('note', '')})"
                                 for r in autres)
                    + "\n"
                )
            self._result.add_finding(
                message=(
                    f"Bibliothèque JS vulnérable : {name} {version} "
                    f"({label}, {note}, {cve})"
                ),
                severity="HIGH",
                evidence=(
                    f"URL du script : {src}\n"
                    f"Bibliothèque : {name} {version}\n"
                    f"Plage vulnérable (la plus large) : {label}\n"
                    f"Impact : {note}\n"
                    f"Référence : {cve}\n"
                    + autres_line
                    + f"Reco : {entry['reco']}\n"
                    f"Note : ces libs embarquées (thème/plugin/CDN) échappent au "
                    f"flux CVE des plugins WordPress, détection type retire.js."
                ),
                url=src,
                confidence="potential",
            )

        # Récapitulatif INFO des libs JS détectées (même non vulnérables).
        if detected:
            libs = sorted({f"{n} {v}" for n, v, _ in detected})
            self._result.add_finding(
                message=(
                    f"{len(libs)} bibliothèque(s) JS front détectée(s) "
                    f"(inventaire des versions)"
                ),
                severity="INFO",
                evidence="Bibliothèques JS identifiées :\n"
                         + "\n".join(f"  - {lib}" for lib in libs),
                url=self.target,
            )
