"""Empreinte : énumère plugins/thèmes/core installés (passif + confirmation)."""
import re
from collections import Counter
from typing import List, Optional
from .base import BaseCheck, CheckResult
from . import common_components

_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9\-_]+)/", re.I)
_THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9][a-z0-9\-_]+)/", re.I)
_VER_RE = re.compile(
    r"/wp-content/(?:plugins|themes)/([a-z0-9][a-z0-9\-_]+)/[^\"'>]*?\?ver=([0-9][\w.\-]*)",
    re.I,
)
_GEN_RE = re.compile(r'name=["\']generator["\']\s+content=["\']WordPress\s+([0-9][0-9.]*)', re.I)
# Extraction tolérante de TOUTES les balises <meta name="generator"> (ordre
# des attributs indifférent), pour la détection de plugins par auto-signature
# (_detect_via_generators), contrairement à _GEN_RE, ciblé sur le seul core.
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I)
_META_NAME_RE = re.compile(r'name=["\']([^"\']*)["\']', re.I)
_META_CONTENT_RE = re.compile(r'content=["\']([^"\']*)["\']', re.I)
# Version du core portée par le cache-buster ?ver= des ressources du cœur
# (wp-includes, wp-admin). Bien plus résistant que la balise generator ou
# readme.html, tous deux supprimés par le moindre durcissement (et signalés
# comme un défaut par file_exposure) : c'est précisément sur ces sites durcis
# que la détection de version cassait (faux négatif possible sur wp2shell /
# CVE-2026-63030). wp-login.php charge aussi des ressources d'admin
# versionnées (login.min.css, wp-admin/css/...).
_CORE_ASSET_RE = re.compile(
    r"/(?:wp-includes|wp-admin)/([^\"'<>\s?#]+)\?ver=([^\"'<>\s&#]+)", re.I
)
# Une version de WordPress : X.Y ou X.Y.Z, sans suffixe (les ?ver= du type
# « 3.1-20121105 » ou les empreintes de js/dist/ ne suivent pas le cœur).
_CORE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
# Bibliothèques tierces embarquées dans wp-includes : leur ?ver= est celui de
# la bibliothèque (jQuery 3.7.1, underscore 1.13.4, React 18...), jamais celui
# du cœur. Les paquets js/dist/ portent aussi leur propre version.
_THIRD_PARTY_ASSET_MARKERS = (
    "jquery", "tinymce", "/js/dist/", "underscore", "backbone", "plupload",
    "mediaelement", "codemirror", "imagesloaded", "masonry", "hoverintent",
    "clipboard", "thickbox", "swfobject", "twemoji", "swfupload", "jcrop",
    "/js/crop/", "json2", "colorpicker", "zxcvbn", "tw-sack", "polyfill",
    "react", "lodash", "moment", "regenerator",
)
# Version exposée par le <generator> du flux RSS (/feed/) : rarement retiré.
_FEED_GEN_RE = re.compile(
    r"<generator>https?://wordpress\.org/\?v=([0-9][0-9.]*)</generator>", re.I
)
_STABLE_RE = re.compile(r"Stable tag:\s*([0-9][\w.\-]*)", re.I)
_READMEVER_RE = re.compile(r"^\s*Version:\s*([0-9][\w.\-]*)", re.I | re.M)
_STYLEVER_RE = re.compile(r"Version:\s*([0-9][\w.\-]*)", re.I)
_README_HTML_VER_RE = re.compile(r"Version\s+([0-9][0-9.]*)")

# Libellés des sources de version du cœur, dans l'ordre de priorité.
_CORE_SOURCE_LABEL = {
    "generator": "balise generator",
    "wpinc_ver": "ressources du cœur (accueil)",
    "login_wpinc_ver": "ressources du cœur (page de connexion)",
    "feed_generator": "flux RSS",
    "readme_html": "readme.html",
}


def core_asset_versions(html: str) -> List[str]:
    """?ver= des ressources du cœur dont la version suit celle de WordPress,
    dans l'ordre du document. Bibliothèques tierces embarquées et versions au
    format non conforme exclues."""
    out = []
    for path, ver in _CORE_ASSET_RE.findall(html or ""):
        low = "/" + path.lower()
        if any(marker in low for marker in _THIRD_PARTY_ASSET_MARKERS):
            continue
        if _CORE_VERSION_RE.match(ver):
            out.append(ver)
    return out


def _dominant(versions: List[str]) -> Optional[str]:
    """Version la plus fréquente (à égalité, la première vue)."""
    if not versions:
        return None
    return Counter(versions).most_common(1)[0][0]


def _norm(version: str) -> tuple:
    """6.4.0 == 6.4 : composants numériques, zéros finaux retirés."""
    parts = [int(p) for p in str(version).split(".") if p.isdigit()]
    while len(parts) > 2 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _versions_agree(sources) -> bool:
    """True si toutes les sources donnent la même version. readme.html peut
    n'afficher que la branche (6.4) : elle concorde alors avec 6.4.x."""
    exact = {_norm(v) for s, v in sources if s != "readme_html"}
    if len(exact) > 1:
        return False
    for s, v in sources:
        if s != "readme_html":
            continue
        branch = _norm(v)
        if any(full != branch and full[:len(branch)] != branch for full in exact):
            return False
    return True


class FingerprintCheck(BaseCheck):
    name = "fingerprint"
    title = "Empreinte WordPress (plugins/thèmes/core)"
    description = "Énumère les composants installés et leurs versions."
    severity = "INFO"
    access_tier = 1  # mixte : readme.txt et style.css devinés sous --authorized
    depends_on: List[str] = []

    def run(self) -> CheckResult:
        try:
            resp = self.http_get("/")
            html = resp.text or ""
        except Exception as e:
            self._result.add_finding(
                message="Empreinte impossible, page d'accueil injoignable",
                severity="INFO", evidence=str(e)[:150], url=self.target,
                confidence="confirmed")
            self.context["inventory"] = {"core": None, "plugins": [], "themes": []}
            return self._result

        ver_by_slug = {}
        for slug, ver in _VER_RE.findall(html):
            ver_by_slug.setdefault(slug.lower(), ver)

        plugins = self._collect(html, _PLUGIN_RE, ver_by_slug, kind="plugin")
        themes = self._collect(html, _THEME_RE, ver_by_slug, kind="theme")
        self._detect_via_generators(html, plugins)
        self._probe_common(plugins, themes)
        self._detect_via_rest_namespaces(plugins)
        plugins.sort(key=lambda p: p["slug"])
        themes.sort(key=lambda t: t["slug"])
        core = self._detect_core(html)
        self._emit_version_exposed_finding(core)
        if not self.config.get("authorized"):
            self.note_unlinked_skipped(
                "confirmation des versions par readme.txt et style.css, et "
                f"détection des {len(common_components.COMMON_PLUGINS)} extensions "
                f"et {len(common_components.COMMON_THEMES)} thèmes courants non "
                "référencés par la page")

        inv = {"core": core, "plugins": plugins, "themes": themes}
        self.context["inventory"] = inv

        self._result.add_finding(
            message=(f"Empreinte : core={core['version'] if core else '?'}, "
                     f"{len(plugins)} plugin(s), {len(themes)} thème(s)"),
            severity="INFO",
            evidence=(
                "Plugins: " + ", ".join(f"{p['slug']} {p['version'] or '?'}" for p in plugins)
                + "\nThèmes: " + ", ".join(f"{t['slug']} {t['version'] or '?'}" for t in themes)
            ),
            url=self.target, confidence="confirmed")
        return self._result

    # Sources par lesquelles la version core est *volontairement affichée*
    # (retirables d'un coup de configuration/hardening), par opposition aux
    # sources fondées sur un ?ver= d'asset (wpinc_ver, login_wpinc_ver),
    # signal technique difficile à supprimer et donc pas un « choix » exposé.
    _ADVERTISED_CORE_SOURCES = ("generator", "readme_html")

    def _emit_version_exposed_finding(self, core):
        """Constat recon : la version du core est publiquement annoncée via
        un signal facilement retirable (balise generator / readme.html).
        Ça n'est pas une vulnérabilité en soi, mais ça facilite le ciblage
        d'exploits connus une fois la version connue, donc un constat de
        durcissement à faible sévérité, distinct de la détection elle-même."""
        if not core or core.get("source") not in self._ADVERTISED_CORE_SOURCES:
            return
        version = core["version"]
        source = core["source"]
        remediation = (
            "Retirer la balise <meta name=\"generator\"> du thème"
            if source == "generator" else
            "Supprimer (ou bloquer l'accès à) readme.html à la racine"
        )
        self._result.add_finding(
            message=(f"Version WordPress exposée ({version}) via {source} "
                     f"- facilite le ciblage d'exploits connus"),
            severity="LOW",
            evidence=f"Signal exposé : {source}\nRemédiation : {remediation}",
            url=self.target,
            confidence="confirmed",
            access_class="recon",
        )

    def _collect(self, html, slug_re, ver_by_slug, kind):
        slugs = sorted({m.lower() for m in slug_re.findall(html)})
        out = []
        for slug in slugs:
            version = ver_by_slug.get(slug)
            source = "ver_param" if version else None
            confirmed = self._confirm(slug, kind)
            if confirmed:
                version, source = confirmed, ("readme" if kind == "plugin" else "style")
            out.append({"slug": slug, "version": version, "source": source})
        return out

    def _probe_common(self, plugins, themes):
        """Sonde active bornée : détecte les composants courants non vus passivement.

        Chemins devinés (niveau 2) : seulement avec --authorized."""
        if not self.config.get("authorized"):
            return
        known_p = {p["slug"] for p in plugins}
        for slug in common_components.COMMON_PLUGINS:
            if slug in known_p:
                continue
            v = self._confirm(slug, "plugin")
            if v:
                plugins.append({"slug": slug, "version": v, "source": "readme"})
        known_t = {t["slug"] for t in themes}
        for slug in common_components.COMMON_THEMES:
            if slug in known_t:
                continue
            v = self._confirm(slug, "theme")
            if v:
                themes.append({"slug": slug, "version": v, "source": "style"})

    def _detect_via_generators(self, html, plugins):
        """Complète l'inventaire via les balises <meta name="generator"> que
        de nombreux plugins s'attribuent eux-mêmes avec leur propre version
        (Yoast, WooCommerce, Elementor, Slider Revolution, Rank Math...).
        Purement passif : relit le HTML de la home déjà récupéré, aucune
        requête réseau supplémentaire. Une version obtenue ainsi est aussi
        fiable qu'un readme.txt (source="generator", éligible confirmed en
        aval), on l'utilise donc pour compléter un slug déjà vu sans
        version, mais jamais pour écraser une version déjà confirmée."""
        by_slug = {p["slug"]: p for p in plugins}
        for tag in _META_TAG_RE.findall(html):
            name_m = _META_NAME_RE.search(tag)
            if not name_m or name_m.group(1).strip().lower() != "generator":
                continue
            content_m = _META_CONTENT_RE.search(tag)
            if not content_m:
                continue
            content = content_m.group(1).strip()
            if content.lower().startswith("wordpress "):
                continue  # cœur, déjà géré par _detect_core / _GEN_RE
            for regex, slug in common_components.PLUGIN_GENERATOR_SIGNATURES:
                m = regex.search(content)
                if not m:
                    continue
                version = m.group(1) if m.groups() and m.group(1) else None
                existing = by_slug.get(slug)
                if existing is None:
                    entry = {"slug": slug, "version": version, "source": "generator"}
                    plugins.append(entry)
                    by_slug[slug] = entry
                elif not existing.get("version") and version:
                    existing["version"] = version
                    existing["source"] = "generator"

    def _detect_via_rest_namespaces(self, plugins):
        """Complète l'inventaire passif via les namespaces exposés sur
        /wp-json : un plugin actif enregistre presque toujours son propre
        namespace REST, même quand aucun de ses assets n'apparaît dans le
        HTML de la home (cache agressif, chargement conditionnel). C'est la
        même énumération qu'un attaquant ferait, on l'ajoute donc en passif,
        en complément de _collect/_probe_common, jamais à leur place."""
        try:
            resp = self.http_get("/wp-json")
            if resp.status_code != 200 or self._is_soft404(resp):
                return
            data = resp.json()
        except Exception:
            return

        namespaces = data.get("namespaces") if isinstance(data, dict) else None
        if not namespaces:
            return

        known = {p["slug"] for p in plugins}
        for ns in namespaces:
            prefix = str(ns).split("/", 1)[0].strip().lower()
            if not prefix or prefix in common_components.CORE_REST_NAMESPACES:
                continue
            slug = common_components.NAMESPACE_TO_SLUG.get(prefix, prefix)
            if slug in known:
                continue
            known.add(slug)
            version = self._confirm(slug, "plugin")
            source = "readme" if version else "rest_namespace"
            plugins.append({"slug": slug, "version": version, "source": source})

    def _confirm(self, slug, kind):
        # Un site soft-404 renvoie 200 + page d'accueil pour tout readme.txt /
        # style.css inexistant. Sans garde, un « Version: » parasite de la home
        # confirme des dizaines de composants fantômes → CVE fausses en aval.
        # readme.txt et style.css ne sont pas liés par la page : niveau 2, sauf
        # une feuille de style de thème que la page référence (niveau 0).
        path = (f"/wp-content/plugins/{slug}/readme.txt" if kind == "plugin"
                else f"/wp-content/themes/{slug}/style.css")
        if not self.may_request(path):
            return None
        try:
            if kind == "plugin":
                r = self.http_get(path)
                if r.status_code == 200 and r.text and not self._is_soft404(r):
                    # Un vrai readme.txt WordPress porte l'en-tête plugin / Stable tag.
                    low = r.text.lower()
                    if "stable tag:" not in low and "===" not in r.text:
                        return None
                    m = _STABLE_RE.search(r.text) or _READMEVER_RE.search(r.text)
                    if m:
                        return m.group(1)
            else:
                r = self.http_get(path)
                if r.status_code == 200 and r.text and not self._is_soft404(r):
                    # Un vrai style.css porte l'en-tête « Theme Name: ».
                    if "theme name:" not in r.text.lower():
                        return None
                    m = _STYLEVER_RE.search(r.text)
                    if m:
                        return m.group(1)
        except Exception:
            return None
        return None

    def _detect_core(self, html):
        """Lit TOUTES les sources de version du cœur puis les croise.

        Ordre de priorité (version retenue = première source trouvée) :
        balise generator, ressources du cœur de l'accueil, page de connexion,
        flux RSS, readme.html. Les sources fondées sur un ?ver= survivent au
        durcissement (suppression de la balise generator et de readme.html) :
        sans elles, un site à jour côté hygiène ressortait « core=? » et
        échappait au matching CVE du cœur. Si les sources divergent, la
        version est rétrogradée en « potential » et un constat le signale.
        """
        sources = []
        m = _GEN_RE.search(html)
        if m:
            sources.append(("generator", m.group(1)))
        home_ver = _dominant(core_asset_versions(html))
        if home_ver:
            sources.append(("wpinc_ver", home_ver))
        login_ver = self._detect_core_via_login()
        if login_ver:
            sources.append(("login_wpinc_ver", login_ver))
        feed_ver = self._detect_core_via_feed()
        if feed_ver:
            sources.append(("feed_generator", feed_ver))
        readme_ver = self._detect_core_via_readme()
        if readme_ver:
            sources.append(("readme_html", readme_ver))
        if not sources:
            return None

        source, version = sources[0]
        agree = _versions_agree(sources)
        core = {"version": version, "source": source,
                "confidence": "confirmed" if agree else "potential",
                "sources": dict(sources)}
        if not agree:
            self._emit_inconsistent_core_finding(sources, version, source)
        return core

    def _emit_inconsistent_core_finding(self, sources, version, source):
        listing = "\n".join(f"{_CORE_SOURCE_LABEL.get(s, s)} : {v}" for s, v in sources)
        values = " / ".join(dict.fromkeys(v for _, v in sources))
        self._result.add_finding(
            message=("Versions incohérentes entre sources : mise à jour peut-être "
                     f"incomplète ou version masquée (WordPress {values})"),
            severity="LOW",
            evidence=(f"{listing}\n"
                      f"Version retenue pour l'analyse CVE : {version} "
                      f"({_CORE_SOURCE_LABEL.get(source, source)}) ; les "
                      "vulnérabilités du cœur sont donc signalées « à vérifier »."),
            url=self.target,
            confidence="potential",
            access_class="recon",
        )

    def _detect_core_via_readme(self):
        """Version du core lue dans readme.html (source la plus fragile)."""
        try:
            r = self.http_get("/readme.html")
            if r.status_code == 200 and not self._is_soft404(r):
                m = _README_HTML_VER_RE.search(r.text or "")
                if m:
                    return m.group(1)
        except Exception:
            pass
        return None

    def _detect_core_via_login(self):
        """Version du core lue dans les ressources versionnées de wp-login.php.

        La home peut être statique/cachée et avoir perdu tout signal de
        version ; wp-login.php, lui, est généré dynamiquement à chaque
        requête et charge toujours les ressources du cœur versionnées
        (wp-includes/..., wp-admin/...), difficiles à faire disparaître
        sans casser l'authentification elle-même. Les bibliothèques tierces
        qu'elle charge aussi (jQuery, underscore) sont exclues."""
        try:
            r = self.http_get("/wp-login.php")
            if r.status_code != 200 or self._is_soft404(r):
                return None
            return _dominant(core_asset_versions(r.text or ""))
        except Exception:
            pass
        return None

    def _detect_core_via_feed(self):
        """Version du core lue dans le <generator> du flux RSS (/feed/)."""
        try:
            r = self.http_get("/feed/")
            if r.status_code == 200 and not self._is_soft404(r):
                m = _FEED_GEN_RE.search(r.text or "")
                if m:
                    return m.group(1)
        except Exception:
            pass
        return None
