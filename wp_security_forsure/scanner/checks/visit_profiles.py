"""Check visit_profiles : la même page vue par plusieurs profils de visite.

Les injections de 2025-2026 se cachent du profil que présente un outil : sans
Referer, sans cookie, agent utilisateur de script, visiteur connecté. Ce check
demande l'accueil et jusqu'à deux pages internes liées depuis l'accueil sous
plusieurs profils, chacun dans une session à cookies vierges, puis compare ce
que chaque variante charge : scripts et iframes d'autres sites, scripts
``data:``, chargeurs en ligne, redirections vers un autre site.

Profils, dans l'ordre d'envoi (le profil le plus proche d'une victime passe
en premier, avant toute requête de l'outil : certaines injections ne se
déclenchent qu'une fois par visiteur ou par adresse IP) :

  victim_google   navigateur de bureau, clic depuis Google ;
  victim_repeat   seconde visite du même visiteur (cookies conservés) ;
  mobile_google   navigateur mobile, clic depuis Google ;
  language        clic depuis Google, autre langue ;
  direct_a/b      navigateur de bureau, visite directe, deux fois (mesure la
                  variation normale de la page) ;
  logged_in       clic depuis Google avec un faux cookie de connexion
                  WordPress (valeur invalide : aucune session n'est ouverte) ;
  googlebot       agent utilisateur de Googlebot.

Méthode inspirée de « Cloak of Visibility » (Invernizzi et al., IEEE S&P
2016) : une différence ne compte que si la page ne varie pas déjà d'elle-même
entre deux visites directes. Toutes les requêtes sont des GET, avec les gardes
du client passif (méthode, SSRF, niveaux d'accès, budget). Ce que cite une
variante n'est jamais noté comme référencé, sauf les pages internes visitées
et les fichiers .js et .css (lus par le check client_injection).

Limites : sans JavaScript, les conditions évaluées dans le navigateur
(localStorage, détection d'automatisation) ne sont pas vues : voir la passe
de rendu (--render). Le cloaking qui vérifie l'adresse IP de Googlebot et le
ciblage par pays ne se déclenchent pas depuis l'adresse de l'auditeur.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

import requests

from .. import access_tiers
from ..htmlscan import (PageFeatures, checkout_page, host_of, internal_pages,
                        is_inline_loader, parse_page, same_site)
from ..injection_signatures import rpc_host_id
from .base import BaseCheck, CheckResult
from .cloaking_seo_spam import GOOGLEBOT_UA

CHROME_DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")
CHROME_ANDROID_UA = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36")
GOOGLE_REFERER = "https://www.google.com/"
FAKE_LOGIN_VALUE = "wpsf-no-session"

_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
           "image/webp,image/apng,*/*;q=0.8")


@dataclass(frozen=True)
class Profile:
    id: str
    label: str
    user_agent: str
    referer: str = ""
    language: str = "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
    mobile: bool = False
    logged_in_cookie: bool = False
    session: str = ""        # profils qui partagent une session (cookies)
    browser: bool = True

    def headers(self, target: str) -> Dict[str, str]:
        h = {"User-Agent": self.user_agent, "Accept": _ACCEPT,
             "Accept-Language": self.language}
        if self.browser:
            h.update({
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "cross-site" if self.referer else "none",
                "Sec-Fetch-User": "?1",
                "Sec-CH-UA-Mobile": "?1" if self.mobile else "?0",
                "Sec-CH-UA-Platform": '"Android"' if self.mobile else '"Windows"',
            })
        if self.referer:
            h["Referer"] = self.referer
        if self.logged_in_cookie:
            h["Cookie"] = f"{logged_in_cookie_name(target)}={FAKE_LOGIN_VALUE}"
        return h


def logged_in_cookie_name(target: str) -> str:
    """Nom du cookie de connexion WordPress (wordpress_logged_in_ + md5 de
    l'URL du site), comme le calcule WordPress (COOKIEHASH)."""
    site = (target or "").rstrip("/")
    return "wordpress_logged_in_" + hashlib.md5(site.encode("utf-8")).hexdigest()


PROFILES: Tuple[Profile, ...] = (
    Profile("victim_google", "clic depuis Google (bureau)", CHROME_DESKTOP_UA,
            referer=GOOGLE_REFERER, session="victim"),
    Profile("victim_repeat", "seconde visite du même visiteur", CHROME_DESKTOP_UA,
            referer=GOOGLE_REFERER, session="victim"),
    Profile("mobile_google", "mobile, clic depuis Google", CHROME_ANDROID_UA,
            referer=GOOGLE_REFERER, mobile=True),
    Profile("language", "clic depuis Google, autre langue (en-US)", CHROME_DESKTOP_UA,
            referer=GOOGLE_REFERER, language="en-US,en;q=0.9"),
    Profile("direct_a", "visite directe (1)", CHROME_DESKTOP_UA),
    Profile("direct_b", "visite directe (2)", CHROME_DESKTOP_UA),
    Profile("logged_in", "faux cookie de connexion WordPress", CHROME_DESKTOP_UA,
            referer=GOOGLE_REFERER, logged_in_cookie=True),
    Profile("googlebot", "agent Googlebot", GOOGLEBOT_UA, browser=False,
            language="en-US,en;q=0.9"),
)
PROFILE_LABELS = {p.id: p.label for p in PROFILES}
PROFILE_LABELS["tool"] = "agent du scanner"
BASELINE = ("direct_a", "direct_b")

Item = Tuple[str, str]   # (nature, hôte ou valeur)

_KIND_LABELS = {
    "script": "script chargé depuis {}",
    "iframe": "iframe vers {}",
    "redirect": "redirection vers {}",
    "data_script": "script data: (code embarqué dans l'URL du script)",
    "inline_loader": "chargeur en ligne (longue chaîne base64 décodée ou exécutée)",
}

# Conditions, de la plus parlante à la moins parlante.
_GATES = {
    "referer": ("HIGH", "absent sans Referer Google : comportement des injections qui "
                "ne visent que les visiteurs venus d'un moteur de recherche "
                "(DollyWay, Sign1)"),
    "logged_in": ("HIGH", "disparaît avec un cookie de connexion WordPress : "
                  "comportement des injections qui épargnent les administrateurs "
                  "(campagne ClickFix décrite par Rapid7 en 2026)"),
    "once": ("MEDIUM", "absent à la seconde visite : affichage limité à une fois "
             "par visiteur"),
    "tool_hidden": ("MEDIUM", "absent pour l'agent du scanner : masqué aux outils"),
    "mobile": ("MEDIUM", "servi seulement au mobile (peut être légitime : thème "
               "ou publicité mobiles)"),
    "language": ("MEDIUM", "servi seulement à une autre langue (peut être légitime : "
                 "extension multilingue)"),
    "googlebot": ("MEDIUM", "servi seulement à l'agent Googlebot"),
}
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}
_STATIC_RE = re.compile(r"\.(?:m?js|css)$", re.I)


@dataclass
class Variant:
    profile: str
    status: Optional[int] = None
    error: str = ""
    final_url: str = ""
    features: PageFeatures = field(default_factory=PageFeatures)
    items: Set[Item] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return self.status is not None and not self.error


def variant_items(features: PageFeatures, status: Optional[int], location: str,
                  target: str) -> Set[Item]:
    """Éléments comparés entre profils : ce qui vient d'un autre site ou
    ressemble à un chargeur."""
    th = host_of(target)
    items: Set[Item] = set()
    for src in features.script_srcs:
        h = host_of(src)
        if h and not same_site(h, th):
            items.add(("script", h))
    for src in features.iframes:
        h = host_of(src)
        if h and not same_site(h, th):
            items.add(("iframe", h))
    if features.data_scripts:
        items.add(("data_script", "data:"))
    if any(is_inline_loader(s) for s in features.inline_scripts):
        items.add(("inline_loader", "inline"))
    redirects = list(features.js_redirects)
    if features.meta_refresh:
        redirects.append(features.meta_refresh)
    if status is not None and 300 <= status < 400 and location:
        redirects.append(location)
    for url in redirects:
        h = host_of(url)
        if h and not same_site(h, th):
            items.add(("redirect", h))
    return items


def compare(variants: Dict[str, Variant], tool: Optional[Variant] = None
            ) -> Tuple[Dict[Item, Set[str]], Set[str]]:
    """Conditions remplies par chaque élément, et natures d'éléments qui
    varient déjà entre les deux visites directes (bruit de la page)."""
    def items(pid: str) -> Optional[Set[Item]]:
        v = variants.get(pid)
        return v.items if v is not None and v.ok else None

    a, b = items("direct_a"), items("direct_b")
    baseline = (a or set()) | (b or set())
    volatile = {kind for kind, _ in ((a ^ b) if a is not None and b is not None else set())}
    p1, repeat = items("victim_google"), items("victim_repeat")
    mobile, lang = items("mobile_google"), items("language")
    logged, gbot = items("logged_in"), items("googlebot")
    tool_items = tool.items if tool is not None and tool.ok else None
    have_baseline = a is not None or b is not None

    gates: Dict[Item, Set[str]] = {}

    def add(item: Item, gate: str) -> None:
        gates.setdefault(item, set()).add(gate)

    for item in set().union(*(v.items for v in variants.values() if v.ok)) if variants else set():
        in_p1 = p1 is not None and item in p1
        in_base = item in baseline
        if have_baseline and in_p1 and not in_base:
            add(item, "referer")
        if in_p1 and logged is not None and item not in logged:
            add(item, "logged_in")
        if (have_baseline and mobile is not None and item in mobile
                and not in_base and not in_p1):
            add(item, "mobile")
        if (have_baseline and lang is not None and item in lang
                and not in_base and not in_p1):
            add(item, "language")
        if in_p1 and in_base and repeat is not None and item not in repeat:
            add(item, "once")
        if tool_items is not None and (in_p1 or in_base) and item not in tool_items:
            add(item, "tool_hidden")
        if (have_baseline and gbot is not None and item in gbot
                and not in_base and not in_p1):
            add(item, "googlebot")
    return gates, volatile


def item_severity(item: Item, gates: Set[str], volatile: Set[str]) -> str:
    severity = min((_GATES[g][0] for g in gates), key=lambda s: _SEV_RANK[s])
    kind, value = item
    if kind in ("data_script", "inline_loader", "redirect") and _SEV_RANK[severity] > 1:
        severity = "HIGH"
    if kind in volatile:
        severity = _DOWNGRADE[severity]
    if kind in ("script", "iframe", "redirect") and rpc_host_id(value):
        severity = "CRITICAL"
    return severity


class VisitProfilesCheck(BaseCheck):
    """Compare l'accueil et des pages internes vus par plusieurs profils."""

    name = "visit_profiles"
    title = "Profils de visite (injections conditionnelles)"
    description = (
        "Demande l'accueil et jusqu'à deux pages internes sous plusieurs profils "
        "(clic depuis Google, mobile, autre langue, visite directe, faux cookie "
        "de connexion, seconde visite, Googlebot) et compare ce que chaque "
        "variante charge : une injection servie seulement à certains visiteurs "
        "se voit dans l'écart.")
    severity = "HIGH"
    access_tier = 0   # accueil et pages qu'il lie
    priority = 1
    depends_on: List[str] = []

    def run(self) -> CheckResult:
        if self.config.get("visit_profiles", True) is False:
            self._result.add_finding(
                message="Profils de visite désactivés (visit_profiles: false)",
                severity="INFO", evidence="Aucune comparaison réalisée.",
                url=self.target, confidence="confirmed")
            return self._result
        home = self.target.rstrip("/") + "/"
        sessions: Dict[str, requests.Session] = {}
        pages: Dict[str, Dict[str, Variant]] = {}

        home_variants = self._visit(home, sessions)
        pages[home] = home_variants
        first = home_variants.get("victim_google")
        if first is None or not first.ok:
            self._result.add_finding(
                message="Profils de visite non comparés : l'accueil ne répond pas "
                        "au premier profil",
                severity="INFO",
                evidence=(first.error if first is not None else "")[:200],
                url=home, confidence="potential")
            self._store(pages, None)
            return self._result

        # Agent du scanner, après les profils de navigateur (réponse mise en
        # cache pour les autres checks).
        tool = self._tool_variant(home)

        links = list(first.features.links)
        for pid in BASELINE:
            v = home_variants.get(pid)
            if v is not None and v.ok:
                links.extend(v.features.links)
        max_pages = int(self.config.get("visit_profiles_pages", 2) or 0)
        extra = internal_pages(links, self.target, limit=max_pages)
        checkout = checkout_page(links, self.target)
        if checkout and checkout not in extra and max_pages > 0:
            extra = extra[:max(0, max_pages - 1)] + [checkout]
        self._mark_referenced(extra)
        for url in extra:
            pages[url] = self._visit(url, sessions)

        for url, variants in pages.items():
            self._mark_referenced(self._static_assets(variants))
            self._analyze(url, variants, tool if url == home else None)
        self._summary(pages, tool)
        self._store(pages, tool)
        return self._result

    # ── Requêtes ─────────────────────────────────────────────────────

    def _visit(self, url: str, sessions: Dict[str, requests.Session]) -> Dict[str, Variant]:
        variants: Dict[str, Variant] = {}
        for profile in PROFILES:
            key = profile.session or f"{profile.id}:{url}"
            client = sessions.get(key)
            if client is None:
                client = self.profile_client()
                sessions[key] = client
            variant = self._fetch(url, profile, client)
            variants[profile.id] = variant
            if profile is PROFILES[0] and variant.status is None:
                # Pas de réponse au premier profil (cible injoignable) : on
                # n'attend pas sept délais de plus, la sonde de joignabilité
                # du moteur rendra le verdict.
                break
        return variants

    def _fetch(self, url: str, profile: Profile, client: requests.Session) -> Variant:
        variant = Variant(profile.id)
        try:
            resp = self.profile_get(url, client, profile.headers(self.target))
        except requests.exceptions.RequestException as exc:
            variant.error = f"{type(exc).__name__}: {exc}"[:200]
            return variant
        variant.status = resp.status_code
        variant.final_url = resp.url or url
        location = resp.headers.get("Location", "") if resp.is_redirect else ""
        if location:
            location = urljoin(variant.final_url, location)
        content_type = (resp.headers.get("Content-Type") or "").lower()
        body = resp.text if ("html" in content_type or not content_type) else ""
        variant.features = parse_page(body or "", variant.final_url)
        variant.items = variant_items(variant.features, variant.status, location,
                                      self.target)
        return variant

    def _tool_variant(self, home: str) -> Optional[Variant]:
        variant = Variant("tool")
        try:
            resp = self.http_get("/")
        except requests.exceptions.RequestException as exc:
            variant.error = type(exc).__name__
            return variant
        variant.status = resp.status_code
        variant.final_url = resp.url or home
        location = resp.headers.get("Location", "") if resp.is_redirect else ""
        variant.features = parse_page(resp.text or "", variant.final_url)
        variant.items = variant_items(variant.features, variant.status, location,
                                      self.target)
        return variant

    def _mark_referenced(self, urls: List[str]) -> None:
        if urls:
            access_tiers.add_references(self.references(), urls,
                                        self.target, access_tiers.TIER_HOME)

    def _static_assets(self, variants: Dict[str, Variant]) -> List[str]:
        """Fichiers .js et .css du site cités par les variantes : notés comme
        référencés pour que client_injection puisse les lire (jamais un .php)."""
        th = host_of(self.target)
        out = []
        for v in variants.values():
            for src in v.features.script_srcs:
                path = urlsplit(src).path
                if same_site(host_of(src), th) and _STATIC_RE.search(path):
                    out.append(src)
        return out

    # ── Analyse ──────────────────────────────────────────────────────

    def _analyze(self, url: str, variants: Dict[str, Variant],
                 tool: Optional[Variant]) -> None:
        gates, volatile = compare(variants, tool)
        all_ids = [p.id for p in PROFILES] + ["tool"]
        for item, item_gates in sorted(gates.items()):
            present = [pid for pid in all_ids if self._has(variants, tool, pid, item)]
            absent = [pid for pid in all_ids if self._ok(variants, tool, pid)
                      and not self._has(variants, tool, pid, item)]
            severity = item_severity(item, item_gates, volatile)
            kind, value = item
            what = _KIND_LABELS[kind].format(value)
            reasons = [_GATES[g][1] for g in sorted(item_gates, key=lambda g: list(_GATES).index(g))]
            note = ""
            if kind in volatile:
                note = (" Sévérité abaissée : ce type d'élément varie déjà entre "
                        "deux visites directes.")
            if rpc_host_id(value):
                note += " L'hôte est un nœud RPC ou un explorateur de blockchain."
            self._result.add_finding(
                message=("Injection conditionnelle possible : " + what
                         + ", servi seulement à certains profils de visite"),
                severity=severity,
                evidence=(
                    "Présent : " + ", ".join(PROFILE_LABELS[p] for p in present)
                    + ". Absent : " + ", ".join(PROFILE_LABELS[p] for p in absent)
                    + ". Lecture : " + " ; ".join(reasons) + "." + note)[:900],
                url=url,
                confidence="potential",
            )

    @staticmethod
    def _variant(variants, tool, pid) -> Optional[Variant]:
        return tool if pid == "tool" else variants.get(pid)

    def _ok(self, variants, tool, pid) -> bool:
        v = self._variant(variants, tool, pid)
        return v is not None and v.ok

    def _has(self, variants, tool, pid, item) -> bool:
        v = self._variant(variants, tool, pid)
        return v is not None and v.ok and item in v.items

    def _summary(self, pages: Dict[str, Dict[str, Variant]], tool: Optional[Variant]) -> None:
        errors = []
        statuses = []
        for url, variants in pages.items():
            failed = [PROFILE_LABELS[pid] for pid, v in variants.items() if not v.ok]
            if failed:
                errors.append(f"{url} : " + ", ".join(failed))
            codes = sorted({v.status for v in variants.values() if v.ok})
            statuses.append(f"{url} (HTTP {', '.join(str(c) for c in codes) or '-'})")
            _, volatile = compare(variants, None)
            if volatile:
                statuses[-1] += " ; varie entre deux visites directes : " + ", ".join(sorted(volatile))
        evidence = (f"{len(PROFILES)} profils sur {len(pages)} page(s) : "
                    + " | ".join(statuses))
        if errors:
            evidence += " | Profils sans réponse : " + " | ".join(errors)
        evidence += (" | Non couvert : conditions évaluées en JavaScript (voir "
                     "--render), cloaking vérifié par l'adresse IP de Googlebot, "
                     "ciblage par pays.")
        self._result.add_finding(
            message="Profils de visite comparés",
            severity="INFO", evidence=evidence[:1500], url=self.target,
            confidence="confirmed")

    def _store(self, pages, tool) -> None:
        """Variantes partagées avec client_injection et browser_render."""
        self.context["visit_profiles"] = {
            "pages": {url: {pid: v.features for pid, v in variants.items() if v.ok}
                      for url, variants in pages.items()},
            "conditional": [f for f in self._result.findings
                            if f.get("severity") != "INFO"],
            "tool": tool.features if tool is not None and tool.ok else None,
        }
