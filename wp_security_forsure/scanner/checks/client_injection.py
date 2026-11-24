"""Check client_injection : signatures ClickFix et EtherHiding dans les scripts.

Lit, sans rien exécuter :
  - les scripts en ligne de l'accueil et des pages comparées par
    visit_profiles, pour chaque profil de visite (une injection peut n'être
    servie qu'à certains profils) ;
  - le contenu décodé des scripts ``data:`` (forme du chargeur ClearFake
    2026, sans URL externe à bloquer) ;
  - les fichiers .js du site cités par ces pages (une injection se loge
    souvent dans un script du thème, d'une extension ou dans jquery.min.js) ;
  - quelques scripts d'autres sites, hors bibliothèques et grands services
    connus, ceux servis seulement à certains profils d'abord.

Les URL de bibliothèques blockchain (web3, ethers, pako, crypto-js) sont
jugées sur leur présence, pas sur leur contenu : il contient légitimement
eth_call et JSON-RPC. Les motifs et leurs sources sont dans
signatures/injection_signatures.yaml.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

import requests

from ..htmlscan import PageFeatures, host_of, parse_page, same_site
from ..injection_signatures import (Hit, decode_data_script, is_library_url,
                                    library_hits, scan_script)
from .base import BaseCheck, CheckResult
from .visit_profiles import PROFILE_LABELS

# Services très répandus dont le contenu n'est pas lu (bruit, coût) ; leur
# présence reste jugée par les autres checks (third_party_scripts).
_WELL_KNOWN_HOSTS = (
    "googletagmanager.com", "google-analytics.com", "gstatic.com", "googleapis.com",
    "google.com", "recaptcha.net", "doubleclick.net", "googlesyndication.com",
    "facebook.net", "facebook.com", "wp.com", "w.org", "wordpress.com",
    "jquery.com", "bootstrapcdn.com", "cloudflareinsights.com", "hotjar.com",
    "youtube.com", "vimeo.com", "stripe.com", "paypal.com", "hubspot.com",
    "cookiebot.com", "onetrust.com", "cookielaw.org", "axeptio.eu",
    "tarteaucitron.io", "matomo.cloud", "clarity.ms", "bing.com",
)
_JS_PATH_SUFFIXES = (".js", ".mjs")


def _is_well_known(host: str) -> bool:
    host = (host or "").lower()
    return any(host == h or host.endswith("." + h) for h in _WELL_KNOWN_HOSTS)


class ClientInjectionCheck(BaseCheck):
    """Signatures ClickFix et EtherHiding dans les scripts servis aux visiteurs."""

    name = "client_injection"
    title = "Injections côté navigateur (ClickFix, EtherHiding)"
    description = (
        "Cherche dans les scripts servis aux visiteurs (en ligne, data:, fichiers "
        ".js du site, scripts tiers inconnus) les signatures publiées du faux "
        "CAPTCHA ClickFix et des chargeurs EtherHiding qui lisent leur charge "
        "sur une blockchain.")
    severity = "CRITICAL"
    access_tier = 0
    priority = 1
    depends_on = ["visit_profiles"]

    def run(self) -> CheckResult:
        sources = self._page_sources()
        self._hits: Dict[Tuple[str, str], dict] = {}
        srcs_by_profile: Dict[str, Set[str]] = {}
        for page, profile, features in sources:
            for script in features.inline_scripts:
                self._scan(script, page, profile, "script en ligne")
            for data_src in features.data_scripts:
                self._data_script(data_src, page, profile)
            srcs_by_profile.setdefault(profile, set()).update(features.script_srcs)

        all_srcs = sorted(set().union(*srcs_by_profile.values())) if srcs_by_profile else []
        for hit in library_hits(all_srcs):
            self._record(hit, self.target, "toutes", "URL des scripts")
        self._scan_site_scripts(all_srcs)
        self._scan_external_scripts(all_srcs, srcs_by_profile)
        self._emit()
        return self._result

    # ── Sources ──────────────────────────────────────────────────────

    def _page_sources(self) -> List[Tuple[str, str, PageFeatures]]:
        """(page, profil, éléments) : variantes de visit_profiles si le check a
        tourné, sinon l'accueil vu par l'agent du scanner."""
        out: List[Tuple[str, str, PageFeatures]] = []
        shared = (self.context or {}).get("visit_profiles") or {}
        for page, variants in (shared.get("pages") or {}).items():
            for profile, features in variants.items():
                out.append((page, profile, features))
        tool = shared.get("tool")
        home = self.target.rstrip("/") + "/"
        if tool is not None:
            out.append((home, "tool", tool))
        if not out:
            try:
                resp = self.http_get("/")
                out.append((home, "tool", parse_page(resp.text or "", resp.url or home)))
            except requests.exceptions.RequestException:
                pass
        return out

    # ── Analyse ──────────────────────────────────────────────────────

    def _scan(self, text: str, page: str, profile: str, where: str) -> None:
        for hit in scan_script(text):
            self._record(hit, page, profile, where)

    def _data_script(self, src: str, page: str, profile: str) -> None:
        decoded = decode_data_script(src)
        self._record(Hit(
            "etherhiding", "data_script", "MEDIUM", "potential",
            "Script data: dans la page : forme du chargeur ClearFake 2026 (aucune URL "
            "externe à bloquer). Certaines extensions d'optimisation, comme "
            "LiteSpeed Cache, en produisent aussi",
            (decoded or src)[:160].replace("http", "hxxp"),
            "https://www.trendmicro.com/pt_br/research/26/e/"
            "smart-contracts-for-command-and-control.html"), page, profile, "script data:")
        if decoded:
            self._scan(decoded, page, profile, "contenu décodé d'un script data:")

    def _scan_site_scripts(self, srcs: List[str]) -> None:
        """Fichiers .js du site (cible et variante www.), bornés en nombre."""
        limit = int(self.config.get("client_injection_max_scripts", 30) or 0)
        th = host_of(self.target)
        bare = th[4:] if th.startswith("www.") else th
        done = 0
        for src in srcs:
            if done >= limit:
                break
            parts = urlsplit(src)
            if (parts.hostname or "").lower() not in (bare, f"www.{bare}"):
                continue
            if not parts.path.lower().endswith(_JS_PATH_SUFFIXES) or is_library_url(src):
                continue
            if not self.may_request(src):
                continue
            done += 1
            self._fetch_and_scan(src)

    def _scan_external_scripts(self, srcs: List[str],
                               by_profile: Dict[str, Set[str]]) -> None:
        """Scripts d'autres sites, hors bibliothèques et services connus ; ceux
        absents des visites directes d'abord (servis à certains profils)."""
        limit = int(self.config.get("client_injection_max_external", 10) or 0)
        th = host_of(self.target)
        baseline = by_profile.get("direct_a", set()) | by_profile.get("direct_b", set())
        candidates = [s for s in srcs
                      if host_of(s) and not same_site(host_of(s), th)
                      and not _is_well_known(host_of(s)) and not is_library_url(s)]
        candidates.sort(key=lambda s: (s in baseline, s))
        for src in candidates[:limit]:
            self._fetch_and_scan(src)

    def _fetch_and_scan(self, url: str) -> None:
        try:
            resp = self.http_get_url(url)
        except requests.exceptions.RequestException:
            return
        if resp.status_code != 200 or not resp.text:
            return
        content_type = (resp.headers.get("Content-Type") or "").lower()
        if "html" in content_type:
            return  # page d'erreur ou soft-404, pas un script
        self._scan(resp.text, url, "tool", "fichier JavaScript")

    def _record(self, hit: Hit, page: str, profile: str, where: str) -> None:
        key = (hit.rule, page)
        entry = self._hits.get(key)
        if entry is None:
            entry = {"hit": hit, "page": page, "profiles": [], "where": where}
            self._hits[key] = entry
        if profile not in entry["profiles"]:
            entry["profiles"].append(profile)

    def _emit(self) -> None:
        for (rule, page), entry in sorted(self._hits.items()):
            hit: Hit = entry["hit"]
            profiles = entry["profiles"]
            seen = (", ".join(PROFILE_LABELS.get(p, p) for p in profiles)
                    if profiles != ["toutes"] else "toutes les variantes")
            evidence = (f"Où : {entry['where']}. Profils : {seen}. "
                        f"Extrait : {hit.excerpt or '-'}")
            if hit.source:
                evidence += f" Source : {hit.source}"
            self._result.add_finding(
                message=hit.label, severity=hit.severity, evidence=evidence[:900],
                url=page, confidence=hit.confidence)
