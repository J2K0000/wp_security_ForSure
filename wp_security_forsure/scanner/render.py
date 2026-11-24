"""Passe de rendu facultative : la page exécutée dans Chromium, sous contrôle.

Le faux CAPTCHA ClickFix et les chargeurs EtherHiding se construisent dans le
navigateur : le HTML statique ne montre au mieux qu'un petit chargeur. Cette
passe ouvre la page dans Chromium (Playwright) comme un visiteur, observe ce
qu'elle fait et bloque ce qui sortirait de la lecture seule.

Règles de la passe (``RequestPolicy``) :
  - seules GET, HEAD et OPTIONS partent ; toute autre méthode est bloquée et
    notée, corps compris (un appel JSON-RPC eth_call se lit sans être envoyé) ;
  - les nœuds RPC et explorateurs de blockchain connus ne sont jamais
    contactés, même en GET ;
  - la page principale ne peut pas naviguer vers un autre site : la tentative
    est bloquée et notée (redirection JavaScript) ;
  - aucune adresse privée, de bouclage ou de lien local (garde SSRF du
    scanner) ; sur le site audité, les requêtes interdites à tout niveau
    (wp-cron.php, diagnostics Site Health, PHP deviné sous wp-content/) sont
    bloquées ;
  - les hôtes tiers que la page appelle (scripts, polices, iframes) sont
    chargés comme chez un visiteur, sauf avec ``render_third_party: false`` ;
  - WebSocket coupés, service workers bloqués, téléchargements refusés,
    fenêtres surgissantes fermées, bac à sable Chromium obligatoire : sans
    lui, la passe ne se lance pas ;
  - presse-papiers jamais écrit : les écritures sont capturées puis annulées.

Le JavaScript du site, y compris un éventuel code malveillant, s'exécute dans
le bac à sable de Chromium : lancer cette passe depuis une machine virtuelle
ou un conteneur jetable (docs/RESPONSIBLE_USE.md). Le script d'initialisation
masque aussi ``navigator.webdriver`` et l'agent utilisateur « HeadlessChrome » :
ClearFake renvoie une page propre aux navigateurs pilotés (Trend Micro, mai
2026). Ce contournement vise le code malveillant, pas les protections du site.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from . import access_tiers
from .checks.base import ALLOWED_METHODS, SSRFBlocked, check_destination
from .htmlscan import host_of, parse_page, same_site
from .injection_signatures import (command_matches, contract_family, defang,
                                   has_lure_terms, keystroke_matches,
                                   rpc_host_id, scan_script)

DEFAULT_MAX_REQUESTS = 400        # requêtes autorisées par rendu de page
MAX_EVENTS = 200                  # événements remontés par la page (borne)
MAX_EVENT_CHARS = 4000
MAX_POST_EXCERPT = 2000
OVERLAY_COVER = 0.8               # part de la fenêtre couverte par une superposition

# Arguments de lancement : moins de trafic propre au navigateur, pas d'UDP
# WebRTC hors proxy (UNC5142 lit l'adresse IP publique par STUN).
CHROMIUM_ARGS = (
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-default-apps",
    "--no-first-run",
    "--no-pings",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
)


@dataclass
class Blocked:
    method: str
    url: str
    reason: str
    resource_type: str = ""
    post_data: str = ""
    main_navigation: bool = False

    @property
    def host(self) -> str:
        return host_of(self.url)


@dataclass
class RequestPolicy:
    """Décide, requête par requête, ce que la passe de rendu laisse partir."""
    target: str
    third_party: bool = True
    max_requests: int = DEFAULT_MAX_REQUESTS
    destination_check: Callable[[str], None] = check_destination
    references: Optional[dict] = None
    allowed: int = 0
    blocked: List[Blocked] = field(default_factory=list)
    contacted_hosts: Set[str] = field(default_factory=set)
    _destinations: Dict[str, Optional[str]] = field(default_factory=dict)

    def _destination_error(self, url: str) -> Optional[str]:
        parts = urlsplit(url)
        key = f"{parts.scheme}://{parts.hostname}"
        if key not in self._destinations:
            try:
                self.destination_check(url)
                self._destinations[key] = None
            except SSRFBlocked as exc:
                self._destinations[key] = str(exc)[:200]
        return self._destinations[key]

    def decide(self, method: str, url: str, resource_type: str = "",
               main_navigation: bool = False, post_data: str = "") -> Tuple[bool, str]:
        """(autorisée, raison du blocage)."""
        method = (method or "GET").upper()
        parts = urlsplit(url or "")
        scheme = parts.scheme.lower()
        if scheme in ("data", "blob", "about", "chrome-extension"):
            return True, ""
        reason = ""
        host = (parts.hostname or "").lower()
        target_host = host_of(self.target)
        if scheme not in ("http", "https") or not host:
            reason = "schéma non http(s)"
        elif rpc_host_id(host):
            reason = "nœud RPC ou explorateur de blockchain"
        elif method not in ALLOWED_METHODS:
            reason = f"méthode {method} (lecture seule)"
        elif main_navigation and not same_site(host, target_host):
            reason = "navigation de la page vers un autre site"
        elif same_site(host, target_host):
            reason = access_tiers.forbidden_reason(url, self.target, self.references) or ""
        elif not self.third_party:
            reason = "hôte tiers (render_third_party: false)"
        if not reason:
            reason = self._destination_error(url) or ""
        if not reason and self.max_requests and self.allowed >= self.max_requests:
            reason = "budget de requêtes de la passe de rendu atteint"
        if reason:
            self.blocked.append(Blocked(method, url, reason, resource_type,
                                        (post_data or "")[:MAX_POST_EXCERPT],
                                        main_navigation))
            return False, reason
        self.allowed += 1
        self.contacted_hosts.add(host)
        return True, ""


# ── Script d'initialisation ──────────────────────────────────────────────
# Exécuté dans chaque cadre avant les scripts de la page. Remonte à Python, par
# la liaison __wpsfReport, les écritures dans le presse-papiers (jamais
# effectuées) et le code passé à eval ou Function.
INIT_SCRIPT = r"""
(() => {
  const report = (kind, data) => {
    try { window.__wpsfReport(kind, String(data == null ? '' : data).slice(0, %(max)d)); } catch (e) {}
  };
  try {
    Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => false, configurable: true });
  } catch (e) {}
  try {
    if (navigator.clipboard) {
      const capture = async (text) => { report('clipboard', text); };
      Object.defineProperty(navigator.clipboard, 'writeText', { value: capture, configurable: true });
      Object.defineProperty(navigator.clipboard, 'write', {
        value: async (items) => {
          try {
            for (const item of items || []) {
              if (item.types && item.types.includes('text/plain')) {
                const blob = await item.getType('text/plain');
                report('clipboard', await blob.text());
              }
            }
          } catch (e) { report('clipboard', '[ClipboardItem]'); }
        }, configurable: true });
    }
  } catch (e) {}
  try {
    const exec = Document.prototype.execCommand;
    Document.prototype.execCommand = function (cmd, ...rest) {
      const c = String(cmd || '').toLowerCase();
      if (c === 'copy' || c === 'cut') {
        let text = '';
        try { text = String(document.getSelection() || ''); } catch (e) {}
        try {
          const a = document.activeElement;
          if (!text && a && typeof a.value === 'string') {
            text = a.value.slice(a.selectionStart || 0, a.selectionEnd || a.value.length) || a.value;
          }
        } catch (e) {}
        report('clipboard', text);
        return true;
      }
      return exec.call(this, cmd, ...rest);
    };
  } catch (e) {}
  try {
    const setData = DataTransfer.prototype.setData;
    DataTransfer.prototype.setData = function (type, data) {
      if (String(type || '').toLowerCase().startsWith('text')) report('clipboard', data);
      return setData.call(this, type, data);
    };
  } catch (e) {}
  try {
    const realEval = window.eval;
    window.eval = function (code) {
      if (typeof code === 'string' && code.length > 120) report('eval', code);
      return realEval(code);
    };
  } catch (e) {}
  try {
    const RealFunction = window.Function;
    window.Function = new Proxy(RealFunction, {
      apply(t, self, args) { const s = args.join(','); if (s.length > 120) report('function', s); return Reflect.apply(t, self, args); },
      construct(t, args) { const s = args.join(','); if (s.length > 120) report('function', s); return Reflect.construct(t, args); }
    });
  } catch (e) {}
})();
""" % {"max": MAX_EVENT_CHARS}

# Superpositions : éléments fixes ou absolus, ou iframes, visibles, qui
# couvrent au moins la moitié de la fenêtre.
OVERLAY_SCRIPT = r"""
() => {
  const vw = innerWidth, vh = innerHeight, area = Math.max(1, vw * vh), out = [];
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) < 0.1) continue;
    if (!(cs.position === 'fixed' || cs.position === 'absolute' || el.tagName === 'IFRAME')) continue;
    const r = el.getBoundingClientRect();
    const w = Math.max(0, Math.min(r.right, vw) - Math.max(r.left, 0));
    const h = Math.max(0, Math.min(r.bottom, vh) - Math.max(r.top, 0));
    const cover = (w * h) / area;
    if (cover < 0.5) continue;
    out.push({tag: el.tagName, cover: cover, src: el.src || '',
              text: (el.innerText || '').slice(0, 3000)});
    if (out.length >= 20) break;
  }
  return out;
}
"""

FRAME_TEXT_SCRIPT = ("() => document.documentElement ? "
                     "document.documentElement.innerText.slice(0, 20000) : ''")
CLICK_LABEL_SCRIPT = ("e => ((e.closest('label') || e.parentElement || e).innerText"
                      " || '').slice(0, 200) + ' ' + (e.getAttribute('aria-label') || '')")
# Évaluations de la passe elle-même : jamais comptées comme code de la page.
_OWN_SCRIPTS = frozenset({OVERLAY_SCRIPT.strip(), FRAME_TEXT_SCRIPT.strip(),
                          CLICK_LABEL_SCRIPT.strip()})

# Élément à cliquer dans un faux CAPTCHA : case à cocher ou bouton dont le
# texte évoque une vérification.
CLICK_SELECTORS = ("input[type=checkbox]", "[role=checkbox]", "button", "label",
                   "[onclick]", "div[class*=check]", "span[class*=check]")
_CLICK_TEXT_RE = re.compile(r"robot|human|humain|verif|vérif|captcha|continuer|continue", re.I)


@dataclass
class RenderObservation:
    """Ce que la passe de rendu a vu pour une page et un profil."""
    page: str
    profile: str
    ok: bool = False
    error: str = ""
    final_url: str = ""
    blocked: List[Blocked] = field(default_factory=list)
    contacted_hosts: Set[str] = field(default_factory=set)
    events: List[Tuple[str, str, str]] = field(default_factory=list)  # (type, données, cadre)
    overlays: List[dict] = field(default_factory=list)
    frames: List[Tuple[str, str, str]] = field(default_factory=list)  # (url, texte, html)
    websockets: List[str] = field(default_factory=list)
    popups: List[str] = field(default_factory=list)
    clicked: str = ""


# ── Analyse (sans navigateur) ────────────────────────────────────────────

def _finding(message, severity, evidence, url, confidence="potential") -> dict:
    return {"message": message, "severity": severity, "evidence": evidence[:900],
            "url": url, "confidence": confidence}


def _lure_text(obs: RenderObservation) -> Tuple[List[str], bool, List[str]]:
    """(raccourcis vus, termes de faux CAPTCHA vus, commandes vues) dans le
    texte des superpositions et des cadres."""
    texts = [o.get("text", "") for o in obs.overlays] + [t for _, t, _ in obs.frames]
    joined = "\n".join(texts)
    return keystroke_matches(joined), has_lure_terms(joined), command_matches(joined)


def analyze(observations: List[RenderObservation], target: str,
            labels: Optional[Dict[str, str]] = None) -> List[dict]:
    """Constats de la passe de rendu, à partir des observations."""
    labels = labels or {}
    findings: List[dict] = []
    seen: Set[Tuple[str, str]] = set()

    def once(key: Tuple[str, str], finding: dict) -> None:
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for obs in observations:
        if not obs.ok:
            continue
        who = labels.get(obs.profile, obs.profile)
        keys, lure, commands_in_text = _lure_text(obs)
        # 1. Presse-papiers
        for kind, data, frame in obs.events:
            if kind != "clipboard" or not data.strip():
                continue
            cmds = command_matches(data)
            flat = defang(_flat(data))
            after = f"Après un clic sur {obs.clicked}. " if obs.clicked else ""
            if cmds:
                once(("clipboard_command", obs.page), _finding(
                    "ClickFix : la page place une commande système dans le "
                    "presse-papiers du visiteur",
                    "CRITICAL",
                    f"Profil : {who}. Cadre : {defang(frame)[:120]}. "
                    f"Motifs : {', '.join(cmds)}. Contenu (neutralisé) : "
                    f"{flat[:220]}. {after}"
                    "La copie a été interceptée, rien n'a été écrit.",
                    obs.page, "confirmed"))
            elif keys or lure:
                once(("clipboard_lure", obs.page), _finding(
                    "ClickFix possible : la page écrit dans le presse-papiers sous "
                    "un faux CAPTCHA",
                    "HIGH",
                    f"Profil : {who}. Contenu (neutralisé) : {flat[:200]}",
                    obs.page))
        # 2. Requêtes bloquées
        for b in obs.blocked:
            body = b.post_data or ""
            family = contract_family(body) or contract_family(b.url)
            is_rpc = bool(re.search(r'"method"\s*:\s*"eth_call"', body)) or bool(rpc_host_id(b.host))
            if family:
                once(("rpc_contract", obs.page), _finding(
                    "EtherHiding : la page lit un contrat connu comme infrastructure "
                    f"malveillante ({family})",
                    "CRITICAL",
                    f"Profil : {who}. Requête bloquée : {b.method} {defang(b.url)[:160]}. "
                    f"Corps : {defang(body)[:240]}",
                    obs.page, "confirmed"))
            elif is_rpc:
                once(("rpc_call", obs.page), _finding(
                    "EtherHiding possible : la page tente de lire un contrat sur une "
                    "blockchain (requête bloquée ; normal seulement pour un site qui "
                    "a une fonction Web3)",
                    "HIGH",
                    f"Profil : {who}. Requête bloquée : {b.method} {defang(b.url)[:160]} "
                    f"({b.reason}). Corps : {defang(body)[:200]}",
                    obs.page, "confirmed"))
            elif b.main_navigation:
                once(("offsite_navigation", obs.page + b.host), _finding(
                    f"Redirection JavaScript vers un autre site ({b.host}), bloquée",
                    "HIGH",
                    f"Profil : {who}. Destination : {defang(b.url)[:200]}. Une "
                    "redirection en JavaScript qui franchit le domaine est le signe "
                    "le plus discriminant du cloaking selon Cloak of Visibility "
                    "(IEEE S&P 2016).",
                    obs.page))
        # 3. Superposition plein écran de type faux CAPTCHA
        big = [o for o in obs.overlays if o.get("cover", 0) >= OVERLAY_COVER]
        if big and (keys or lure):
            severity = "CRITICAL" if keys and commands_in_text else "HIGH"
            once(("overlay", obs.page), _finding(
                "Superposition plein écran de type faux CAPTCHA",
                severity,
                f"Profil : {who}. Élément : {big[0].get('tag')} couvrant "
                f"{big[0].get('cover', 0):.0%} de la fenêtre"
                + (f", source {defang(big[0].get('src', ''))[:120]}" if big[0].get("src") else "")
                + (f". Raccourcis : {', '.join(keys)}" if keys else "")
                + (". Termes de faux CAPTCHA présents" if lure else ""),
                obs.page))
        # 4. Scripts du DOM rendu et code passé à eval ou Function
        for frame_url, _, html in obs.frames:
            features = parse_page(html, frame_url or obs.page)
            for script in features.inline_scripts:
                for hit in scan_script(script):
                    once((hit.rule, obs.page), _finding(
                        hit.label + " (page rendue)", hit.severity,
                        f"Profil : {who}. Cadre : {defang(frame_url)[:120]}. "
                        f"Extrait : {hit.excerpt}",
                        obs.page, hit.confidence))
        for kind, data, frame in obs.events:
            if kind in ("eval", "function"):
                for hit in scan_script(data):
                    once((hit.rule, obs.page), _finding(
                        hit.label + f" (code exécuté par {kind})", hit.severity,
                        f"Profil : {who}. Cadre : {defang(frame)[:120]}. "
                        f"Extrait : {hit.excerpt}",
                        obs.page, "confirmed"))
        # 5. Fenêtres surgissantes vers un autre site
        th = host_of(target)
        for popup in obs.popups:
            h = host_of(popup)
            if h and not same_site(h, th):
                once(("popup", obs.page + h), _finding(
                    f"Fenêtre surgissante vers un autre site ({h}), fermée",
                    "MEDIUM", f"Profil : {who}. URL : {defang(popup)[:200]}",
                    obs.page))

    # 6. Hôtes tiers contactés sans le cookie de connexion seulement
    by_page: Dict[str, Dict[str, RenderObservation]] = {}
    for obs in observations:
        if obs.ok:
            by_page.setdefault(obs.page, {})[obs.profile] = obs
    th = host_of(target)
    for page, profiles in by_page.items():
        victim, logged = profiles.get("victim_google"), profiles.get("logged_in")
        if victim is None or logged is None:
            continue
        only = sorted(h for h in victim.contacted_hosts - logged.contacted_hosts
                      if not same_site(h, th))
        if only:
            once(("logged_in_gate", page), _finding(
                "Injection conditionnelle possible : hôtes tiers contactés seulement "
                "sans cookie de connexion WordPress",
                "HIGH",
                "Hôtes : " + ", ".join(only[:15]) + ". Comportement des injections qui "
                "épargnent les administrateurs (campagne ClickFix décrite par Rapid7 "
                "en 2026). À comparer avec la même page vue connecté.",
                page))
    return findings


def summary(observations: List[RenderObservation], target: str,
            labels: Optional[Dict[str, str]] = None) -> dict:
    """Constat INFO : ce que la passe a fait, contacté et bloqué."""
    labels = labels or {}
    th = host_of(target)
    done = [o for o in observations if o.ok]
    failed = [o for o in observations if not o.ok]
    hosts = sorted({h for o in done for h in o.contacted_hosts if not same_site(h, th)})
    reasons: Dict[str, int] = {}
    for o in done:
        for b in o.blocked:
            reasons[b.reason] = reasons.get(b.reason, 0) + 1
        if o.websockets:
            reasons["WebSocket coupé"] = reasons.get("WebSocket coupé", 0) + len(o.websockets)
    evidence = (f"{len(done)} rendu(s) : "
                + ", ".join(f"{labels.get(o.profile, o.profile)} sur {o.page}" for o in done)
                + f". Hôtes tiers chargés ({len(hosts)}) : " + (", ".join(hosts[:30]) or "aucun")
                + ". Requêtes bloquées : "
                + (", ".join(f"{n} × {r}" for r, n in sorted(reasons.items())) or "aucune"))
    clicked = [o for o in done if o.clicked]
    if clicked:
        evidence += ". Clic simulé sur un faux CAPTCHA : " + ", ".join(
            f"{labels.get(o.profile, o.profile)} ({o.clicked})" for o in clicked)
    if failed:
        evidence += ". Échecs : " + "; ".join(
            f"{labels.get(o.profile, o.profile)} sur {o.page} : {o.error[:80]}" for o in failed)
    return _finding("Passe de rendu réalisée (Chromium, bac à sable actif)", "INFO",
                    evidence, target, "confirmed")


# ── Exécution (Playwright) ───────────────────────────────────────────────

@dataclass(frozen=True)
class RenderProfile:
    id: str
    user_agent: str
    mobile: bool = False
    logged_in_cookie: bool = False
    referer: str = "https://www.google.com/"


class RenderUnavailable(RuntimeError):
    """Playwright ou Chromium absent, ou bac à sable indisponible."""


def _post_data(request) -> str:
    try:
        return request.post_data or ""
    except Exception:
        try:
            raw = request.post_data_buffer
            return raw.decode("utf-8", "replace") if raw else ""
        except Exception:
            return ""


class Renderer:
    """Ouvre des pages dans Chromium selon la politique de la passe."""

    def __init__(self, target: str, config: dict,
                 destination_check: Callable[[str], None] = check_destination,
                 references: Optional[dict] = None):
        self.target = target
        self.config = config
        self.destination_check = destination_check
        self.references = references
        self.settle_ms = int(config.get("render_settle_ms", 5000) or 0)
        self.timeout_ms = int(config.get("render_timeout_ms", 25000) or 25000)

    def __enter__(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RenderUnavailable(
                "Playwright n'est pas installé : pip install "
                "\"wp-security-forsure[render]\" puis python -m playwright install "
                "chromium") from exc
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(
                headless=True, chromium_sandbox=True, args=list(CHROMIUM_ARGS))
        except Exception as exc:
            self._pw.stop()
            raise RenderUnavailable(
                "Chromium n'a pas pu démarrer avec son bac à sable : passe de rendu "
                f"non lancée ({str(exc).splitlines()[0][:200]})") from exc
        return self

    def __exit__(self, *exc):
        try:
            self._browser.close()
        finally:
            self._pw.stop()
        return False

    def render(self, url: str, profile: RenderProfile) -> RenderObservation:
        obs = RenderObservation(page=url, profile=profile.id)
        policy = RequestPolicy(
            self.target,
            third_party=self.config.get("render_third_party", True) is not False,
            max_requests=int(self.config.get("render_max_requests", DEFAULT_MAX_REQUESTS) or 0),
            destination_check=self.destination_check,
            references=self.references)
        options = dict(
            user_agent=profile.user_agent, locale="fr-FR", timezone_id="Europe/Paris",
            accept_downloads=False, service_workers="block", ignore_https_errors=True,
            java_script_enabled=True)
        if profile.mobile:
            options.update(viewport={"width": 412, "height": 915}, device_scale_factor=2.625,
                           is_mobile=True, has_touch=True)
        else:
            options.update(viewport={"width": 1366, "height": 768})
        context = self._browser.new_context(**options)
        try:
            self._instrument(context, policy, obs, profile)
            page = context.new_page()
            page.set_default_timeout(self.timeout_ms)
            page.on("dialog", lambda d: _safe(d.dismiss))
            context.on("page", lambda p: self._popup(p, page, obs))
            try:
                page.goto(url, referer=profile.referer or None, wait_until="load",
                          timeout=self.timeout_ms)
            except Exception as exc:  # délai dépassé : on garde ce qui a chargé
                obs.error = f"chargement incomplet : {str(exc).splitlines()[0][:120]}"
            page.wait_for_timeout(self.settle_ms)
            self._collect(page, obs)
            target = self._click_target(page, obs)
            if target:
                page.wait_for_timeout(2500)
                self._collect(page, obs)
            obs.final_url = page.url
            obs.ok = True
            obs.error = obs.error if obs.error else ""
        except Exception as exc:
            obs.ok = False
            obs.error = f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
        finally:
            obs.blocked = list(policy.blocked)
            obs.contacted_hosts = set(policy.contacted_hosts)
            _safe(context.close)
        return obs

    # ── Instrumentation ──────────────────────────────────────────────

    def _instrument(self, context, policy: RequestPolicy, obs: RenderObservation,
                    profile: RenderProfile) -> None:
        def report(source, kind, data):
            if str(data).strip() in _OWN_SCRIPTS:
                return  # évaluation de la passe elle-même, pas de la page
            if len(obs.events) < MAX_EVENTS:
                frame = ""
                try:
                    frame = source["frame"].url
                except Exception:
                    pass
                obs.events.append((str(kind)[:20], str(data)[:MAX_EVENT_CHARS], frame))

        context.expose_binding("__wpsfReport", report)
        context.add_init_script(INIT_SCRIPT)

        def route(route_obj):
            request = route_obj.request
            try:
                main_nav = (request.is_navigation_request()
                            and request.frame.parent_frame is None)
            except Exception:
                main_nav = False
            allowed, _ = policy.decide(request.method, request.url, request.resource_type,
                                       main_nav, _post_data(request))
            if allowed:
                _safe(route_obj.continue_)
            elif main_nav:
                # Une navigation abandonnée remplacerait la page par une page
                # d'erreur : une réponse 204 l'annule et garde le document.
                _safe(lambda: route_obj.fulfill(status=204, body=""))
            else:
                _safe(lambda: route_obj.abort("blockedbyclient"))

        context.route("**/*", route)

        def websocket(ws):
            obs.websockets.append(ws.url[:300])
            _safe(ws.close)

        try:
            context.route_web_socket(re.compile(r".*"), websocket)
        except Exception:
            pass
        if profile.logged_in_cookie:
            from .checks.visit_profiles import FAKE_LOGIN_VALUE, logged_in_cookie_name
            parts = urlsplit(self.target)
            context.add_cookies([{
                "name": logged_in_cookie_name(self.target), "value": FAKE_LOGIN_VALUE,
                "domain": parts.hostname, "path": "/"}])

    def _popup(self, popup, main_page, obs: RenderObservation) -> None:
        if popup is main_page:
            return
        try:
            obs.popups.append(popup.url[:300])
        except Exception:
            pass
        _safe(popup.close)

    def _collect(self, page, obs: RenderObservation) -> None:
        try:
            obs.overlays = page.evaluate(OVERLAY_SCRIPT) or []
        except Exception:
            obs.overlays = []
        frames = []
        for frame in page.frames[:20]:
            try:
                text = frame.evaluate(FRAME_TEXT_SCRIPT)
                html = frame.content()[:2_000_000]
            except Exception:
                continue
            frames.append((frame.url, text or "", html or ""))
        obs.frames = frames

    def _click_target(self, page, obs: RenderObservation) -> str:
        """Clique, une fois, l'élément de vérification d'un faux CAPTCHA, pour
        provoquer la copie dans le presse-papiers. Seulement si la page montre
        un leurre (raccourci clavier ou terme de faux CAPTCHA)."""
        keys, lure, _ = _lure_text(obs)
        if not (keys or lure):
            return ""
        for frame in page.frames[:20]:
            for selector in CLICK_SELECTORS:
                try:
                    handles = frame.query_selector_all(selector)[:30]
                except Exception:
                    continue
                for handle in handles:
                    try:
                        text = handle.evaluate(CLICK_LABEL_SCRIPT)
                        if selector not in ("input[type=checkbox]", "[role=checkbox]") \
                                and not _CLICK_TEXT_RE.search(text):
                            continue
                        if not handle.is_visible():
                            continue
                        handle.click(timeout=3000)
                        obs.clicked = f"{selector} « {_flat(text)[:60]} »"
                        return obs.clicked
                    except Exception:
                        continue
        return ""


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _safe(fn) -> None:
    try:
        fn()
    except Exception:
        pass
