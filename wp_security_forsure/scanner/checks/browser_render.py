"""Check browser_render : passe de rendu facultative dans Chromium (--render).

Ouvre l'accueil, puis la page de paiement WooCommerce ou la première page
interne comparée par visit_profiles, sous trois profils : clic depuis Google
(bureau), mobile, et clic depuis Google avec un faux cookie de connexion
WordPress (témoin). Les règles de la passe sont dans scanner/render.py : seules
les lectures partent, les appels de blockchain, les navigations vers un autre
site, les WebSocket et les téléchargements sont bloqués et notés, le
presse-papiers est intercepté.

Non lancé sans --render (statut « skipped »). Nécessite l'extra « render » :
pip install "wp-security-forsure[render]" puis python -m playwright install
chromium.
"""

from __future__ import annotations

from typing import List

from ..render import RenderProfile, Renderer, analyze, summary
from .base import BaseCheck, CheckResult
from .visit_profiles import CHROME_ANDROID_UA, CHROME_DESKTOP_UA, PROFILE_LABELS

RENDER_PROFILES = (
    RenderProfile("victim_google", CHROME_DESKTOP_UA),
    RenderProfile("mobile_google", CHROME_ANDROID_UA, mobile=True),
    RenderProfile("logged_in", CHROME_DESKTOP_UA, logged_in_cookie=True),
)
SKIP_REASON = ("Non réalisé : nécessite --render (passe de rendu Chromium, "
               "facultative)")


class BrowserRenderCheck(BaseCheck):
    """Exécute les pages dans Chromium et observe ce qu'elles font."""

    name = "browser_render"
    title = "Rendu JavaScript (Chromium isolé)"
    description = (
        "Passe facultative (--render) : la page s'exécute dans Chromium, bac à "
        "sable actif, en lecture seule. Capture les écritures dans le "
        "presse-papiers, les appels de blockchain, les redirections JavaScript "
        "et les superpositions de faux CAPTCHA.")
    severity = "CRITICAL"
    access_tier = 0
    priority = 1
    opt_in = "render"
    skip_reason = SKIP_REASON
    depends_on = ["visit_profiles"]

    def pages(self) -> List[str]:
        home = self.target.rstrip("/") + "/"
        limit = int(self.config.get("render_max_pages", 2) or 1)
        shared = (self.context or {}).get("visit_profiles") or {}
        others = [u for u in (shared.get("pages") or {}) if u != home]
        checkout = [u for u in others if "checkout" in u or "commande" in u]
        ordered = [home] + checkout + [u for u in others if u not in checkout]
        return ordered[:max(1, limit)]

    def run(self) -> CheckResult:
        if not self.config.get(self.opt_in):
            # Garde-fou en plus du moteur (qui ne lance pas ce check sans
            # --render) : un appel direct ne démarre jamais Chromium.
            self._result.add_finding(
                message=SKIP_REASON, severity="INFO",
                evidence="Chromium n'a pas été lancé.", url=self.target,
                confidence="confirmed")
            return self._result
        observations = []
        with Renderer(self.target, self.config,
                      references=self.references()) as renderer:
            for url in self.pages():
                for profile in RENDER_PROFILES:
                    observations.append(renderer.render(url, profile))
        for f in analyze(observations, self.target, PROFILE_LABELS):
            self._result.add_finding(**f)
        self._result.add_finding(**summary(observations, self.target, PROFILE_LABELS))
        return self._result
