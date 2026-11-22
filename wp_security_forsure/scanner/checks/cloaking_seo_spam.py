"""Check cloaking & SEO spam, détection de compromission par référencement noir.

Vecteurs couverts (parmi les plus fréquents sur WordPress compromis) :

  1) Cloaking : la home est récupérée DEUX fois, une fois en visiteur normal,
     une fois en se faisant passer pour Googlebot. Si la version Googlebot
     diffère fortement (taille très différente) OU contient des marqueurs de
     spam absents du rendu visiteur → cloaking.
  2) SEO spam / défacement : les deux corps sont scannés pour des marqueurs
     curés, caractères japonais (Japanese Keyword Hack) et termes
     pharma / contrefaçon / paris (viagra, cialis, casino, replica, ...).
  3) Sitemap / robots (léger) : si le sitemap référence un grand nombre d'URLs
     manifestement hors-sujet / japonaises → indice de spam injecté.

Le check gère le soft-404 (site qui renvoie la home pour toute URL) et n'écrit
jamais : toutes les requêtes réseau sont encadrées par un try/except.
"""

import re
from typing import List, Optional, Tuple

from .base import BaseCheck, CheckResult

# User-Agent Googlebot officiel, sert à provoquer un éventuel cloaking.
GOOGLEBOT_UA = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)


class CloakingSeoSpamCheck(BaseCheck):
    """Détecte le cloaking et le SEO spam (Japanese Keyword Hack, pharma/casino)."""

    name = "cloaking_seo_spam"
    title = "Cloaking & SEO Spam Detection"
    description = (
        "Compare le rendu de la page d'accueil vu par un visiteur et par "
        "Googlebot, et recherche des marqueurs de spam (caractères japonais, "
        "termes pharma/contrefaçon/paris) signalant un Japanese Keyword Hack "
        "ou un défacement furtif."
    )
    severity = "HIGH"
    access_tier = 1  # accueil et sitemap.xml
    depends_on: List[str] = []

    # Marqueurs pharma / contrefaçon / paris. Volontairement en minuscule ASCII :
    # le japonais est traité séparément par une plage Unicode.
    SPAM_KEYWORDS: List[str] = [
        "viagra", "cialis", "levitra", "tadalafil", "sildenafil",
        "vardenafil", "kamagra", "xanax", "tramadol", "phentermine",
        "oxycontin", "percocet", "prescription drugs",
        "casino", "poker", "roulette", "blackjack", "baccarat",
        "slot machine", "betting", "gambling", "sportsbet", "sbobet",
        "replica watch", "replica rolex", "replica handbag",
        "rolex replica", "oakley", "ugg boots", "louis vuitton",
        "canada goose", "moncler", "supreme copy",
    ]

    # Caractères japonais : hiragana, katakana et idéogrammes CJK.
    _JP_RE = re.compile(r"[぀-ゟ゠-ヿ一-鿿]")

    # Seuils heuristiques
    _JP_MIN = 8          # nb de caractères japonais jugé « significatif »
    _SIZE_DIFF = 0.40    # écart de taille visiteur/Googlebot signalant un cloaking
    _SITEMAP_MIN = 5     # nb d'URLs suspectes dans le sitemap avant de signaler

    # ── Public API ────────────────────────────────────────────────────

    def run(self) -> CheckResult:
        normal_resp, normal_body = self._fetch_normal()
        googlebot_body = self._fetch_googlebot()

        soft404 = False
        if normal_resp is not None:
            try:
                soft404 = self._is_soft404(normal_resp)
            except Exception:
                soft404 = False

        self._analyze_bodies(normal_body, googlebot_body, soft404)
        self._check_sitemap_robots()
        return self._result

    # ── Récupération des corps ────────────────────────────────────────

    def _fetch_normal(self) -> Tuple[Optional[object], str]:
        """Home vue par un visiteur normal (via le cache borné de la session)."""
        try:
            resp = self.http_get("/")
            return resp, (resp.text or "")
        except Exception:
            return None, ""

    def _fetch_googlebot(self) -> str:
        """Home vue par Googlebot, requête fraîche, hors cache, UA usurpé."""
        try:
            # headers= : jamais servie par le cache du GET visiteur.
            resp = self.http_get("/", headers={"User-Agent": GOOGLEBOT_UA})
            return resp.text or ""
        except Exception:
            return ""

    # ── Analyse ───────────────────────────────────────────────────────

    def _spam_markers(self, body: str) -> Tuple[List[str], int]:
        """Retourne (mots-clés de spam trouvés, nb de caractères japonais)."""
        if not body:
            return [], 0
        low = body.lower()
        # Mots ENTIERS uniquement (\b) : « cialis » ne doit PAS matcher
        # « spécialisés », « commercialisation », etc. (faux positif classique).
        kw = [k for k in self.SPAM_KEYWORDS
              if re.search(r"\b" + re.escape(k) + r"\b", low)]
        jp = len(self._JP_RE.findall(body))
        return kw, jp

    def _analyze_bodies(self, normal_body: str, gb_body: str,
                        soft404: bool = False) -> None:
        """Compare les deux rendus et signale cloaking + spam."""
        n_kw, n_jp = self._spam_markers(normal_body)
        g_kw, g_jp = self._spam_markers(gb_body)

        # 1. Cloaking, marqueurs présents pour Googlebot mais pas le visiteur.
        cloaked_kw = sorted(set(g_kw) - set(n_kw))
        cloaked_jp = g_jp >= self._JP_MIN and n_jp < self._JP_MIN

        if cloaked_kw or cloaked_jp:
            reasons = []
            if cloaked_kw:
                reasons.append("mots-clés spam Googlebot-only: "
                               + ", ".join(cloaked_kw[:8]))
            if cloaked_jp:
                reasons.append(f"{g_jp} caractères japonais côté Googlebot "
                               f"(vs {n_jp} côté visiteur)")
            self._result.add_finding(
                message="Cloaking détecté, contenu de spam servi à Googlebot "
                        "mais masqué au visiteur",
                severity="HIGH",
                evidence=self._clip(" ; ".join(reasons)),
                url=self.target,
                confidence="confirmed",
            )
        elif not soft404:
            # Pas de spam cloaké, mais deux rendus très différents en taille.
            n_len, g_len = len(normal_body or ""), len(gb_body or "")
            if n_len and g_len:
                diff = abs(g_len - n_len) / max(n_len, 1)
                if diff > self._SIZE_DIFF:
                    self._result.add_finding(
                        message="Cloaking possible, la version Googlebot diffère "
                                "fortement du rendu visiteur",
                        severity="HIGH",
                        evidence=self._clip(
                            f"taille visiteur={n_len}, taille Googlebot={g_len} "
                            f"(écart {diff:.0%})"),
                        url=self.target,
                        confidence="potential",
                    )

        # 2. SEO spam présent dans l'un ou l'autre rendu.
        self._flag_spam(normal_body, "rendu visiteur", n_kw, n_jp)
        # Évite un doublon si les deux corps sont identiques.
        if gb_body and gb_body != normal_body:
            self._flag_spam(gb_body, "rendu Googlebot", g_kw, g_jp)

    def _flag_spam(self, body: str, where: str, kw: List[str],
                   jp_count: int) -> None:
        """Émet un finding « contenu de spam injecté » si marqueurs significatifs."""
        if not body:
            return
        reasons: List[str] = []
        severity = "HIGH"
        confidence = "potential"

        if jp_count >= self._JP_MIN:
            reasons.append(f"{jp_count} caractères japonais (hiragana/katakana/CJK)")
            # Le Japanese Keyword Hack est un marqueur très distinctif.
            severity = "CRITICAL"
            confidence = "confirmed"
        if kw:
            reasons.append("mots-clés pharma/contrefaçon/paris: "
                           + ", ".join(sorted(set(kw))[:10]))

        if not reasons:
            return

        self._result.add_finding(
            message=f"Contenu de spam injecté ({where}), possible Japanese SEO "
                    "spam / défacement",
            severity=severity,
            evidence=self._clip("; ".join(reasons) + " | extrait: "
                                + self._excerpt(body)),
            url=self.target,
            confidence=confidence,
        )

    # ── Sitemap / robots (léger) ─────────────────────────────────────

    def _check_sitemap_robots(self) -> None:
        """Signale un sitemap bourré d'URLs hors-sujet / japonaises."""
        try:
            resp = self.http_get("/sitemap.xml")
        except Exception:
            return
        if resp.status_code != 200 or not resp.text:
            return
        try:
            if self._is_soft404(resp):
                return
        except Exception:
            pass

        locs = re.findall(r"<loc>\s*([^<]+?)\s*</loc>", resp.text, re.IGNORECASE)
        suspicious = [
            u for u in locs
            if self._JP_RE.search(u)
            or any(re.search(r"\b" + re.escape(k) + r"\b", u.lower())
                   for k in self.SPAM_KEYWORDS)
        ]
        if len(suspicious) >= self._SITEMAP_MIN:
            self._result.add_finding(
                message="Sitemap suspect, nombreuses URLs hors-sujet / japonaises "
                        "(possible SEO spam indexé)",
                severity="INFO",
                evidence=self._clip(
                    f"{len(suspicious)} URL(s) suspecte(s) sur {len(locs)}, "
                    "ex.: " + ", ".join(suspicious[:5])),
                url=f"{self.target.rstrip('/')}/sitemap.xml",
                confidence="potential",
            )

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _excerpt(body: str, n: int = 200) -> str:
        text = re.sub(r"\s+", " ", body or "").strip()
        return text[:n]

    @staticmethod
    def _clip(text: str, n: int = 200) -> str:
        return (text or "")[:n]
