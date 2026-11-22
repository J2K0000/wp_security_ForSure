"""Exposition d'endpoints RÉCEPTEURS de webhooks, détection strictement PASSIVE.

CADRAGE (à respecter absolument)
--------------------------------
La validation de signature/HMAC d'un webhook N'EST PAS vérifiable à distance sans
ÉMETTRE un payload à effet de bord (créer une commande, notifier, muter des
données), ce que cet audit non destructif s'INTERDIT. Ce check NE DÉCLENCHE
JAMAIS de webhook : aucun POST/PUT/DELETE, aucun payload d'action n'est émis vers
un endpoint récepteur.

Il se limite à DÉTECTER PASSIVEMENT la PRÉSENCE d'endpoints récepteurs de webhooks
exposés, et signale EXPLICITEMENT que la validation de signature doit être auditée
CÔTÉ CODE (surface à examiner, non prouvable à distance).

Détection passive, en lecture seule uniquement :
  (a) Index REST (GET wp-json/), repère les CLÉS de routes dont le motif est
      typique d'un récepteur de webhook (WEBHOOK_ROUTE_PATTERNS). Parsing JSON
      défensif, soft-404 géré, faux positifs limités (motif net dans la clé).
  (b) Endpoint hérité WooCommerce `?wc-api=` (callbacks de passerelles de
      paiement), probe GET BÉNIN de "/?wc-api=" SANS nom d'action ni payload ;
      si la réponse n'est pas un simple 404 « ressource absente » (ni un
      soft-404), on note la présence de la surface wc-api.

Robustesse : try/except partout, réponses non-JSON tolérées, jamais de crash.
"""

from typing import List, Optional

from .base import BaseCheck, CheckResult

# ── Motifs de CLÉ de route typiques d'un endpoint RÉCEPTEUR de webhook ──────
# Insensible à la casse, recherché dans la CLÉ de route de l'index REST.
# Attention aux faux positifs : on exige un motif NET (ex. "/hook"/"webhook"/
# "-hook" plutôt que "hook" seul, qui apparaîtrait dans des mots non liés).
WEBHOOK_ROUTE_PATTERNS = (
    "webhook",
    "/hook",
    "-hook",
    "callback",
    "ipn",
    "notify",
    "gateway",
    "zapier",
    "automation",
    "make.com",
    "n8n",
    # Namespaces de paiement susceptibles d'exposer des callbacks/IPN.
    "stripe",
    "paypal",
    "mollie",
    "razorpay",
)

# Rappel de cadrage inséré dans chaque évidence : la validation de signature ne
# peut PAS être prouvée à distance sans payload à effet de bord.
_SIGNATURE_CAVEAT = (
    "L'absence de validation de signature ne peut PAS être prouvée à distance "
    "sans envoyer un payload à effet de bord, ce que cet audit s'interdit. Ce "
    "finding signale la SURFACE à auditer côté code (validation de signature/HMAC "
    "du récepteur), pas une vulnérabilité confirmée."
)


class WebhookExposureCheck(BaseCheck):
    """Repère passivement les endpoints récepteurs de webhooks exposés."""

    name = "webhook_exposure"
    title = "Exposition d'endpoints récepteurs de webhooks"
    description = (
        "Détecte passivement (lecture seule) la présence d'endpoints récepteurs "
        "de webhooks exposés, routes REST au motif récepteur et surface héritée "
        "WooCommerce ?wc-api=, et rappelle que la validation de signature/HMAC "
        "doit être auditée côté code (non vérifiable à distance)."
    )
    severity = "MEDIUM"
    access_tier = 1  # mixte : sonde ?wc-api= sous --authorized
    depends_on: List[str] = ["fingerprint"]

    def run(self) -> CheckResult:
        plugins = ((self.context or {}).get("inventory") or {}).get("plugins") or []

        # ── (a) Routes REST au motif « récepteur de webhook » ──────────────
        try:
            routes = [r for r in self._match_webhook_routes() if r]
        except Exception:
            # Aucun crash : l'échec du parsing REST ne doit pas casser le check.
            routes = []
        if routes:
            # Un SEUL finding agrégé pour toutes les routes (anti-bruit) : sur un
            # plugin comme LiteSpeed, 5 routes notify_* ne doivent pas produire 5
            # findings distincts.
            self._flag_routes(routes, plugins)

        # ── (b) Surface héritée WooCommerce ?wc-api= (lecture seule) ───────
        # Paramètre deviné, non lié par la page : niveau 2 (--authorized).
        wc_api_url = None
        if self.config.get("authorized"):
            try:
                wc_api_url = self._probe_wc_api()
            except Exception:
                wc_api_url = None
        else:
            self.note_unlinked_skipped("surface héritée WooCommerce ?wc-api=")
        if wc_api_url:
            self._flag_wc_api(wc_api_url, plugins)

        # ── Rien trouvé : INFO discret ─────────────────────────────────────
        if not routes and not wc_api_url:
            self._result.add_finding(
                message="Aucun endpoint récepteur de webhook évident détecté",
                severity="INFO",
                evidence=(
                    "Aucune route REST au motif récepteur ni surface ?wc-api= "
                    "détectée passivement. Un récepteur de webhook peut néanmoins "
                    "exister sans motif reconnaissable dans sa route : "
                    + _SIGNATURE_CAVEAT
                ),
                url=f"{self.target.rstrip('/')}/wp-json/",
                confidence="potential",
            )
        return self._result

    # ── Findings ────────────────────────────────────────────────────────────

    def _flag_routes(self, routes: list, plugins: list) -> None:
        """Un SEUL finding MEDIUM listant toutes les routes réceptrices (anti-bruit)."""
        routes = sorted(set(routes))
        hints: List[str] = []
        for r in routes:
            h = self._plugin_hint(r, plugins)
            if h and h not in hints:
                hints.append(h)
        listing = "\n".join(
            f"  - {self.target.rstrip('/')}/wp-json{r}" for r in routes
        )
        self._result.add_finding(
            message=(
                f"{len(routes)} route(s) REST réceptrice(s) de webhook exposée(s) "
                "- vérifier la validation de signature/HMAC côté serveur "
                "(NON vérifiable à distance)"
            ),
            severity="MEDIUM",
            evidence=(
                "Routes REST au motif récepteur de webhook :\n"
                + listing + "\n"
                + ("\n".join(hints) + "\n" if hints else "")
                + "Détecté passivement via l'index REST (GET wp-json/, lecture "
                "seule). Aucun payload n'a été émis vers ces endpoints.\n"
                + _SIGNATURE_CAVEAT
            ),
            url=f"{self.target.rstrip('/')}/wp-json/",
            confidence="potential",
        )

    def _flag_wc_api(self, wc_api_url: str, plugins: list) -> None:
        plugin_note = self._plugin_hint("woocommerce", plugins)
        self._result.add_finding(
            message=(
                "Endpoint récepteur de webhook exposé : ?wc-api= (callbacks de "
                "passerelles de paiement WooCommerce), vérifier la validation de "
                "signature/HMAC côté serveur (NON vérifiable à distance)"
            ),
            severity="MEDIUM",
            evidence=(
                f"Surface héritée WooCommerce joignable : {wc_api_url}\n"
                + (plugin_note + "\n" if plugin_note else "")
                + "Probe GET bénin SANS nom d'action réel ni payload : la réponse "
                "n'est ni un 404 « ressource absente » ni un soft-404, la surface "
                "wc-api est donc présente. Ces callbacks reçoivent les IPN des "
                "passerelles de paiement (Stripe, PayPal, etc.).\n"
                + _SIGNATURE_CAVEAT
            ),
            url=wc_api_url,
            confidence="potential",
        )

    @staticmethod
    def _plugin_hint(needle: str, plugins: list) -> Optional[str]:
        """Nomme le plugin de l'inventaire dont le slug apparaît dans la route."""
        low = (needle or "").lower()
        for p in plugins or []:
            if not isinstance(p, dict):
                continue
            slug = (p.get("slug") or "").lower()
            if slug and slug in low:
                ver = p.get("version") or "version inconnue"
                return f"Recoupement inventaire : plugin {slug} détecté (version {ver})"
        return None

    # ── (a) Index REST : parsing défensif + matching des clés de routes ──────

    def _match_webhook_routes(self) -> list:
        """Renvoie les clés de routes de l'index REST au motif récepteur.

        Lecture seule (GET wp-json/). Gère soft-404, corps non-JSON et formes
        inattendues sans jamais lever.
        """
        try:
            resp = self.http_get("wp-json/")
        except Exception:
            return []
        if resp is None:
            return []
        try:
            if self._is_soft404(resp):
                return []
            if resp.status_code >= 500:
                return []
            data = resp.json()
        except Exception:
            return []
        if not isinstance(data, dict):
            return []

        routes = data.get("routes")
        if not isinstance(routes, dict):
            return []

        matched = []
        for key in routes.keys():
            route = str(key)
            low = route.lower()
            if any(pat in low for pat in WEBHOOK_ROUTE_PATTERNS):
                matched.append(route)
        return matched

    # ── (b) Surface héritée WooCommerce ?wc-api= (probe bénin, lecture seule) ─

    def _probe_wc_api(self) -> Optional[str]:
        """Probe GET BÉNIN de /?wc-api= (SANS action ni payload).

        Renvoie l'URL de la surface si elle est présente (réponse ≠ 404 simple et
        ≠ soft-404), sinon None. Aucune mutation, aucune donnée d'action émise.
        """
        try:
            resp = self.http_get("?wc-api=")
        except Exception:
            return None
        if resp is None:
            return None
        wc_api_url = f"{self.target.rstrip('/')}/?wc-api="
        try:
            # Un soft-404 (home servie pour tout) n'atteste rien.
            if self._is_soft404(resp):
                return None
            status = resp.status_code
        except Exception:
            return None
        # 404 « ressource absente » = pas de surface wc-api. Toute autre réponse
        # (200/400/401/403/500…) trahit un handler qui traite le paramètre.
        if status == 404:
            return None
        return wc_api_url
