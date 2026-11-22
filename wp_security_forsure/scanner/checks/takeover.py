"""takeover, détection de subdomain / subresource takeover (DNS dangling).

Classe de vulnérabilité couverte : un enregistrement DNS (A/CNAME) pointe encore
vers un service tiers (S3, GitHub Pages, Heroku, Fastly, Azure…) qui a été
déprovisionné ou dont l'espace de noms est désormais réclamable. Un attaquant qui
recrée la ressource côté fournisseur « capture » alors l'hôte : il sert du contenu
sous un domaine/sous-domaine légitime de la cible (phishing, vol de cookies,
bypass CSP, exfiltration via une ressource chargée par la home).

NON DESTRUCTIF, boîte noire, non authentifié. Ce check n'effectue QUE :
  - de la résolution DNS via la bibliothèque standard (socket.getaddrinfo) ;
  - des requêtes GET en lecture seule (aucune écriture, aucun POST).
Il ne tente JAMAIS de réclamer/recréer la ressource : il se contente de constater
le pointeur pendouillant (dangling) et de le confirmer par une empreinte de
réponse (« fingerprint ») du service déprovisionné.

DEUX MODES
----------
1) LÉGER (par défaut) :
   (a) Hôte CIBLE : la home est récupérée puis son corps est comparé aux
       DANGLING_FINGERPRINTS (cas où la cible elle-même est déjà capturée).
   (b) RESSOURCES EXTERNES de la home : les src/href externes (script/img/iframe/
       link) sont extraits, les hôtes tiers dédupliqués. Pour chaque hôte tiers :
         - résolution DNS ; un NXDOMAIN sur un hôte POURTANT référencé = candidat
           subresource takeover (MEDIUM potential) ;
         - sinon fetch http(s) et comparaison aux fingerprints (HIGH potential si
           un service déprovisionné est reconnu).

2) ÉTENDU (opt-in via config `takeover_enum: true`) : énumération des sous-domaines
   du domaine cible via Certificate Transparency (crt.sh). Chaque sous-domaine est
   résolu + fetché + comparé aux fingerprints. L'énumération est BORNÉE à ~50
   sous-domaines ; si la liste est tronquée, un finding INFO explicite indique le
   nombre total vu et le nombre testé (jamais de cap silencieux).

Remarque : la détection de CNAME pendouillant se fait en « best-effort » via le
fingerprint du corps (socket standard ne renvoie pas le CNAME de façon portable ;
on ne dépend d'AUCUNE bibliothèque DNS externe type dnspython).

La base DANGLING_FINGERPRINTS est volontairement EXTENSIBLE : ajouter une entrée
`service -> {"fingerprint": "...", "desc": "..."}` suffit à couvrir un nouveau
fournisseur.
"""

import ipaddress
import re
import socket
from typing import List, Optional
from urllib.parse import urlparse

from .base import BaseCheck, CheckResult

# ── Empreintes de services déprovisionnés / réclamables ─────────────────────
# service -> {"fingerprint": <chaîne présente dans le corps quand la ressource
#             est absente/réclamable>, "desc": <libellé du service>}.
# Matching insensible à la casse (voir _match_fingerprint). Liste EXTENSIBLE :
# ajouter une entrée suffit à couvrir un nouveau fournisseur.
DANGLING_FINGERPRINTS = {
    "aws_s3": {
        "fingerprint": "NoSuchBucket",
        "desc": "AWS S3, bucket inexistant (réclamable)",
    },
    "github_pages": {
        "fingerprint": "There isn't a GitHub Pages site here",
        "desc": "GitHub Pages, dépôt/site absent",
    },
    "heroku": {
        "fingerprint": "No such app",
        "desc": "Heroku, application inexistante "
                "(cf. herokucdn.com/error-pages/no-such-app.html)",
    },
    "fastly": {
        "fingerprint": "Fastly error: unknown domain",
        "desc": "Fastly, domaine non configuré (réclamable)",
    },
    "shopify": {
        "fingerprint": "Sorry, this shop is currently unavailable",
        "desc": "Shopify, boutique indisponible/supprimée",
    },
    "azure": {
        "fingerprint": "404 Web Site not found",
        "desc": "Azure App Service, site absent "
                "(variante : « This web app has been stopped »)",
    },
    "aws_cloudfront": {
        "fingerprint": "The request could not be satisfied",
        "desc": "AWS CloudFront, distribution absente/mal configurée",
    },
    "bitbucket": {
        "fingerprint": "Repository not found",
        "desc": "Bitbucket, dépôt introuvable",
    },
    "ghost": {
        "fingerprint": "The thing you were looking for is no longer here",
        "desc": "Ghost, publication supprimée",
    },
    "zendesk": {
        "fingerprint": "Help Center Closed",
        "desc": "Zendesk, Help Center fermé",
    },
    "netlify": {
        "fingerprint": "Not Found - Request ID",
        "desc": "Netlify, site absent",
    },
    "surge": {
        "fingerprint": "project not found",
        "desc": "Surge.sh, projet inexistant",
    },
    "readthedocs": {
        "fingerprint": "unknown to Read the Docs",
        "desc": "Read the Docs, projet inconnu",
    },
    "pantheon": {
        "fingerprint": "The gods are wise",
        "desc": "Pantheon, site non réclamé",
    },
    "wordpress_com": {
        "fingerprint": "Do you want to register",
        "desc": "WordPress.com, sous-domaine réclamable",
    },
    "tumblr": {
        "fingerprint": "Whatever you were looking for doesn't currently exist",
        "desc": "Tumblr, blog inexistant",
    },
}

# Ressources externes de la home : src/href des balises script/img/iframe/link.
_ASSET_RE = re.compile(
    r"<(?:script|img|iframe|link)\b[^>]*?\b(?:src|href)\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

# Borne de l'énumération étendue (crt.sh) : au-delà, on tronque ET on le signale.
_ENUM_CAP = 50


class TakeoverCheck(BaseCheck):
    """Détecte les subdomain / subresource takeover (DNS dangling + fingerprint)."""

    name = "takeover"
    title = "Subdomain / subresource takeover (DNS dangling)"
    description = (
        "Détecte les prises de contrôle possibles d'un (sous-)domaine ou d'une "
        "ressource externe : enregistrement DNS pointant vers un service tiers "
        "déprovisionné/réclamable, confirmé par une empreinte de réponse. Non "
        "destructif : résolution DNS standard + GET en lecture seule. Mode étendu "
        "opt-in : énumération des sous-domaines via Certificate Transparency."
    )
    severity = "HIGH"
    access_tier = 0  # accueil et hôtes tiers qu'il cite
    depends_on: List[str] = []

    def run(self) -> CheckResult:
        target_host = self._target_host()
        domain = self._target_domain()
        tested = 0  # hôtes/sous-domaines réellement sondés (pour le récap)

        # ── (a) Hôte CIBLE lui-même : la home est-elle déjà capturée ? ──────
        home_body = self._home_body()
        if home_body is not None:
            tested += 1
            match = self._match_fingerprint(home_body)
            if match:
                self._flag_takeover(target_host, match, referenced_by="home (cible)")

        # ── (b) Ressources externes chargées par la home ────────────────────
        for host in self._external_hosts(home_body, target_host):
            tested += 1
            self._inspect_host(host, referenced=True)

        # ── ÉTENDU (opt-in) : énumération crt.sh ────────────────────────────
        mode = "léger"
        if self.config.get("takeover_enum"):
            mode = "étendu (crt.sh)"
            tested += self._run_enum(domain, target_host)

        # ── Récapitulatif INFO ──────────────────────────────────────────────
        self._result.add_finding(
            message=(
                f"Analyse takeover terminée, mode {mode}, {tested} hôte(s) "
                f"testé(s) (domaine cible : {domain or 'inconnu'})"
            ),
            severity="INFO",
            evidence=(
                f"Mode : {mode}\n"
                f"Hôtes/sous-domaines testés : {tested}\n"
                "Méthode non destructive : résolution DNS (socket standard) + GET "
                "en lecture seule ; empreintes de services déprovisionnés comparées "
                "au corps des réponses. Aucune ressource n'a été réclamée/recréée."
            ),
            url=self.target.rstrip("/"),
            confidence="potential",
        )
        return self._result

    # ── Inspection d'un hôte (résolution → fetch → fingerprint) ─────────────

    def _inspect_host(self, host: str, referenced: bool):
        """Résout `host` ; NXDOMAIN d'un hôte référencé = MEDIUM ; fingerprint = HIGH."""
        try:
            resolves = self._resolve(host)
        except Exception:
            resolves = True  # en cas d'imprévu, on ne conclut pas au NXDOMAIN
        if not resolves:
            if referenced:
                self._result.add_finding(
                    message=(
                        "Ressource externe référencée mais domaine non résolu "
                        f"(NXDOMAIN) : {host}, subresource takeover possible"
                    ),
                    severity="MEDIUM",
                    evidence=(
                        f"Hôte : {host}\n"
                        "L'hôte est référencé par la home (src/href) mais ne résout "
                        "plus en DNS (NXDOMAIN). Si le domaine/sous-domaine redevient "
                        "enregistrable, un attaquant peut le capturer et servir une "
                        "ressource malveillante sous une origine de confiance.\n"
                        "Confirmation manuelle recommandée (registrar/fournisseur DNS)."
                    ),
                    url=f"//{host}",
                    confidence="potential",
                )
            return
        # Résout : on récupère le corps et on cherche une empreinte de dangling.
        body = self._probe_host(host)
        match = self._match_fingerprint(body)
        if match:
            self._flag_takeover(host, match, referenced_by="ressource externe")

    def _flag_takeover(self, host: str, match: tuple, referenced_by: str):
        service, fingerprint = match
        info = DANGLING_FINGERPRINTS.get(service, {})
        desc = info.get("desc", service)
        self._result.add_finding(
            message=(
                f"Subdomain/subresource takeover probable : {host} pointe vers "
                f"{desc} déprovisionné"
            ),
            severity="HIGH",
            evidence=(
                f"Hôte : {host}\n"
                f"Référencé via : {referenced_by}\n"
                f"Service reconnu : {service} ({desc})\n"
                f"Empreinte de service déprovisionné détectée : \"{fingerprint}\"\n"
                "Le corps de la réponse correspond à la page d'erreur d'un service "
                "tiers dont la ressource est absente/réclamable : un attaquant "
                "recréant la ressource côté fournisseur capturerait cet hôte.\n"
                "Remédiation : supprimer l'enregistrement DNS pendouillant ou "
                "reprendre possession de la ressource chez le fournisseur."
            ),
            url=f"//{host}",
            confidence="potential",
        )

    # ── Mode ÉTENDU : énumération crt.sh ────────────────────────────────────

    def _run_enum(self, domain: Optional[str], target_host: Optional[str]) -> int:
        if not domain:
            return 0
        try:
            subs = self._crtsh_subdomains(domain) or []
        except Exception:
            subs = []
        # Dédup défensive + exclusion de l'hôte cible déjà testé en mode léger.
        seen, ordered = set(), []
        for s in subs:
            s = (s or "").strip().lower()
            if not s or s == target_host or s in seen:
                continue
            seen.add(s)
            ordered.append(s)

        total = len(ordered)
        to_test = ordered[:_ENUM_CAP]
        if total > _ENUM_CAP:
            # Cap explicite (jamais silencieux) : on trace la troncature en INFO.
            self._result.add_finding(
                message=(
                    f"Énumération crt.sh tronquée : {total} sous-domaines vus, "
                    f"{_ENUM_CAP} testés (borne de sûreté)"
                ),
                severity="INFO",
                evidence=(
                    f"Domaine : {domain}\n"
                    f"Sous-domaines uniques vus (Certificate Transparency) : {total}\n"
                    f"Testés (résolution + fetch + fingerprint) : {_ENUM_CAP}\n"
                    "La liste est bornée pour préserver le caractère léger/non "
                    "intrusif du scan. Relancer avec une borne supérieure ou cibler "
                    "manuellement les sous-domaines restants si nécessaire."
                ),
                url=self.target.rstrip("/"),
                confidence="potential",
            )
        for host in to_test:
            # En énumération, un NXDOMAIN d'un sous-domaine issu d'un vieux
            # certificat n'est pas concluant : on ne remonte que les dangling
            # confirmés par fingerprint (referenced=False).
            self._inspect_host(host, referenced=False)
        return len(to_test)

    # ── SEAMS DE TEST : résolution DNS / fetch tiers / crt.sh ───────────────
    #
    # Ces trois méthodes isolent tout accès réseau non-cible pour que les tests
    # les monkeypatchent sans réseau réel.

    def _resolve(self, host: str) -> bool:
        """True si `host` résout en DNS, False sur NXDOMAIN (socket.gaierror).

        N'utilise que la bibliothèque standard (aucune dépendance DNS externe).
        Toute autre erreur (timeout, réseau) est traitée comme « résout » afin de
        ne PAS conclure à tort à un NXDOMAIN (éviter les faux positifs MEDIUM).
        """
        if not host:
            return False
        try:
            socket.getaddrinfo(host, None)
            return True
        except socket.gaierror:
            return False
        except Exception:
            return True

    def _fetch_external(self, url: str) -> Optional[str]:
        """GET en lecture seule d'un hôte TIERS ; renvoie le corps ou None.

        Timeout court, verify=False (les certificats des services capturés sont
        souvent invalides), aucune exception propagée.
        """
        try:
            # Garde SSRF, redirections dans le périmètre et corps borné : via
            # le client passif de BaseCheck (IP littérales internes refusées).
            resp = self.http_get_url(url, verify=False)
            return resp.text or ""
        except Exception:
            return None

    def _crtsh_subdomains(self, domain: str) -> list:
        """Sous-domaines de `domain` via Certificate Transparency (crt.sh).

        GET https://crt.sh/?q=%25.<domain>&output=json ; parse le JSON ; dédup des
        `name_value` ; ignore les wildcards (*.). Renvoie [] en cas d'échec.
        """
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = self.http_get_url(url, verify=False)
            data = resp.json()
        except Exception:
            return []
        if not isinstance(data, list):
            return []
        subs = set()
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.strip().lower()
                if not name or name.startswith("*."):
                    continue
                if name == domain or name.endswith("." + domain):
                    subs.add(name)
        return sorted(subs)

    # ── Utilitaires ─────────────────────────────────────────────────────────

    def _home_body(self) -> Optional[str]:
        """Corps de la home de la CIBLE (via http_get), ou None."""
        try:
            resp = self.http_get("")
            return resp.text or ""
        except Exception:
            return None

    def _probe_host(self, host: str) -> Optional[str]:
        """Fetch http(s) d'un hôte tiers : https d'abord, http en repli."""
        for scheme in ("https", "http"):
            body = self._fetch_external(f"{scheme}://{host}/")
            if body:
                return body
        return None

    def _external_hosts(self, home_body: Optional[str],
                        target_host: Optional[str]) -> list:
        """Hôtes tiers dédupliqués référencés par la home (src/href externes)."""
        if not home_body:
            return []
        hosts, seen = [], set()
        for raw in _ASSET_RE.findall(home_body):
            host = self._url_host(raw)
            if not host or host == target_host or host in seen:
                continue
            seen.add(host)
            hosts.append(host)
        return hosts

    @staticmethod
    def _url_host(raw: str) -> Optional[str]:
        """Hôte d'une URL de ressource (absolue http(s) ou protocol-relative //)."""
        raw = (raw or "").strip()
        if raw.startswith("//"):
            raw = "https:" + raw
        if not raw.lower().startswith(("http://", "https://")):
            return None  # URL relative → même origine que la cible, ignorée
        try:
            host = (urlparse(raw).hostname or "").lower()
        except Exception:
            return None
        # Un hôte valide comporte au moins un point et n'est PAS une IP
        # littérale (10.0.0.5, 169.254.169.254, [::1]...) : ni un nom local sans
        # TLD ni une adresse ne relèvent d'un takeover de service tiers, et les
        # requêter exposerait le réseau de l'auditeur (SSRF depuis une page
        # piégée). La garde SSRF de BaseCheck reste le rempart final.
        if not host or "." not in host:
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            return host

    def _target_host(self) -> Optional[str]:
        try:
            return (urlparse(self.target).hostname or "").lower() or None
        except Exception:
            return None

    def _target_domain(self) -> Optional[str]:
        """Domaine enregistrable approché : les deux derniers labels de l'hôte."""
        host = self._target_host()
        if not host:
            return None
        labels = host.split(".")
        if len(labels) <= 2:
            return host
        return ".".join(labels[-2:])

    @staticmethod
    def _match_fingerprint(body: Optional[str]) -> Optional[tuple]:
        """(service, fingerprint) si le corps matche une empreinte, sinon None."""
        if not body:
            return None
        low = body.lower()
        for service, info in DANGLING_FINGERPRINTS.items():
            fp = info.get("fingerprint", "")
            if fp and fp.lower() in low:
                return service, fp
        return None
