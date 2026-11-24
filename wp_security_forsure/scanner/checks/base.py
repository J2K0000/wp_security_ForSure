"""Base : classe abstraite pour tous les checks de sécurité.

Porte aussi le client HTTP unique des checks, garant du caractère « 100 %
passif, lecture seule » du scanner :
  - garde de méthode : seules GET, HEAD et OPTIONS partent (PassivityViolation
    sinon), quel que soit le chemin emprunté (helpers ou session) ;
  - garde SSRF : toute destination est résolue puis refusée si elle pointe vers
    une adresse privée, de bouclage, de lien local, réservée, multicast ou non
    spécifiée (IP littérales et hôtes tiers compris) ;
  - redirections suivies à la main, plafonnées (MAX_REDIRECTS), jamais hors du
    périmètre (hôte demandé, cible et leurs variantes www.), garde SSRF à
    chaque saut ;
  - corps lus bornés (max_response_bytes) et budget de requêtes par audit
    (max_requests) ;
  - niveaux d'accès (scanner/access_tiers.py) : chaque requête vers la cible
    est classée 0, 1 ou 2 ; sans l'option `authorized`, une requête de niveau 2
    lève AccessTierRequired ; une requête interdite à tout niveau (wp-cron.php,
    diagnostic Site Health, PHP deviné sous wp-content/) lève ForbiddenProbe.
"""

from dataclasses import dataclass, field
from typing import Any, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit
import ipaddress
import json
import re
import socket

import requests
from requests.adapters import HTTPAdapter
from requests.utils import requote_uri

from .. import access_tiers
from ..access_tiers import SOFT404_PROBE_PATH, TIER_HOME, TIER_UNLINKED

# Taille max de corps HTTP lu par défaut (5 Mio). Protège la RAM et le temps de
# scan face à une cible qui sert un flux volumineux. 0 / None = pas de borne.
DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# Seules méthodes HTTP que le scanner a le droit d'émettre (lecture seule).
ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Plafond de redirections suivies pour une même requête.
MAX_REDIRECTS = 5

# Budget de requêtes réseau par audit (clé de config `max_requests`).
DEFAULT_MAX_REQUESTS = 2000


class PassivityViolation(Exception):
    """Méthode HTTP refusée : le scanner n'émet que GET, HEAD et OPTIONS.

    Volontairement hors de la hiérarchie `requests.RequestException` : c'est
    une erreur de programmation, elle ne doit pas être confondue avec une
    simple erreur réseau.
    """


class SSRFBlocked(requests.exceptions.ConnectionError):
    """Destination refusée par la garde SSRF (adresse non publique ou non
    résoluble). Hérite de ConnectionError : un check la traite comme un hôte
    injoignable."""


class RequestBudgetExceeded(requests.exceptions.RequestException):
    """Budget de requêtes de l'audit (`max_requests`) épuisé."""


class AccessPolicyViolation(BaseException):
    """Requête refusée par la politique de niveaux d'accès.

    Hérite de BaseException, comme asyncio.CancelledError, et non de
    `requests.RequestException` ni même d'Exception : de nombreux checks
    attrapent ces exceptions (« except Exception ») et concluraient à tort
    « non exposé ». Le refus remonte donc jusqu'au moteur, qui donne au check
    le statut « error » : une erreur de classement se voit.
    """


class AccessTierRequired(AccessPolicyViolation):
    """Requête de niveau 2 (chemin deviné et non lié) sans l'option
    `authorized`."""

    def __init__(self, method: str, url: str):
        self.method, self.url = method, url
        super().__init__(
            f"Requête de niveau 2 refusée sans --authorized : {method} {url} "
            "(chemin non lié, réservé à l'audit autorisé par écrit)."
        )


class ForbiddenProbe(AccessPolicyViolation):
    """Requête interdite à tout niveau : elle exécuterait un fichier deviné
    ou déclencherait un travail côté serveur."""

    def __init__(self, method: str, url: str, reason: str):
        self.method, self.url, self.reason = method, url, reason
        super().__init__(f"Requête interdite à tout niveau : {method} {url} ({reason}).")


def check_method(method: str) -> str:
    """Renvoie la méthode normalisée, ou lève PassivityViolation."""
    normalized = (method or "").upper()
    if normalized not in ALLOWED_METHODS:
        raise PassivityViolation(
            f"Méthode HTTP {normalized or '(vide)'} refusée : le scanner est en "
            "lecture seule (GET, HEAD et OPTIONS uniquement)."
        )
    return normalized


def is_forbidden_address(address) -> bool:
    """True si l'adresse ne doit jamais être contactée.

    Privée, bouclage, lien local, réservée, multicast, non spécifiée, ou plus
    généralement non routable sur Internet (is_global faux). Une adresse IPv6
    qui encapsule une IPv4 (::ffff:a.b.c.d) est jugée sur son IPv4.
    """
    ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
            or not ip.is_global)


def resolve_host(host: str) -> List[str]:
    """Adresses IP de `host` (résolution DNS du système)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def check_destination(url: str) -> None:
    """Garde SSRF unique : lève SSRFBlocked si `url` vise une adresse interdite.

    Une IP littérale est jugée telle quelle ; un nom est résolu et TOUTES ses
    adresses doivent être publiques. Un nom non résoluble est refusé.
    """
    parts = urlsplit(url or "")
    if parts.scheme.lower() not in ("http", "https"):
        raise SSRFBlocked(f"Schéma refusé pour {url!r} : http ou https uniquement.")
    host = parts.hostname
    if not host:
        raise SSRFBlocked(f"Hôte absent dans {url!r} : requête refusée.")
    try:
        addresses = [str(ipaddress.ip_address(host.split("%", 1)[0]))]
    except ValueError:
        try:
            addresses = resolve_host(host)
        except (OSError, UnicodeError) as exc:
            raise SSRFBlocked(
                f"Résolution DNS impossible pour {host} : requête refusée."
            ) from exc
    if not addresses:
        raise SSRFBlocked(f"Aucune adresse pour {host} : requête refusée.")
    for address in addresses:
        try:
            forbidden = is_forbidden_address(address)
        except ValueError:
            forbidden = True
        if forbidden:
            raise SSRFBlocked(
                f"Destination refusée : {host} -> {address} (adresse privée, de "
                "bouclage, de lien local, réservée ou non routable)."
            )


class _PassiveAdapter(HTTPAdapter):
    """Adaptateur monté sur la session de l'audit : dernier rempart.

    Applique la garde de méthode et la garde SSRF à toute requête qui traverse
    la session, y compris un appel qui contournerait les helpers de BaseCheck
    (et chaque saut d'une redirection suivie par requests lui-même).
    """

    def send(self, request, **kwargs):
        check_method(request.method)
        check_destination(request.url)
        return super().send(request, **kwargs)


def session_references(session) -> dict:
    """Ressources référencées par les pages déjà récupérées pendant l'audit
    (partagées par la session) : clé access_tiers.reference_key -> niveau."""
    store = getattr(session, "_wpsf_references", None)
    if store is None:
        store = {}
        try:
            session._wpsf_references = store
        except AttributeError:
            pass
    return store


def record_references(session, resp, target: str, tier: Optional[int]) -> None:
    """Note les ressources que référence une réponse (corps, en-tête Link),
    au niveau de la page qui les cite. Sans effet sur une réponse sans corps."""
    try:
        text = resp.text or ""
        content_type = resp.headers.get("Content-Type", "") or ""
        link = resp.headers.get("Link", "") or ""
        base_url = resp.url or target
    except Exception:
        return
    urls = list(access_tiers.extract_references(text, content_type, base_url))
    if link:
        urls.extend(u.strip() for u in re.findall(r"<([^>]+)>", link))
    if urls:
        level = TIER_HOME if tier == TIER_HOME else (tier or access_tiers.TIER_PUBLIC)
        access_tiers.add_references(session_references(session), urls, target,
                                    level, base_url=base_url)


def install_passive_guard(session) -> None:
    """Monte _PassiveAdapter sur http:// et https:// (idempotent)."""
    if not isinstance(session, requests.Session):
        return
    if isinstance(session.adapters.get("https://"), _PassiveAdapter):
        return
    adapter = _PassiveAdapter()
    session.mount("https://", adapter)
    session.mount("http://", adapter)

# Sévérités connues, du pire au moindre. Source unique de vérité pour le tri
# par sévérité (max_severity ci-dessous, et les reporters qui en ont besoin) :
# évite que plusieurs copies de cet ordre ne divergent avec le temps.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_ORDER = {sev: i for i, sev in enumerate(SEVERITIES)}


@dataclass
class CheckResult:
    """Résultat d'un check de sécurité."""
    check_name: str          # Identifiant du check
    title: str               # Titre lisible
    description: str         # Description du check
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    passed: bool             # True = pas de vulnérabilité
    findings: List[dict] = field(default_factory=list)
    default_access_class: Optional[str] = None  # classe par défaut du check
    status: str = "ok"                    # ok | error (contrôle non réalisé)
    data_sources: Optional[dict] = None   # provenance et fraîcheur des données
    # findings = [
    #   {"message": "...", "severity": "HIGH", "evidence": "...", "url": "..."}
    # ]

    def add_finding(self, message: str, severity: str = "HIGH",
                    evidence: str = "", url: str = "",
                    confidence: str = "confirmed",
                    access_class: Optional[str] = None,
                    impact: Optional[dict] = None,
                    scoring: Optional[dict] = None):
        """Ajoute un résultat de vulnérabilité.

        confidence : "confirmed" (déterministe) ou "potential" (heuristique).
        access_class : classe d'accès attaquant (controle/secrets/pii/prive/
        recon). Si absente, on retombe sur la classe par défaut du check.
        impact : narratif structuré {data, path, enables} porté à la source.
        scoring : dict structuré {cvss, cvss_vector, cve_ids, epss} porté à
        la source.

        Lève ValueError si `severity` n'est pas une des 5 valeurs connues :
        fail-fast en dev plutôt que de laisser un typo (ex. "CRTICAL") se
        trier silencieusement comme INFO.
        """
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"severity invalide: {severity!r}")
        finding = {
            "message": message,
            "severity": severity,
            "evidence": evidence,
            "url": url,
            "confidence": confidence,
        }
        cls = access_class or self.default_access_class
        if cls:
            finding["access_class"] = cls
        if impact:
            finding["impact"] = impact
        if scoring:
            finding["scoring"] = scoring
        self.findings.append(finding)
        # Un finding réel (non purement informatif) fait échouer le check.
        if severity != "INFO":
            self.passed = False

    @property
    def max_severity(self) -> str:
        """Sévérité maximale parmi les findings."""
        if not self.findings:
            return "INFO"
        return min(self.findings,
                   key=lambda f: SEVERITY_ORDER.get(f["severity"], 4))["severity"]


class BaseCheck:
    """Classe de base pour un check de sécurité.

    Héritez-en et implémentez run().
    """

    name: str = ""                # Identifiant unique (snake_case)
    title: str = ""               # Titre humain
    description: str = ""         # Description
    severity: str = "INFO"        # Sévérité par défaut
    depends_on: List[str] = []    # Checks requis avant celui-ci
    # Niveau d'accès (scanner/access_tiers.py) de ce que le check lance sans
    # --authorized : 0 (accueil et ce qu'il référence), 1 (points d'entrée
    # publics standard) ou 2 (check entièrement fait de chemins devinés : non
    # lancé sans --authorized, statut « skipped »). Un check mixte déclare 0
    # ou 1 et protège sa partie de niveau 2 par `self.config.get("authorized")`.
    # Chaque check le déclare ; une requête mal classée lève de toute façon
    # AccessTierRequired dans le client HTTP.
    access_tier: int = TIER_HOME

    def __init__(self, target: str, config: dict, session: requests.Session):
        self.target = target
        self.config = config
        self.session = session
        install_passive_guard(session)
        self.context = {}
        self._result = CheckResult(
            check_name=self.name,
            title=self.title,
            description=self.description,
            severity=self.severity,
            passed=True,
        )

    def run(self) -> CheckResult:
        """Exécute le check. À implémenter dans les sous-classes."""
        raise NotImplementedError

    def _bounded(self, resp: requests.Response) -> requests.Response:
        """Borne le corps lu à max_response_bytes (matérialise `.content`).

        Transparent pour l'appelant : `resp.content` / `resp.text` reflètent le
        corps (éventuellement tronqué). Une borne à 0 / None lit tout.
        """
        cap = self.config.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)
        if not cap:
            _ = resp.content  # force la lecture complète du flux
            return resp
        chunks, total = [], 0
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= cap:
                break
        resp._content = b"".join(chunks)[:cap]
        resp._content_consumed = True
        return resp

    # ── Client HTTP passif (seul point de sortie réseau des checks) ─────

    def _url(self, path: str) -> str:
        """URL absolue d'un chemin relatif à la cible."""
        return f"{self.target.rstrip('/')}/{path.lstrip('/')}"

    def _scope_hosts(self, url: str) -> Set[str]:
        """Hôtes vers lesquels une redirection peut être suivie : la cible,
        l'hôte demandé, et leur variante avec ou sans « www. »."""
        hosts: Set[str] = set()
        for candidate in (self.target, url):
            host = (urlsplit(candidate or "").hostname or "").lower()
            if not host:
                continue
            hosts.add(host)
            hosts.add(host[4:] if host.startswith("www.") else "www." + host)
        return hosts

    def _consume_budget(self) -> None:
        """Décompte une requête du budget de l'audit (partagé via la session)."""
        limit = self.config.get("max_requests", DEFAULT_MAX_REQUESTS)
        count = getattr(self.session, "_wpsf_request_count", 0)
        if limit and count >= limit:
            raise RequestBudgetExceeded(
                f"Budget de requêtes de l'audit atteint ({limit}, clé "
                "max_requests) : requête non envoyée."
            )
        self.session._wpsf_request_count = count + 1

    def _send(self, method: str, url: str, allow_redirects: bool = True,
              client: Optional[requests.Session] = None, record: bool = True,
              **kwargs) -> requests.Response:
        """Émet une requête passive : garde de méthode, garde SSRF, budget,
        corps borné, redirections suivies à la main dans le périmètre.

        Une redirection vers un hôte hors périmètre n'est pas suivie : la
        réponse 3xx est rendue telle quelle. Au-delà de MAX_REDIRECTS sauts,
        TooManyRedirects est levée.

        `client` : session distincte (profil de visite à cookies isolés), à
        laquelle la garde passive est montée ; le budget et les ressources
        référencées restent ceux de la session de l'audit. `record=False` : les
        ressources que cite la réponse ne sont pas notées comme référencées
        (variante servie à un profil de visite, possiblement injectée).
        """
        method = check_method(method)
        tier = self._enforce_access(method, url, kwargs.get("params"))
        kwargs.setdefault("timeout", self.config.get("timeout", 30))
        kwargs.setdefault("stream", True)
        sender = client if client is not None else self.session
        if sender is not self.session:
            install_passive_guard(sender)
        scope = self._scope_hosts(url)
        history: List[requests.Response] = []
        while True:
            check_destination(url)
            self._consume_budget()
            resp = sender.request(method, url, allow_redirects=False,
                                  **kwargs)
            if method == "HEAD":
                # Une réponse HEAD n'a pas de corps : rien à lire.
                resp._content = b""
                resp._content_consumed = True
                resp.close()
            else:
                resp = self._bounded(resp)
            if not (allow_redirects and resp.is_redirect):
                break
            location = resp.headers.get("location")
            if hasattr(sender, "get_redirect_target"):
                location = sender.get_redirect_target(resp) or location
            if not location:
                break
            next_url = urljoin(resp.url or url, requote_uri(location))
            next_parts = urlsplit(next_url)
            if (next_parts.scheme.lower() not in ("http", "https")
                    or (next_parts.hostname or "").lower() not in scope):
                break  # hors périmètre : redirection rendue, jamais suivie
            if access_tiers.forbidden_reason(next_url, self.target,
                                             session_references(self.session)):
                break  # destination interdite à tout niveau : jamais suivie
            if len(history) >= MAX_REDIRECTS:
                raise requests.exceptions.TooManyRedirects(
                    f"Plus de {MAX_REDIRECTS} redirections depuis {url} : arrêt.",
                    response=resp,
                )
            history.append(resp)
            if resp.status_code in (302, 303) and method == "OPTIONS":
                method = "GET"
            kwargs.pop("params", None)  # déjà intégrés à l'URL de redirection
            url = next_url
        if history:
            resp.history = history
        if method != "HEAD" and record:
            record_references(self.session, resp, self.target, tier)
        return resp

    def profile_client(self) -> requests.Session:
        """Session à cookies vierges pour un profil de visite, garde passive
        montée (méthode, SSRF), même politique de certificats que l'audit."""
        client = requests.Session()
        client.verify = getattr(self.session, "verify", False)
        install_passive_guard(client)
        return client

    def references(self) -> dict:
        """Ressources déjà vues comme référencées pendant l'audit."""
        return session_references(self.session)

    def profile_get(self, url: str, client: requests.Session,
                    headers: dict, allow_redirects: bool = True) -> requests.Response:
        """GET d'un profil de visite : session à cookies isolés (`client`),
        en-têtes du profil, mêmes gardes que http_get (méthode, SSRF, niveaux
        d'accès, budget, corps borné, redirections dans le périmètre), jamais
        mis en cache, ressources citées non notées comme référencées."""
        return self._send("GET", url, allow_redirects=allow_redirects,
                          client=client, record=False, headers=headers)

    # ── Niveaux d'accès ──────────────────────────────────────────────────

    def _absolute(self, path_or_url: str) -> str:
        if (path_or_url or "").lower().startswith(("http://", "https://")):
            return path_or_url
        return self._url(path_or_url)

    def request_tier(self, path_or_url: str, method: str = "GET") -> Optional[int]:
        """Niveau (0, 1, 2) d'une requête vers la cible, None pour un hôte
        tiers. Les ressources déjà vues comme référencées comptent."""
        return access_tiers.classify(method, self._absolute(path_or_url),
                                     self.target, session_references(self.session))

    def may_request(self, path_or_url: str, method: str = "GET") -> bool:
        """True si la requête peut partir dans le mode courant : ni interdite
        à tout niveau, ni de niveau 2 sans `authorized`. Sert aux checks mixtes
        pour ne garder que les sondes permises."""
        url = self._absolute(path_or_url)
        refs = session_references(self.session)
        if access_tiers.forbidden_reason(url, self.target, refs):
            return False
        tier = access_tiers.classify(method, url, self.target, refs)
        return (bool(self.config.get("authorized")) or tier is None
                or tier < TIER_UNLINKED)

    def note_unlinked_skipped(self, what: str) -> None:
        """Constat INFO d'un check mixte lancé sans --authorized : dit quelle
        partie de niveau 2 (chemins devinés et non liés) n'a pas été faite."""
        self._result.add_finding(
            message=("Non réalisé sans --authorized (recherche de chemins non "
                     f"liés) : {what}"),
            severity="INFO",
            evidence=("Ces sondes visent des chemins devinés et non liés (niveau "
                      "2), réservés à l'audit d'un site dont le propriétaire a "
                      "donné son autorisation écrite (option --authorized). "
                      "Leur absence de constat ne prouve rien."),
            url=self.target,
            confidence="potential",
        )

    def note_not_assessable(self, what: str, server_work: bool = False,
                            evidence: str = "") -> None:
        """Constat INFO d'une sonde retirée à tout niveau : elle exécutait un
        fichier deviné ou déclenchait un travail côté serveur."""
        cause = ("sans déclencher un traitement côté serveur" if server_work
                 else "sans exécuter le fichier")
        default = ("Demander ce point d'entrée lancerait un traitement côté "
                   "serveur" if server_work else
                   "Un GET sur un fichier PHP l'exécute côté serveur")
        self._result.add_finding(
            message=(f"{what} : non évaluable de l'extérieur {cause} ; à "
                     "vérifier en mode authentifié"),
            severity="INFO",
            evidence=(evidence or default) + (
                " : le scanner ne l'envoie à aucun niveau d'accès."),
            url=self.target,
            confidence="potential",
        )

    def _enforce_access(self, method: str, url: str, params=None) -> Optional[int]:
        """Classe la requête ; lève ForbiddenProbe (interdite à tout niveau) ou
        AccessTierRequired (niveau 2 sans `authorized`). Renvoie le niveau."""
        if params:
            url = requests.Request(method, url, params=params).prepare().url or url
        refs = session_references(self.session)
        reason = access_tiers.forbidden_reason(url, self.target, refs)
        if reason:
            raise ForbiddenProbe(method, url, reason)
        tier = access_tiers.classify(method, url, self.target, refs)
        if (tier is not None and tier >= TIER_UNLINKED
                and not self.config.get("authorized")):
            raise AccessTierRequired(method, url)
        return tier

    def _cached_get(self, url: str, no_cache: bool = False,
                    **kwargs) -> requests.Response:
        """GET borné et mémoïsé par URL (voir http_get)."""
        cache = getattr(self.session, "_wpsf_get_cache", None)
        if cache is None:
            cache = {}
            self.session._wpsf_get_cache = cache
        cacheable = (not no_cache
                     and not any(k in kwargs for k in
                                 ("data", "json", "params", "headers", "method")))
        if cacheable and url in cache:
            return cache[url]
        allow_redirects = kwargs.pop("allow_redirects", True)
        resp = self._send("GET", url, allow_redirects=allow_redirects, **kwargs)
        if cacheable:
            cache[url] = resp
        return resp

    def http_get(self, path: str, no_cache: bool = False, **kwargs) -> requests.Response:
        """Requête GET sur l'URL cible (corps borné, mémoïsée par URL).

        Les GET idempotents sont mis en cache sur la session : plusieurs checks
        qui lisent la même URL (home, readme, wp-login) ne déclenchent qu'un
        seul appel réseau. `no_cache=True` force une requête fraîche. Un GET
        avec `data`/`json`/`params`/`headers`/`method` n'est pas mémoïsé (non
        idempotent, ou distinct de la requête simple, au sens du cache par
        URL) : un appelant qui personnalise ses en-têtes ou sa méthode veut
        explicitement une requête fraîche et distincte, pas la réponse mise en
        cache d'un GET simple vers la même URL.
        """
        return self._cached_get(self._url(path), no_cache=no_cache, **kwargs)

    def http_get_url(self, url: str, no_cache: bool = False,
                     **kwargs) -> requests.Response:
        """GET sur une URL ABSOLUE (cible ou hôte tiers), mêmes garanties que
        http_get : garde SSRF, redirections dans le périmètre, corps borné,
        budget, mémoïsation par URL."""
        return self._cached_get(url, no_cache=no_cache, **kwargs)

    def get_json(
        self, path: str, bail_404: bool = True, **kwargs
    ) -> Tuple[Optional[Any], Optional[requests.Response]]:
        """GET `path` et parse le corps en JSON, factorise le pattern répété

        try: resp = self.http_get(path)
        except Exception: return
        if resp.status_code == 404: return
        try: data = resp.json()
        except Exception: return

        présent ~15 fois dans les checks (rest_api notamment).

        Retourne un tuple (data, resp) :
          - (None, None) si la requête GET elle-même a levé (erreur réseau...).
          - (None, resp) si `bail_404` (par défaut) et resp.status_code == 404
           , le JSON n'est alors même pas tenté (le corps d'un 404 générique
            n'a aucune raison d'être inspecté par la majorité des appelants).
          - (None, resp) si le corps n'est pas du JSON valide.
          - (data, resp) avec le corps parsé sinon.

        `bail_404=False` désactive le court-circuit sur 404 : certains
        appelants doivent inspecter le corps même sur un 404 (ex. distinguer
        un WP_Error JSON d'une page HTML de 404). `resp` reste disponible
        dans tous les cas où la requête a abouti, pour les appelants qui ont
        besoin du status code / des headers en plus du corps parsé.
        `**kwargs` est transmis tel quel à `http_get` (ex. `headers=...`).
        """
        try:
            resp = self.http_get(path, **kwargs)
        except Exception:
            return None, None
        if bail_404 and resp.status_code == 404:
            return None, resp
        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            return None, resp
        return data, resp

    def http_request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Requête sur l'URL cible avec une méthode explicite (corps borné,
        jamais mise en cache). Seules GET, HEAD et OPTIONS sont acceptées :
        toute autre méthode lève PassivityViolation."""
        allow_redirects = kwargs.pop("allow_redirects", True)
        return self._send(method, self._url(path),
                          allow_redirects=allow_redirects, **kwargs)

    def http_head(self, path: str, **kwargs) -> requests.Response:
        """Requête HEAD sur l'URL cible (sans suivi de redirection par
        défaut, comme requests)."""
        allow_redirects = kwargs.pop("allow_redirects", False)
        return self._send("HEAD", self._url(path),
                          allow_redirects=allow_redirects, **kwargs)

    def http_options(self, path: str, **kwargs) -> requests.Response:
        """Requête OPTIONS sur l'URL cible (lecture des méthodes annoncées)."""
        allow_redirects = kwargs.pop("allow_redirects", False)
        return self._send("OPTIONS", self._url(path),
                          allow_redirects=allow_redirects, **kwargs)

    def rest_index(self) -> Tuple[Optional[dict], str]:
        """Index REST public : (données, url) via GET wp-json/, repli
        ?rest_route=/ (permaliens désactivés), ou (None, url) s'il est absent.

        Lecture seule et mémoïsée : la présence d'une route dans l'index prouve
        qu'elle existe sans jamais l'appeler.
        """
        for path in ("wp-json/", "?rest_route=/"):
            data, resp = self.get_json(path)
            if resp is None or not isinstance(data, dict):
                continue
            if (isinstance(data.get("routes"), dict)
                    or isinstance(data.get("namespaces"), list)):
                return data, self._url(path)
        return None, self._url("wp-json/")

    # Chemin bidon très improbable, servant de témoin « ressource absente »
    # (niveau 1, voir access_tiers.PUBLIC_ENTRY_POINTS).
    _SOFT404_PROBE_PATH = SOFT404_PROBE_PATH

    def _soft404_baseline(self) -> Optional[dict]:
        """Réponse témoin d'un chemin inexistant (mémoïsée sur la session).

        Retourne {status, size, prefix} ou None si la sonde échoue. Sert à
        distinguer une vraie ressource d'un site qui renvoie 200 + page d'accueil
        (soft-404) pour toute URL.
        """
        cached = getattr(self.session, "_wpsf_soft404", "unset")
        if cached != "unset":
            return cached
        baseline = None
        try:
            resp = self.http_get(self._SOFT404_PROBE_PATH)
            body = resp.text or ""
            baseline = {
                "status": resp.status_code,
                "size": len(resp.content or b""),
                "prefix": body[:64],
            }
        except Exception:
            baseline = None
        self.session._wpsf_soft404 = baseline
        return baseline

    def _is_soft404(self, resp) -> bool:
        """True si `resp` ≈ le témoin « ressource absente » (donc PAS une vraie
        ressource exposée). False si le témoin est indisponible (on ne masque
        rien par défaut) ou si la réponse diffère nettement.
        """
        from .signatures import matches_baseline
        baseline = self._soft404_baseline()
        if not baseline:
            return False
        try:
            size = len(resp.content or b"")
            prefix = (resp.text or "")[:64]
        except Exception:
            return False
        return matches_baseline(resp.status_code, size, prefix, baseline)

    @property
    def result(self) -> CheckResult:
        return self._result
