"""email_auth, Audit SPF / DKIM / DMARC (surface d'usurpation d'email).

Passif : résolutions DNS TXT en lecture seule. Distingue une absence légitime
(NoAnswer/NXDOMAIN) d'une résolution indéterminée (timeout/réseau) pour ne pas
émettre de faux « absent ».
"""
from typing import List, Optional
from urllib.parse import urlparse

from .base import BaseCheck, CheckResult

_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1"]


def _resolve_txt(name: str) -> Optional[List[str]]:
    """TXT de `name`. [] = absent (légitime) ; None = indéterminé (réseau)."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return None
    out = []
    for r in answers:
        parts = getattr(r, "strings", None) or []
        out.append("".join(p.decode() if isinstance(p, bytes) else p for p in parts))
    return out


class EmailAuthCheck(BaseCheck):
    name = "email_auth"
    title = "Authentification email (SPF / DKIM / DMARC)"
    description = ("Vérifie SPF, DMARC et DKIM du domaine, une configuration "
                  "absente ou permissive facilite l'usurpation d'email (phishing).")
    severity = "MEDIUM"
    access_tier = 0  # DNS seulement, aucune requête HTTP vers la cible
    depends_on: List[str] = []

    def _domain(self) -> str:
        host = (urlparse(self.target).hostname or "").lower()
        return host[4:] if host.startswith("www.") else host

    def run(self) -> CheckResult:
        domain = self._domain()
        if not domain:
            return self._result
        self._audit_spf(domain)
        self._audit_dmarc(domain)
        self._audit_dkim(domain)
        return self._result

    def _audit_spf(self, domain: str):
        txt = _resolve_txt(domain)
        if txt is None:
            self._result.add_finding(
                message=f"Résolution DNS indisponible pour {domain}, audit SPF ignoré",
                severity="INFO", evidence="Timeout ou serveur DNS injoignable.",
                url=self.target, confidence="confirmed")
            return
        spf = next((r for r in txt if r.lower().startswith("v=spf1")), None)
        if spf is None:
            self._result.add_finding(
                message=f"SPF absent pour {domain}, usurpation d'email facilitée",
                severity="MEDIUM", evidence="Aucun enregistrement TXT « v=spf1 ».",
                url=self.target, confidence="confirmed", access_class="pii")
            return
        norm = spf.replace(" ", "").lower()
        permissive = "+all" in norm or (
            norm.endswith("all") and not norm.endswith(("-all", "~all", "?all")))
        if permissive:
            self._result.add_finding(
                message=f"SPF permissif (+all) pour {domain}, tout serveur autorisé à émettre",
                severity="HIGH", evidence=f"Enregistrement : {spf}",
                url=self.target, confidence="confirmed", access_class="pii")

    def _audit_dmarc(self, domain: str):
        txt = _resolve_txt("_dmarc." + domain)
        if txt is None:
            self._result.add_finding(
                message=f"Résolution DNS indisponible pour _dmarc.{domain}, audit DMARC ignoré",
                severity="INFO", evidence="Timeout ou serveur DNS injoignable.",
                url=self.target, confidence="confirmed")
            return
        dmarc = next((r for r in txt if r.lower().startswith("v=dmarc1")), None)
        if dmarc is None:
            self._result.add_finding(
                message=f"DMARC absent pour {domain}, pas de politique anti-usurpation",
                severity="MEDIUM", evidence="Aucun TXT « v=DMARC1 » sur _dmarc.",
                url=self.target, confidence="confirmed", access_class="pii")
            return
        policy = ""
        for tag in dmarc.split(";"):
            t = tag.strip().lower()
            if t.startswith("p="):
                policy = t[2:].strip()
                break
        if policy == "none":
            self._result.add_finding(
                message=f"DMARC en p=none pour {domain}, aucune application (surveillance seule)",
                severity="LOW", evidence=f"Enregistrement : {dmarc}",
                url=self.target, confidence="confirmed", access_class="pii")

    def _audit_dkim(self, domain: str):
        found = []
        for sel in _DKIM_SELECTORS:
            txt = _resolve_txt(f"{sel}._domainkey.{domain}")
            if txt:
                found.append(sel)
        if not found:
            self._result.add_finding(
                message=f"DKIM non détecté pour {domain} (sélecteurs courants), à confirmer",
                severity="INFO",
                evidence=f"Sélecteurs testés : {', '.join(_DKIM_SELECTORS)}.",
                url=self.target, confidence="potential", access_class="recon")
