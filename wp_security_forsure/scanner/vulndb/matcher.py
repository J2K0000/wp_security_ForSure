"""Matching version installée -> vulnérabilités (format wpvulnerability.net)."""
from dataclasses import dataclass, field
from typing import List, Optional
from packaging.version import Version, InvalidVersion


@dataclass
class Vuln:
    title: str
    cve_ids: List[str]
    cvss_score: Optional[float]
    cvss_vector: str
    fixed_in: Optional[str]          # version corrigée connue, sinon None
    refs: List[str] = field(default_factory=list)
    last_affected: Optional[str] = None  # borne haute inclusive (le)
    unfixed: bool = False                # fiche marquée sans correctif
    operator: dict = field(default_factory=dict)


def _parse(v: str):
    """Version comparable, tolérant aux versions non-PEP440 fréquentes en WP."""
    try:
        return Version(v)
    except (InvalidVersion, TypeError):
        parts = []
        for chunk in str(v).replace("-", ".").split("."):
            num = "".join(ch for ch in chunk if ch.isdigit())
            parts.append(int(num) if num else 0)
        return tuple(parts) if parts else (0,)


def compare_versions(a: str, b: str) -> int:
    """-1 si a<b, 0 si a==b, 1 si a>b (avec fallback homogène)."""
    pa, pb = _parse(a), _parse(b)
    if type(pa) is not type(pb):
        pa, pb = _as_tuple(a), _as_tuple(b)
    return (pa > pb) - (pa < pb)


# Alias rétro-compatible : d'anciens appelants réimportaient le nom privé
# directement (`from ..vulndb.matcher import _cmp`). Conservé pour ne rien
# casser en dehors des deux checks déjà migrés vers `compare_versions`.
_cmp = compare_versions


def _as_tuple(v: str):
    parts = []
    for chunk in str(v).replace("-", ".").split("."):
        num = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts) if parts else (0,)


MATCH = "match"
NO_MATCH = "no_match"
UNKNOWN = "unknown"   # opérateur inconnu : non apparié, à vérifier

_MIN_OPS = ("gt", "ge", None)
_MAX_OPS = ("lt", "le", None)


def _op(value):
    """Opérateur normalisé : minuscules, chaîne vide = absent."""
    return str(value).strip().lower() or None if value is not None else None


def match_status(version: str, operator: dict) -> str:
    """MATCH si `version` est dans la plage affectée, NO_MATCH sinon, UNKNOWN
    si un opérateur de borne n'est pas reconnu (jamais compté vulnérable)."""
    if not version:
        return NO_MATCH
    minv = operator.get("min_version")
    maxv = operator.get("max_version")
    min_op = _op(operator.get("min_operator"))
    max_op = _op(operator.get("max_operator"))

    # Aucune borne de version exploitable : ne PAS matcher toutes les versions
    # (sinon une install à jour serait signalée vulnérable). On préfère ici ne
    # rien affirmer plutôt qu'un faux positif CVE sur données incomplètes.
    if not minv and not maxv:
        return NO_MATCH

    unknown = False
    if minv:
        c = compare_versions(version, minv)
        if min_op not in _MIN_OPS:
            unknown = True
        elif min_op == "gt" and not (c > 0):
            return NO_MATCH
        elif min_op in ("ge", None) and c < 0:
            return NO_MATCH
    if maxv:
        c = compare_versions(version, maxv)
        if max_op not in _MAX_OPS:
            unknown = True
        elif max_op == "lt" and not (c < 0):
            return NO_MATCH
        elif max_op in ("le", None) and c > 0:
            return NO_MATCH
    return UNKNOWN if unknown else MATCH


def matches(version: str, operator: dict) -> bool:
    """True si `version` est dans la plage affectée décrite par `operator`.

    Un opérateur inconnu ne matche pas (voir `unverifiable_for`)."""
    return match_status(version, operator) == MATCH


def _extract_vuln(entry: dict) -> Vuln:
    impact = entry.get("impact") or {}
    cvss = impact.get("cvss") if isinstance(impact, dict) else None
    score = None
    vector = ""
    if isinstance(cvss, dict):
        try:
            score = float(cvss.get("score")) if cvss.get("score") not in (None, "") else None
        except (TypeError, ValueError):
            score = None
        vector = cvss.get("vector") or ""
    sources = entry.get("source") or []
    cve_ids = [s.get("id") for s in sources if str(s.get("id", "")).upper().startswith("CVE-")]
    refs = [s.get("link") for s in sources if s.get("link")]
    op = entry.get("operator") or {}
    maxv = op.get("max_version") or None
    max_op = _op(op.get("max_operator"))
    # Champ explicite de version corrigée, s'il est fourni par la fiche.
    explicit = (entry.get("fixed_in") or op.get("fixed_in")
                or op.get("fixed_version") or None)
    unfixed = str(op.get("unfixed") or "").strip() == "1"
    fixed_in, last_affected = explicit, None
    if not fixed_in and maxv:
        if max_op == "lt":
            fixed_in = maxv          # borne stricte : première version saine
        elif max_op in ("le", None):
            last_affected = maxv     # borne inclusive : dernière vulnérable
    return Vuln(
        title=entry.get("name") or "Vulnérabilité",
        cve_ids=cve_ids,
        cvss_score=score,
        cvss_vector=vector,
        fixed_in=fixed_in,
        refs=refs,
        last_affected=last_affected,
        unfixed=unfixed and not fixed_in,
        operator=dict(op),
    )


def fixed_in_label(v: Vuln) -> str:
    """Libellé « Corrigé dans » honnête : une borne inclusive ne donne pas la
    version corrigée."""
    if v.fixed_in:
        return str(v.fixed_in)
    if v.unfixed:
        return "aucun correctif publié"
    if v.last_affected:
        return f"corrigé après {v.last_affected} (version exacte inconnue)"
    return "voir source"


def vulnerabilities_for(payload: dict, version: str) -> List[Vuln]:
    """Liste des vulnérabilités du payload wpvulnerability affectant `version`."""
    data = (payload or {}).get("data") or {}
    vulns = data.get("vulnerability") or []
    return [_extract_vuln(e) for e in vulns
            if match_status(version, e.get("operator") or {}) == MATCH]


def unverifiable_for(payload: dict, version: str) -> List[Vuln]:
    """Fiches non appariées faute d'opérateur reconnu : à vérifier à la main."""
    data = (payload or {}).get("data") or {}
    vulns = data.get("vulnerability") or []
    return [_extract_vuln(e) for e in vulns
            if match_status(version, e.get("operator") or {}) == UNKNOWN]
