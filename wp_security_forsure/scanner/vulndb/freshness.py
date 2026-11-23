"""Fraîcheur des données de vulnérabilités : source des CVE, date des fiches
en cache utilisées, âge du snapshot EPSS et date de l'instantané CISA KEV.
Produit par vulnerability_scan, lu par les reporters JSON, HTML et terminal
(structure unique)."""

import time
from datetime import datetime, timezone
from typing import Iterable, Optional

from .kev import KEV_SOURCE

CVE_SOURCE = "wpvulnerability.net"
EPSS_ABSENT_LABEL = ("EPSS absent : probabilité d'exploitation non prise en "
                     "compte (commande refresh-epss pour la télécharger)")
EPSS_NOT_USED_LABEL = "EPSS non consulté : aucun composant versionné à apparier"
KEV_ABSENT_LABEL = "KEV absent : lancer refresh-kev"
KEV_NOT_USED_LABEL = "KEV non consulté : aucun composant versionné à apparier"


def _iso(ts: Optional[int]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), timezone.utc).isoformat(timespec="seconds")


def _day(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), timezone.utc).date().isoformat()


def cve_section(entries: Iterable[dict], missing: int = 0) -> dict:
    """`entries` : fiches consultées {type, slug, fetched_at (epoch|None), stale}."""
    entries = list(entries)
    stamps = [e["fetched_at"] for e in entries if e.get("fetched_at") is not None]
    stale = sum(1 for e in entries if e.get("stale"))
    if not entries:
        label = f"{CVE_SOURCE} : aucune fiche consultée"
    elif not stamps:
        label = (f"{CVE_SOURCE} : {len(entries)} fiche(s) consultée(s), "
                 "date de mise en cache inconnue")
    else:
        first, last = _day(min(stamps)), _day(max(stamps))
        when = f"le {first}" if first == last else f"entre le {first} et le {last}"
        label = f"{CVE_SOURCE} : {len(entries)} fiche(s) mise(s) en cache {when}"
    if stale:
        label += f", dont {stale} périmée(s) (réseau indisponible)"
    if missing:
        label += f" ; {missing} composant(s) sans fiche (réseau et cache indisponibles)"
    return {
        "source": CVE_SOURCE,
        "entries": [{"type": e.get("type"), "slug": e.get("slug"),
                     "fetched_at": _iso(e.get("fetched_at")),
                     "stale": bool(e.get("stale"))} for e in entries],
        "oldest_fetched_at": _iso(min(stamps)) if stamps else None,
        "newest_fetched_at": _iso(max(stamps)) if stamps else None,
        "stale_count": stale,
        "missing_count": missing,
        "label": label,
    }


def epss_section(index, now: Optional[float] = None) -> dict:
    """État du snapshot EPSS utilisé (`index` None = non consulté)."""
    if index is None:
        return {"present": None, "snapshot_date": None, "age_days": None,
                "date_source": None, "label": EPSS_NOT_USED_LABEL}
    if not getattr(index, "present", False):
        return {"present": False, "snapshot_date": None, "age_days": None,
                "date_source": None, "label": EPSS_ABSENT_LABEL}
    date = getattr(index, "snapshot_date", None)
    age = None
    if date is not None:
        today = datetime.fromtimestamp(now if now is not None else time.time(),
                                       timezone.utc).date()
        age = (today - date).days
    if date is None:
        label = "Snapshot EPSS présent, date inconnue"
    else:
        label = f"Snapshot EPSS du {date.isoformat()} (âge : {age} jours)"
    return {"present": True,
            "snapshot_date": date.isoformat() if date else None,
            "age_days": age,
            "date_source": getattr(index, "date_source", None),
            "label": label}


def kev_section(index, now: Optional[float] = None) -> dict:
    """État de l'instantané CISA KEV utilisé (`index` None = non consulté)."""
    empty = {"source": KEV_SOURCE, "present": None, "catalog_version": None,
             "snapshot_date": None, "age_days": None, "date_source": None,
             "entries": None}
    if index is None:
        return dict(empty, label=KEV_NOT_USED_LABEL)
    if not getattr(index, "present", False):
        return dict(empty, present=False, label=KEV_ABSENT_LABEL)
    snap = getattr(index, "snapshot_date", None)
    age = None
    if snap is not None:
        today = datetime.fromtimestamp(now if now is not None else time.time(),
                                       timezone.utc).date()
        age = (today - snap).days
    version = getattr(index, "catalog_version", None)
    if snap is None:
        label = "Catalogue CISA KEV présent, date inconnue"
    else:
        label = f"Catalogue CISA KEV du {snap.isoformat()} (âge : {age} jours"
        label += f", version {version})" if version else ")"
    return dict(empty, present=True, catalog_version=version,
                snapshot_date=snap.isoformat() if snap else None,
                age_days=age, date_source=getattr(index, "date_source", None),
                entries=getattr(index, "count", None), label=label)


def build(entries, epss_index, now: Optional[float] = None, missing: int = 0,
          kev_index=None) -> dict:
    return {"cve": cve_section(entries, missing=missing),
            "epss": epss_section(epss_index, now),
            "kev": kev_section(kev_index, now)}


def not_consulted() -> dict:
    """Valeur par défaut quand vulnerability_scan n'a pas tourné."""
    cve = cve_section([])
    cve["label"] = (f"{CVE_SOURCE} : non consulté "
                    "(contrôle vulnerability_scan non exécuté)")
    return {"cve": cve, "epss": epss_section(None), "kev": kev_section(None)}


def from_results(results) -> dict:
    """Données de fraîcheur portées par un résultat (vulnerability_scan)."""
    for r in results or []:
        ds = getattr(r, "data_sources", None)
        if ds:
            return ds
    return not_consulted()
