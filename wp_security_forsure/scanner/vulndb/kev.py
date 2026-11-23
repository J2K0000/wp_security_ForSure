"""Catalogue CISA KEV (Known Exploited Vulnerabilities) : instantané local.

Le flux officiel (licence CC0) est téléchargé par la commande opt-in
``refresh-kev`` dans le dossier de cache utilisateur (vulndb.cache.kev_path).
Pendant un audit, aucun téléchargement : on lit l'instantané s'il existe.

Format du flux : ``catalogVersion``, ``dateReleased`` et ``vulnerabilities``,
liste d'entrées portant ``cveID``, ``dateAdded``, ``dueDate``,
``knownRansomwareCampaignUse`` (``Known`` ou ``Unknown``)...
"""
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_SOURCE = "catalogue CISA KEV"

_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")


def _iso_date(value) -> Optional[date]:
    m = _DATE_RE.match(str(value or ""))
    if not m:
        return None
    try:
        return date(*(int(g) for g in m.groups()))
    except ValueError:
        return None


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: Optional[str]
    due_date: Optional[str]
    ransomware: str            # « Known » ou « Unknown », tel que publié

    def as_finding(self) -> dict:
        """Valeur du champ ``kev`` d'un constat."""
        return {"date_added": self.date_added, "due_date": self.due_date,
                "ransomware": self.ransomware}


def validate_feed(data) -> int:
    """Nombre d'entrées d'un flux KEV valide ; ValueError sinon."""
    if not isinstance(data, dict):
        raise ValueError("flux KEV invalide : objet JSON attendu")
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("flux KEV invalide : liste « vulnerabilities » absente")
    count = sum(1 for v in vulns if isinstance(v, dict) and v.get("cveID"))
    if not count:
        raise ValueError("flux KEV invalide : aucune entrée cveID")
    return count


class KevIndex:
    """Index CVE (majuscules) -> KevEntry.

    ``present`` : instantané chargé avec au moins une entrée.
    ``snapshot_date`` : date de publication du catalogue (``dateReleased``),
    à défaut date de modification du fichier (``date_source`` = ``mtime``).
    """

    def __init__(self, entries: dict, catalog_version: Optional[str] = None,
                 snapshot_date: Optional[date] = None,
                 date_source: Optional[str] = None, path=None):
        self._entries = entries
        self.present = bool(entries)
        self.catalog_version = catalog_version if self.present else None
        self.snapshot_date = snapshot_date if self.present else None
        self.date_source = date_source if self.present else None
        self.path = path
        self.count = len(entries)

    def entry_for(self, cve_ids: Optional[Iterable[str]]) -> Optional[KevEntry]:
        """Entrée KEV d'une des CVE (la plus anciennement ajoutée), ou None."""
        found = [self._entries[c.upper()] for c in (cve_ids or [])
                 if c and c.upper() in self._entries]
        if not found:
            return None
        return min(found, key=lambda e: e.date_added or "9999-99-99")


def index_from_feed(data: dict, path=None, mtime: Optional[float] = None) -> KevIndex:
    entries = {}
    for item in data.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        entries[cve] = KevEntry(
            cve_id=cve,
            date_added=(str(item["dateAdded"]) if item.get("dateAdded") else None),
            due_date=(str(item["dueDate"]) if item.get("dueDate") else None),
            ransomware=str(item.get("knownRansomwareCampaignUse") or "Unknown"),
        )
    released = _iso_date(data.get("dateReleased"))
    source = "dateReleased" if released else None
    if released is None and mtime is not None:
        released = datetime.fromtimestamp(mtime, timezone.utc).date()
        source = "mtime"
    version = data.get("catalogVersion")
    return KevIndex(entries, str(version) if version else None, released,
                    source, path=path)


def load_kev(path) -> KevIndex:
    """Charge l'instantané KEV. Fichier absent ou illisible -> index vide."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
        data = json.loads(raw)
        validate_feed(data)
        mtime = p.stat().st_mtime
    except (OSError, ValueError):
        return KevIndex({}, path=p)
    return index_from_feed(data, path=p, mtime=mtime)
