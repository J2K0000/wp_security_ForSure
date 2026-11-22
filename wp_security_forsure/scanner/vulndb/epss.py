"""Chargeur d'un snapshot EPSS local (offline).

EPSS = probabilité d'exploitation dans les 30 jours (FIRST.org). Le fichier
`epss.csv` (dossier de cache utilisateur, commande refresh-epss) suit le format
officiel : lignes de commentaire préfixées '#' (dont `score_date:` qui date le
snapshot), une ligne d'en-tête `cve,epss,percentile`, puis les données.
"""
import csv
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

_SCORE_DATE_RE = re.compile(r"score_date:(\d{4})-(\d{2})-(\d{2})")


class EpssIndex:
    """Index CVE (majuscules) -> probabilité EPSS (float).

    `present` : snapshot chargé avec au moins une ligne exploitable.
    `snapshot_date` : date du snapshot (`score_date` du fichier, à défaut la
    date de modification du fichier, cf. `date_source`), ou None si absent.
    """

    def __init__(self, mapping: dict, snapshot_date: Optional[date] = None,
                 date_source: Optional[str] = None, path=None):
        self._m = mapping
        self.present = bool(mapping)
        self.snapshot_date = snapshot_date if self.present else None
        self.date_source = date_source if self.present else None
        self.path = path

    def score_for(self, cve_ids: Optional[Iterable[str]]) -> Optional[float]:
        """Probabilité EPSS max parmi `cve_ids`, ou None si aucune connue."""
        if not cve_ids:
            return None
        scores = [self._m[c.upper()] for c in cve_ids if c and c.upper() in self._m]
        return max(scores) if scores else None


def load_epss(path) -> EpssIndex:
    """Charge le snapshot EPSS. Fichier absent/illisible -> index vide."""
    p = Path(path)
    mapping = {}
    snapshot_date, date_source = None, None
    if not p.exists():
        return EpssIndex(mapping, path=p)
    try:
        with open(p, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row:
                    continue
                if row[0].startswith("#"):
                    m = _SCORE_DATE_RE.search(",".join(row))
                    if m and snapshot_date is None:
                        try:
                            snapshot_date = date(*(int(g) for g in m.groups()))
                            date_source = "score_date"
                        except ValueError:
                            pass
                    continue
                if row[0].strip().lower() == "cve":
                    continue
                try:
                    mapping[row[0].strip().upper()] = float(row[1])
                except (IndexError, ValueError):
                    continue
        if snapshot_date is None:
            snapshot_date = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).date()
            date_source = "mtime"
    except OSError:
        return EpssIndex({}, path=p)
    return EpssIndex(mapping, snapshot_date, date_source, path=p)
