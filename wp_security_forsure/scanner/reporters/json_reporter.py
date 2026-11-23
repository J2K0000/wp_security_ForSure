"""JSON Reporter : export structuré pour traitement automatique."""

import json

from wp_security_forsure import TOOL_NAME, __version__
from datetime import datetime, timezone
from . import BaseReporter
from .guidance import audit_limits_block, incident_block, recommendations_block
from .impact import exposure_surface, narrative
from ..redact import redact_obj
from ..access_tiers import access_level
from ..status import (STATUS_LABELS, STATUS_SKIPPED, audit_is_complete,
                      error_results, get_status, incomplete_label, ok_results,
                      skipped_results)
from ..vulndb import freshness


class JSONReporter(BaseReporter):
    """Rapport en JSON."""

    @staticmethod
    def _finding_json(check_name, f):
        entry = {
            "message": f["message"],
            "severity": f["severity"],
            "confidence": f.get("confidence", "confirmed"),
            "evidence": f.get("evidence", ""),
            "url": f.get("url", ""),
        }
        # Narratif d'accès attaquant pour les constats réels (hors INFO).
        if f["severity"] != "INFO":
            entry["impact"] = narrative(check_name, f["message"], f)
        if f.get("scoring"):
            entry["scoring"] = f["scoring"]
        if f.get("kev"):
            entry["kev"] = f["kev"]   # catalogue CISA KEV : exploitation active
        return entry

    def generate(self) -> str:
        # Un contrôle en erreur n'est ni conforme ni porteur de constats :
        # il est listé avec son statut et rend l'audit incomplet.
        done = ok_results(self.results)
        errors = error_results(self.results)
        complete = audit_is_complete(self.results)
        data = {
            "scan": {
                "target": self.target,
                "date": datetime.now(timezone.utc).isoformat(),
                "tool": f"{TOOL_NAME} {__version__}",
                "checks_count": len(self.results),
                "access_level": access_level(self.config),
            },
            "results": [],
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in done if r.passed and not r.findings),
                "errors": len(errors),
                "skipped": len(skipped_results(self.results)),
                "audit_status": "complet" if complete else "incomplet",
                "audit_status_label": ("Audit complet" if complete
                                       else incomplete_label(self.results)),
                "findings": sum(len(r.findings) for r in done),
                "by_severity": {},
            },
            "data_sources": freshness.from_results(self.results),
        }

        for result in self.results:
            status = get_status(result)
            r_data = {
                "check_name": result.check_name,
                "title": result.title,
                "status": status,
                "status_label": STATUS_LABELS[status],
                "severity": result.severity,
                # Non lancé faute de --authorized : ni échec ni conformité.
                "passed": None if status == STATUS_SKIPPED else result.passed,
                "max_finding_severity": result.max_severity,
                "findings": [
                    self._finding_json(result.check_name, f)
                    for f in result.findings
                ],
            }
            data["results"].append(r_data)

        # Statistiques (contrôles réalisés seulement)
        for result in done:
            for f in result.findings:
                sev = f["severity"]
                data["summary"]["by_severity"][sev] = \
                    data["summary"]["by_severity"].get(sev, 0) + 1

        data["summary"]["by_confidence"] = {
            "confirmed": sum(1 for r in done for f in r.findings
                             if f.get("confidence", "confirmed") == "confirmed"),
            "potential": sum(1 for r in done for f in r.findings
                             if f.get("confidence") == "potential"),
        }

        # ── Surface d'exposition : accès PROUVÉS groupés par classe ──
        data["exposure_surface"] = [
            {
                "class": b["key"],
                "label": b["label"],
                "description": b["blurb"],
                "findings": [
                    {"check": cn, "message": ff["message"],
                     "severity": ff["severity"],
                     "impact": narrative(cn, ff["message"], ff)}
                    for cn, ff in b["findings"]
                ],
            }
            for b in exposure_surface(done)
        ]

        # ── Textes de conduite communs aux trois rapports (guidance.py) ──
        # incident_response : mis en avant (placement « en_tete ») sur indice
        # de compromission, sinon annexe « En cas de compromission ».
        data["incident_response"] = incident_block(self.results)
        data["audit_limits"] = audit_limits_block()
        data["recommendations"] = recommendations_block()

        # Dernier passage avant écriture : masquage des secrets sur tout le
        # document (défense en profondeur, en plus du masquage à la source).
        return json.dumps(redact_obj(data), indent=2, ensure_ascii=False)
