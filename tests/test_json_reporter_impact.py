"""Le JSON reporter propage le narratif porté par le finding (chantier A)."""
import json
from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter


def _reporter_with(finding_kwargs):
    r = CheckResult(check_name="forms_upload", title="Upload",
                    description="", severity="HIGH", passed=True)
    r.add_finding("upload arbitraire", **finding_kwargs)
    return JSONReporter([r], "https://cible.test", {})


def test_json_uses_finding_impact_when_present():
    imp = {"data": "Dépôt de webshell", "path": "Endpoint sans filtre",
           "enables": "RCE puis contrôle"}
    rep = _reporter_with(dict(severity="HIGH", access_class="controle",
                              impact=imp))
    data = json.loads(rep.generate())
    entry = data["results"][0]["findings"][0]
    assert entry["impact"]["data"] == "Dépôt de webshell"
    assert entry["impact"]["classe"] == "controle"


def test_json_exposure_surface_respects_finding_class():
    imp = {"data": "Dépôt de webshell", "path": "Endpoint sans filtre",
           "enables": "RCE puis contrôle"}
    rep = _reporter_with(dict(severity="HIGH", access_class="controle",
                              impact=imp))
    data = json.loads(rep.generate())
    classes = [b["class"] for b in data["exposure_surface"]]
    assert "controle" in classes
    # Le narratif de la surface d'exposition doit venir du finding (call-site
    # modifié en tâche 3), pas du matching de message.
    bloc = next(b for b in data["exposure_surface"] if b["class"] == "controle")
    assert bloc["findings"][0]["impact"]["data"] == "Dépôt de webshell"
