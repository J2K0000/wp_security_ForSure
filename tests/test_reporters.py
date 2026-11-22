import html
import json
from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.reporters import html_reporter as html_reporter_module
from wp_security_forsure.scanner.reporters import impact as impact_module
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter


def _results():
    r = CheckResult("c", "T", "d", "HIGH", True)
    r.add_finding("<b>xss</b>", severity="HIGH", confidence="confirmed")
    r.add_finding("maybe", severity="MEDIUM", confidence="potential")
    return [r]


def test_json_carries_confidence():
    out = JSONReporter(_results(), "https://cible.test", {}).generate()
    data = json.loads(out)
    confs = [f["confidence"] for f in data["results"][0]["findings"]]
    assert confs == ["confirmed", "potential"]


def test_html_escapes_finding_message():
    out = HTMLReporter(_results(), "https://cible.test", {}).generate()
    assert "<b>xss</b>" not in out
    assert "&lt;b&gt;xss&lt;/b&gt;" in out


def test_html_uses_max_severity_not_class_default():
    from wp_security_forsure.scanner.checks.base import CheckResult
    from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter
    # Un check dont la severite de CLASSE serait CRITICAL mais qui ne produit qu'un INFO
    r = CheckResult("c", "T", "d", "CRITICAL", True)
    r.add_finding("juste une info", severity="INFO", confidence="confirmed")
    out = HTMLReporter([r], "https://cible.test", {}).generate()
    # Le badge de check ne doit pas afficher CRITICAL pour un check sans finding critique
    assert 'class="check-status">CRITICAL' not in out


def test_html_reporter_has_no_independent_impact_taxonomy():
    """impact.py est la source unique de vérité du narratif d'impact.

    html_reporter ne doit plus définir sa propre table mots-clés -> texte
    d'impact (_IMPACT_MAP / _impact()) : ce serait une seconde taxonomie
    qui peut driver de celle d'impact.py. Seule la classification CWE
    (_CWE_MAP), qui est un référentiel distinct, peut subsister.
    """
    assert not hasattr(html_reporter_module, "_IMPACT_MAP")
    assert not hasattr(html_reporter_module, "_impact")
    assert not hasattr(html_reporter_module, "_SEV_IMPACT")


def test_html_reporter_narrative_matches_impact_single_source_of_truth():
    """Le narratif rendu par le HTML reporter doit être EXACTEMENT celui que
    renvoie impact.narrative() pour le même (check_name, message, finding) -
    preuve qu'il n'existe pas de dérivation indépendante dans le reporter.
    """
    r = CheckResult("wp_features", "T", "d", "HIGH", True)
    r.add_finding(
        "REST API exposes user list (4 users)",
        severity="HIGH",
        confidence="confirmed",
    )
    finding = r.findings[0]
    expected = impact_module.narrative("wp_features", finding["message"], finding)

    out = HTMLReporter([r], "https://cible.test", {}).generate()

    assert html.escape(expected["data"]) in out
    assert html.escape(expected["path"]) in out
    assert html.escape(expected["enables"]) in out
    assert f'class="chip {expected["classe"]}"' in out
