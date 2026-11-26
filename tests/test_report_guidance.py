"""SEC-17 et SEC-15 : bloc de réponse à incident (mis en avant sur indice de
compromission, sinon en annexe « En cas de compromission »), bloc « Ce que
cet audit ne peut pas voir » et recommandation 2FA, dans les trois rapports,
depuis un module unique (reporters/guidance.py)."""
import io
import json

from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.reporters import guidance
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter
from wp_security_forsure.scanner.reporters.terminal_reporter import TerminalReporter

TARGET = "https://cible.test"


def _result(check, message, severity="HIGH", confidence="confirmed"):
    r = CheckResult(check, f"Titre {check}", "d", "HIGH", True)
    r.add_finding(message, severity=severity, confidence=confidence,
                  url=f"{TARGET}/")
    return r


def _clean():
    return [_result("security_headers", "HSTS manquant", severity="MEDIUM")]


def _infected():
    return _clean() + [_result(
        "malware_detection",
        "Hidden iframe injection detected, possible malware delivery vector")]


def _terminal(results):
    buf = io.StringIO()
    text = TerminalReporter(results, TARGET, {}).generate(stream=buf)
    return " ".join(text.split())


def _json(results):
    return json.loads(JSONReporter(results, TARGET, {}).generate())


def _html(results):
    return HTMLReporter(results, TARGET, {}).generate()


# ── Déclencheur ──────────────────────────────────────────────────────────

def test_confirmed_malware_finding_triggers_incident():
    assert guidance.incident_block(_infected())["highlighted"] is True


def test_clean_report_does_not_trigger_incident():
    assert guidance.incident_block(_clean())["highlighted"] is False


def test_trigger_rules():
    cases = [
        # (check, message, severity, confidence, attendu)
        ("malware_detection", "Signature Balada", "MEDIUM", "confirmed", True),
        ("malware_detection", "Motif suspect", "HIGH", "potential", True),
        ("malware_detection", "Motif faible", "MEDIUM", "potential", False),
        ("malware_detection", "Aucun malware", "INFO", "confirmed", False),
        ("cloaking_seo_spam", "Cloaking détecté", "CRITICAL", "potential", True),
        ("nulled_plugins", "Plugin nullé", "LOW", "confirmed", True),
        # Constat d'injection, quel que soit le check.
        ("third_party_scripts", "Script externe injecté dans la page", "HIGH",
         "confirmed", True),
        # Une classe de vulnérabilité n'est pas un indice de compromission.
        ("vulnerability_scan", "Contact Form 7 : SQL Injection (CVE-2026-0001)",
         "CRITICAL", "confirmed", False),
        ("security_headers", "CSP 'base-uri' is not set, may be vulnerable to "
         "DOM clobbering via <base> tag injection", "MEDIUM", "confirmed", False),
        ("security_headers", "HSTS manquant", "HIGH", "confirmed", False),
    ]
    for check, msg, sev, conf, expected in cases:
        block = guidance.incident_block([_result(check, msg, sev, conf)])
        assert block["highlighted"] is expected, (check, msg, sev, conf)


def test_error_or_skipped_checks_do_not_trigger():
    r = _result("malware_detection", "Webshell", "CRITICAL")
    r.status = "error"
    assert guidance.incident_block([r])["highlighted"] is False


# ── Contenu ──────────────────────────────────────────────────────────────

def test_incident_steps_in_required_order():
    steps = guidance.INCIDENT_STEPS
    assert len(steps) == 7
    keys = ["hors ligne", "Changer tous les accès", "sauvegarde antérieure",
            "Mettre à jour le cœur", "intégrité côté serveur", "Remettre",
            "réexamen dans Google Search Console"]
    for step, key in zip(steps, keys):
        assert key in step, (key, step)
    for needle in ("hébergement", "SFTP", "FTP", "base de données",
                   "administrateurs", "sels", "wp-config.php", "clés d'API"):
        assert needle in steps[1], needle
    for needle in ("wp core verify-checksums", "wp plugin verify-checksums",
                   "wp-content/mu-plugins/", "drop-ins", ".user.ini",
                   "administrateurs", "options"):
        assert needle in steps[4], needle
    assert "supprimer ceux qui ne servent pas" in steps[3]
    assert "ne pas se contenter de supprimer le fichier suspect" in \
        guidance.INCIDENT_WARNING.lower()
    assert "plusieurs emplacements" in guidance.INCIDENT_WARNING


def test_audit_limits_items():
    text = " ".join(guidance.AUDIT_LIMITS)
    for needle in ("functions.php", "mu-plugins", "drop-ins", "base de données",
                   "tâches planifiées", "Referer", "JavaScript",
                   "versions masquées", "authentification", "sauvegardes",
                   "restauration", "Sécurité", "Actions manuelles",
                   "Search Console", "API", "Transparency Report"):
        assert needle in text, needle


def test_guidance_texts_have_no_em_dash():
    import inspect
    assert "\u2014" not in inspect.getsource(guidance)
    from wp_security_forsure.scanner.reporters import (
        html_reporter, json_reporter, terminal_reporter)
    for mod in (html_reporter, json_reporter, terminal_reporter):
        assert "\u2014" not in inspect.getsource(mod), mod.__name__


# ── JSON ─────────────────────────────────────────────────────────────────

def test_json_incident_block_highlighted_with_malware():
    data = _json(_infected())
    block = data["incident_response"]
    assert block["highlighted"] is True
    assert block["placement"] == "en_tete"
    assert block["steps"] == list(guidance.INCIDENT_STEPS)
    assert block["warning"] == guidance.INCIDENT_WARNING
    assert block["indicators"][0]["check"] == "malware_detection"


def test_json_incident_block_in_annex_without_indicator():
    block = _json(_clean())["incident_response"]
    assert block["highlighted"] is False
    assert block["placement"] == "annexe"
    assert block["title"] == "En cas de compromission"
    assert block["indicators"] == []
    assert block["steps"] == list(guidance.INCIDENT_STEPS)


def test_json_limits_and_2fa_always_present():
    for results in (_clean(), _infected(), []):
        data = _json(results)
        assert data["audit_limits"]["title"] == "Ce que cet audit ne peut pas voir"
        assert data["audit_limits"]["items"] == list(guidance.AUDIT_LIMITS)
        ids = [r["id"] for r in data["recommendations"]]
        assert "2fa_admins" in ids


# ── HTML ─────────────────────────────────────────────────────────────────

def test_html_incident_highlighted_before_findings_with_malware():
    out = _html(_infected())
    assert "Réponse à incident" in out
    # Juste après le verdict, avant la vue attaquant et les constats.
    assert out.index("Pour le dirigeant") < out.index("Réponse à incident") \
        < out.index("Vue attaquant") < out.index("Vulnérabilités & points")
    assert "En cas de compromission" not in out
    assert "wp core verify-checksums" in out


def test_html_incident_in_annex_without_indicator():
    out = _html(_clean())
    assert "Réponse à incident" not in out
    assert "En cas de compromission" in out
    assert out.index("Méthodologie") < out.index("En cas de compromission")


def test_html_limits_and_2fa_present():
    for results in (_clean(), _infected()):
        out = _html(results)
        assert "Ce que cet audit ne peut pas voir" in out
        assert "Transparency Report" in out
        assert "double authentification sur chaque compte administrateur" in out.lower()


# ── Terminal ─────────────────────────────────────────────────────────────

def test_terminal_incident_highlighted_with_malware():
    out = _terminal(_infected())
    assert "RÉPONSE À INCIDENT" in out
    assert out.index("RÉPONSE À INCIDENT") < out.index("Titre security_headers")
    assert "En cas de compromission" not in out


def test_terminal_incident_in_annex_without_indicator():
    out = _terminal(_clean())
    assert "RÉPONSE À INCIDENT" not in out
    assert "En cas de compromission" in out
    assert out.index("Titre security_headers") < out.index("En cas de compromission")


def test_terminal_limits_and_2fa_present():
    for results in (_clean(), _infected()):
        out = _terminal(results)
        assert "Ce que cet audit ne peut pas voir" in out
        assert "Transparency Report" in out
        assert "double authentification sur chaque compte administrateur" in out.lower()
        assert "ne se voit pas de l'extérieur" in out


def test_active_attacks_limit_and_owner_checks_in_every_report():
    """La limite principale (attaques actives non rejouées) et ce que le
    propriétaire doit vérifier lui-même figurent dans les trois rapports."""
    assert guidance.AUDIT_LIMITS[0].startswith("Les attaques actives ne sont pas rejouées")
    ids = [r["id"] for r in guidance.recommendations_block()]
    assert ids == ["2fa_admins", "login_limits", "remove_unused", "server_side"]
    for results in (_clean(), _infected()):
        term = " ".join(_terminal(results).split())
        html_out = _html(results)
        data = _json(results)
        for text in (term, html_out):
            assert "attaques actives ne sont pas rejouées" in text
            assert "Limiter les tentatives de connexion" in text
            assert "DISALLOW_FILE_EDIT" in text
        assert data["audit_limits"]["items"][0].startswith("Les attaques actives")
        assert [r["id"] for r in data["recommendations"]] == ids
