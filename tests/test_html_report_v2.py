"""Rapport HTML v2 : impact par finding, contrôles OK masqués en tête, synthèse."""
from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter


def _mixed():
    crit = CheckResult("brute_force_login", "Force brute", "d", "INFO", True)
    crit.add_finding("REST API exposes user list (4 users)", severity="CRITICAL")
    ok = CheckResult("nulled_plugins", "Détection de Plugins & Thèmes Nullés",
                     "d", "INFO", True)  # aucun finding = conforme
    return [crit, ok]


def test_impact_line_present():
    out = HTMLReporter(_mixed(), "https://cible.test", {}).generate()
    # Narratif d'accès attaquant par constat (donnée → chemin → permet ensuite).
    assert "Donnée / accès :" in out
    assert "Permet ensuite :" in out
    # narratif spécifique au user-enum
    assert "spear-phishing" in out
    # la synthèse « surface d'exposition » liste l'accès prouvé
    assert "Surface d'exposition" in out


def test_ok_control_not_shown_as_finding_but_in_conformes():
    out = HTMLReporter(_mixed(), "https://cible.test", {}).generate()
    # le contrôle conforme apparaît dans la section repliée (nom échappé)
    assert "Détection de Plugins &amp; Thèmes Nullés" in out
    assert "conformes" in out


def test_verdict_first_methodo_last_crescendo():
    out = HTMLReporter(_mixed(), "https://cible.test", {}).generate()
    # Entonnoir : verdict dirigeant en langage clair d'abord, méthodo en annexe.
    assert "Pour le dirigeant" in out
    assert "Niveau de risque : Critique" in out          # CRITICAL confirmé
    assert "Méthodologie" in out
    # le verdict précède la méthodologie (crescendo dirigeant → technique)
    assert out.index("Pour le dirigeant") < out.index("Méthodologie")
