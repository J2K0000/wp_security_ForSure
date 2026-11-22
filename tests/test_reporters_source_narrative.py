"""Regression : html_reporter / terminal_reporter doivent honorer le narratif
`impact` porte a la source par le finding, pas seulement le deriver du message.

Meme idee que le test json_reporter (Task 3) : on construit un finding dont le
message est opaque ("Constat interne #42", ne matche AUCUN mot-cle de
classification/narratif) mais qui porte access_class="controle" +
impact={"data": "SOURCE-WEBSHELL", ...} a la source. Si le reporter appelle
narrative(check_name, message) SANS le finding, il retombe sur la classe
"recon" et un narratif generique, le texte source "SOURCE-WEBSHELL"
n'apparait jamais dans la sortie.
"""

from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter
from wp_security_forsure.scanner.reporters.terminal_reporter import TerminalReporter


def _finding_with_source_narrative():
    # check_name inconnu de _CLASS_BY_CHECK + message sans mot-cle => une
    # classification/narratif derives du message tomberaient sur "recon" et
    # le narratif generique recon, jamais sur "controle" / SOURCE-WEBSHELL.
    r = CheckResult("custom_check_xyz", "Titre test", "desc", "HIGH", True)
    r.add_finding(
        "Constat interne #42",
        severity="HIGH",
        confidence="confirmed",
        access_class="controle",
        impact={
            "data": "SOURCE-WEBSHELL",
            "path": "Chemin source specifique porte par le finding",
            "enables": "Controle total source porte par le finding",
        },
    )
    return r


def test_html_reporter_uses_source_narrative_not_message_derived():
    out = HTMLReporter([_finding_with_source_narrative()], "https://cible.test", {}).generate()

    # Le narratif source doit apparaitre, dans le resume dirigeant (top
    # priorites), dans le bloc "surface d'exposition" et dans le detail du
    # constat : 3 sites d'appel a narrative() dans html_reporter.
    assert out.count("SOURCE-WEBSHELL") == 3

    # Coherence visible : le finding est bucketise "controle" par
    # exposure_surface (deja finding-aware) ET son badge par-item dans la
    # section Constats doit aussi afficher "controle" (pas "recon" derive du
    # seul message). Sans le fix, seul le badge de bucket porte "controle".
    assert out.count('class="chip controle"') == 2


def test_terminal_reporter_uses_source_narrative_not_message_derived(capsys):
    TerminalReporter([_finding_with_source_narrative()], "https://cible.test", {}).generate()
    captured = capsys.readouterr()
    assert "SOURCE-WEBSHELL" in captured.out
