"""Terminal Reporter : sortie colorée dans le terminal."""

from typing import List, Optional, TextIO
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.panel import Panel
from rich import box

from . import BaseReporter
from ..checks.base import CheckResult, SEVERITIES
from ..access_tiers import AUTHORIZED_WARNING, access_level
from ..status import (ERROR_LABEL, audit_is_complete, error_results, is_error,
                      incomplete_label, is_skipped, ok_results, skip_label,
                      skipped_results)
from ..vulndb import freshness
from .guidance import (RECOMMENDATIONS_TITLE, audit_limits_block, incident_block,
                       recommendations_block)
from .impact import exposure_surface, narrative

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "white",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️",
    "PASSED": "✅",
    "ERROR": "❌",
}


def _e(value) -> str:
    """Texte issu de la cible : échappé pour ne jamais être lu comme balisage Rich."""
    return escape(str(value or ""))


def _incident_lines(block: dict) -> list:
    """Corps du bloc de réponse à incident (texte Rich échappé)."""
    lines = [f"[bold]{_e(block['lead'])}[/]"]
    for ind in block["indicators"][:8]:
        lines.append(f"  [dim]Indice :[/] {_e(ind['message'])} "
                     f"[dim]({_e(ind['check'])}, {_e(ind['severity'])})[/]")
    lines += [f"  {i}. {_e(step)}" for i, step in enumerate(block["steps"], 1)]
    lines.append(f"[bold]{_e(block['warning'])}[/]")
    return lines


def _print_guidance_annex(console: Console, incident: dict) -> None:
    """Annexes communes (reporters/guidance.py) : recommandation 2FA, réponse
    à incident si elle n'est pas en tête, limites de l'audit."""
    for rec in recommendations_block():
        console.print(f"\n[bold]{_e(RECOMMENDATIONS_TITLE)} : {_e(rec['title'])}[/]")
        console.print(f"  {_e(rec['text'])}")
    if not incident["highlighted"]:
        console.print(f"\n[bold]{_e(incident['title'])}[/]")
        for line in _incident_lines(incident):
            console.print(f"  {line}")
    limits = audit_limits_block()
    console.print(f"\n[bold]{_e(limits['title'])}[/]")
    console.print(f"  [dim]{_e(limits['lead'])}[/]")
    for item in limits["items"]:
        console.print(f"  - {_e(item)}")


class TerminalReporter(BaseReporter):
    """Rapport formaté pour le terminal avec Rich."""

    def generate(self, stream: Optional[TextIO] = None) -> str:
        """Affiche le rapport (sur `stream`, sinon la sortie standard) et
        renvoie son texte brut, pour l'écrire dans un fichier (--output)."""
        console = Console(file=stream, record=True)
        done = ok_results(self.results)
        errors = error_results(self.results)
        skipped = skipped_results(self.results)
        level = access_level(self.config)

        console.print()
        if level["authorized"]:
            console.print(Panel(f"[bold]{_e(AUTHORIZED_WARNING)}[/]",
                                title="AVERTISSEMENT", border_style="red"))
        console.print(Panel(
            f"[bold white]wp_security_ForSure : audit de sécurité WordPress[/]\n"
            f"[dim]Cible :[/] {_e(self.target)}\n"
            f"[dim]Checks exécutés :[/] {len(self.results) - len(skipped)}\n"
            f"[dim]Niveau d'accès :[/] {_e(level['label'])}",
            title="📋 RAPPORT D'AUDIT",
            border_style="cyan",
        ))

        # Résumé exécutif (les contrôles en erreur ne comptent ni comme OK
        # ni comme vulnérabilités)
        passed = sum(1 for r in done if r.passed and not r.findings)
        warnings = sum(1 for r in done if not r.passed and r.findings)
        criticals = sum(1 for r in done
                        if not r.passed and r.max_severity == "CRITICAL")
        highs = sum(1 for r in done
                    if not r.passed and r.max_severity == "HIGH")

        console.print(f"\n[bold]Résumé :[/]")
        console.print(f"  ✅ {passed} checks OK")
        console.print(f"  ⚠️  {warnings} vulnérabilités potentielles")

        if criticals:
            console.print(f"  [red bold]🔴 {criticals} critiques[/]")
        if highs:
            console.print(f"  [orange1 bold]🟠 {highs} hautes[/]")
        if errors:
            console.print(f"  [bold]❌ {len(errors)} contrôle(s) non réalisé(s) (erreur)[/]")
        if skipped:
            console.print(f"  [dim]{len(skipped)} contrôle(s) non réalisé(s) : nécessite "
                          "--authorized (recherche de chemins non liés)[/]")
        if audit_is_complete(self.results):
            console.print("  [dim]Audit complet[/]")
        else:
            console.print(f"  [bold]{_e(incomplete_label(self.results))}[/] "
                          "L'absence de constat ne vaut pas preuve d'absence de faille.")
        console.print()

        # Surface d'exposition : accès PROUVÉS groupés par classe (du pire au moindre)
        surface = exposure_surface(done)
        if surface:
            console.print("[bold]🎯 Surface d'exposition (accès prouvés) : ce "
                          "qu'un attaquant peut atteindre[/]")
            for b in surface:
                console.print(f"  {b['emoji']} [bold]{_e(b['label'])}[/] "
                              f"[dim]({len(b['findings'])})[/]")
                for cn, f in b["findings"]:
                    n = narrative(cn, f.get("message", ""), f)
                    console.print(f"     • {_e(f['message'])}  [dim]→ {_e(n['data'])}[/]")
            console.print()

        # Réponse à incident mise en avant : indice de compromission relevé.
        incident = incident_block(self.results)
        if incident["highlighted"]:
            console.print(Panel("\n".join(_incident_lines(incident)),
                                title=_e(incident["title"].upper()),
                                border_style="red"))
            console.print()

        # Détail par check : on affiche la sévérité RÉELLE (max des findings)
        for result in self.results:
            if is_skipped(result):
                console.print(f"\n[dim]{_e('[NON RÉALISÉ]')}[/] [bold]{_e(result.title)}[/] : "
                              f"{_e(skip_label(result))}")
                continue
            if is_error(result):
                console.print(f"\n{SEVERITY_ICONS['ERROR']} [bold]{_e('[ERREUR]')}[/] "
                              f"[bold]{_e(result.title)}[/] : {ERROR_LABEL}")
                for finding in result.findings:
                    console.print(f"  [dim]→ {_e(finding.get('message'))}[/]")
                continue
            display_sev = result.max_severity if result.findings else "INFO"
            icon = SEVERITY_ICONS.get(display_sev, "📋")
            color = SEVERITY_COLORS.get(display_sev, "white")
            status = SEVERITY_ICONS["PASSED"] if result.passed else icon

            console.print(f"\n[{color}]{status} [{color}][[bold]{display_sev}[/]][/] "
                          f"[bold]{_e(result.title)}[/]")
            console.print(f"  [dim]{_e(result.description)}[/dim]")

            for finding in result.findings:
                fcolor = SEVERITY_COLORS.get(finding["severity"], "white")
                ficom = SEVERITY_ICONS.get(finding["severity"], "•")
                tag = "" if finding.get("confidence", "confirmed") == "confirmed" else "[dim](à vérifier)[/] "
                console.print(f"  [{fcolor}]{ficom} {tag}{_e(finding['message'])}[/]")
                if finding.get("evidence"):
                    console.print(f"    [dim]→ {_e(finding['evidence'][:150])}[/]")
                if finding.get("url"):
                    console.print(f"    [dim]→ {_e(finding['url'])}[/]")

        # Tableau récapitulatif final
        table = Table(box=box.SIMPLE, title="Récapitulatif par sévérité")
        table.add_column("Sévérité", style="bold")
        table.add_column("Nombre", justify="right")

        for sev in SEVERITIES:
            count = sum(1 for r in done
                        for f in r.findings
                        if f["severity"] == sev)
            if count > 0:
                table.add_row(f"{SEVERITY_ICONS.get(sev, '')} {sev}", str(count))

        if table.row_count > 0:
            console.print()
            console.print(table)

        # Fraîcheur des données de vulnérabilités
        sources = freshness.from_results(self.results)
        console.print()
        console.print(f"[dim]Données CVE : {_e(sources['cve']['label'])}[/]")
        console.print(f"[dim]{_e(sources['epss']['label'])}[/]")
        console.print(f"[dim]{_e(sources['kev']['label'])}[/]")

        _print_guidance_annex(console, incident)

        console.print()
        return console.export_text()
