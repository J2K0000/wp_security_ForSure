"""Statut d'exécution des contrôles et complétude de l'audit.

Un contrôle qui plante, ou une cible injoignable, ne doit jamais passer pour un
contrôle conforme. Le moteur pose donc sur chaque ``CheckResult`` un statut
``ok`` ou ``error``. Un contrôle de niveau 2 (chemins devinés) non lancé faute
de ``--authorized`` reçoit ``skipped`` : ni échec ni conformité, il ne compte
ni dans les conformes ni dans les erreurs et ne change pas le code de sortie.
``CheckResult`` (checks/base.py) ne déclare pas encore ce champ : il est posé comme attribut d'instance et lu ici avec la valeur par
défaut ``ok``, ce qui reste compatible avec un futur champ déclaré.
"""

from .access_tiers import SKIPPED_LABEL

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"

STATUS_LABELS = {
    STATUS_OK: "Contrôle réalisé",
    STATUS_ERROR: "Contrôle non réalisé (erreur)",
    STATUS_SKIPPED: SKIPPED_LABEL,
}
ERROR_LABEL = STATUS_LABELS[STATUS_ERROR]


def get_status(result) -> str:
    """Statut d'un résultat (``ok`` par défaut)."""
    return getattr(result, "status", None) or STATUS_OK


def set_status(result, status: str):
    """Pose le statut sur le résultat et le renvoie (chaînable)."""
    if status not in STATUS_LABELS:
        raise ValueError(f"statut invalide: {status!r}")
    result.status = status
    return result


def is_error(result) -> bool:
    return get_status(result) == STATUS_ERROR


def error_results(results) -> list:
    return [r for r in results if is_error(r)]


def skip_label(result) -> str:
    """Pourquoi un contrôle n'a pas été lancé : faute de --authorized par
    défaut, ou passe facultative non demandée (attribut ``skip_reason``)."""
    return getattr(result, "skip_reason", None) or SKIPPED_LABEL


def is_skipped(result) -> bool:
    return get_status(result) == STATUS_SKIPPED


def skipped_results(results) -> list:
    return [r for r in results if is_skipped(r)]


def ok_results(results) -> list:
    """Contrôles réalisés (ni en erreur, ni non lancés faute de --authorized)."""
    return [r for r in results if get_status(r) == STATUS_OK]


def audit_is_complete(results) -> bool:
    """Complet = au moins un contrôle exécuté et aucun en erreur. Un contrôle
    « skipped » est neutre : il ne rend l'audit ni complet ni incomplet."""
    return bool(ok_results(results)) and not error_results(results)


def incomplete_label(results) -> str:
    """Phrase courte « audit incomplet » pour les rapports."""
    errors = error_results(results)
    if not errors and not ok_results(results):
        return "Audit incomplet : aucun contrôle exécuté."
    return (f"Audit incomplet : {len(errors)} contrôle(s) non réalisé(s) "
            "(erreur ou cible injoignable).")
