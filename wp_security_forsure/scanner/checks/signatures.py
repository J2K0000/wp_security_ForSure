"""Signatures & détecteurs partagés, évitent les faux positifs récurrents."""
import re

# ── Page "WordPress déjà installé" (install.php sur un site opérationnel) ──
_ALREADY_INSTALLED_PATTERNS = [
    r"déj[àa]\s+install",            # FR : "Déjà installé"
    r"already\s+installed",          # EN
    r"est\s+déj[àa]\s+install",      # FR variante
    r"you\s+appear\s+to\s+have\s+already",
]

# Indices d'un VRAI formulaire d'installation vierge
_INSTALL_FORM_MARKERS = ["weblog_title", "admin_email", "admin_password"]


def is_already_installed(body: str) -> bool:
    """True si la page est l'écran 'WordPress déjà installé' (pas une install ouverte)."""
    if not body:
        return False
    low = body.lower()
    if any(m in low for m in _INSTALL_FORM_MARKERS):
        return False
    return any(re.search(p, low) for p in _ALREADY_INSTALLED_PATTERNS)


# ── Contenu bénin après </html> (commentaires de cache) ───────────────────
_BENIGN_AFTER_HTML = [
    r"cached by litespeed",
    r"page caching by",
    r"performance optimized by w3 total cache",
    r"dynamic page generated in",
    r"super cache",
    r"cache file was created",
]


def is_benign_after_html(text: str) -> bool:
    """True si le contenu après </html> est un commentaire de cache connu (non malveillant)."""
    if not text:
        return True
    low = text.lower()
    # Un commentaire HTML seul et connu = bénin
    stripped = low.strip()
    if stripped.startswith("<!--") and any(k in low for k in _BENIGN_AFTER_HTML):
        return True
    return any(k in low for k in _BENIGN_AFTER_HTML) and "<script" not in low


XMLRPC_GET_SIGNATURE = "XML-RPC server accepts POST requests only."


def xmlrpc_server_active(body: str) -> bool:
    """True si un GET sur xmlrpc.php a été servi par le serveur XML-RPC de
    WordPress (IXR), qui répond à toute méthode autre que POST par ce message.

    Preuve passive que XML-RPC est actif, sans envoyer le moindre appel.
    """
    return bool(body) and XMLRPC_GET_SIGNATURE.lower() in body.lower()


def matches_baseline(status: int, size: int, body_prefix: str, baseline: dict,
                     size_tolerance: float = 0.15) -> bool:
    """True si une réponse est ≈ la baseline GET (même statut, taille ~identique, même début).

    Sert à détecter qu'un serveur renvoie la même page pour toute méthode HTTP
    (ex : LiteSpeed renvoie la home pour PUT/DELETE/CONNECT)."""
    if status != baseline.get("status"):
        return False
    base_size = baseline.get("size", 0)
    if base_size:
        delta = abs(size - base_size) / base_size
        if delta > size_tolerance:
            return False
    base_prefix = (baseline.get("prefix") or "")[:64]
    return (body_prefix or "")[:64] == base_prefix
