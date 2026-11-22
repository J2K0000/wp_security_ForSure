"""Verrouille la classification historique pour les findings NON annotés.

Garantit que l'ajout de la priorité finding > message > check n'a rien changé
pour les findings qui ne portent pas d'access_class.
"""
from wp_security_forsure.scanner.reporters.impact import classify

# (check_name, message) -> classe attendue (comportement d'avant chantier A)
CASES = [
    ("rest_api", "user enumeration via /wp/v2/users", "pii"),
    ("rest_api", "CORS access-control-allow-origin reflété", "prive"),
    ("wp_features", "xmlrpc pingback.ping activé", "prive"),
    ("database_exposure", "dump .sql téléchargeable", "prive"),
    ("file_exposure", "wp-config.php lisible", "secrets"),
    ("ssl_tls", "TLS 1.0 accepté", "recon"),
    ("security_headers", "CSP absente", "recon"),
    ("rest_batch", "wp2shell RCE pré-auth", "controle"),
    ("takeover", "NXDOMAIN dangling CNAME", "controle"),
    ("fingerprint", "version WordPress 6.1 détectée", "recon"),
]


def test_unannotated_findings_keep_historical_classification():
    for check, msg, expected in CASES:
        got = classify(check, msg, {"message": msg})  # pas d'access_class
        assert got == expected, f"{check}/{msg!r}: {got} != {expected}"
