"""Régression, discipline de confiance des fallbacks database_exposure.

Même contrat que file_exposure : un chemin accessible sans indicateur de
contenu réel matché est une heuristique (confidence=="potential"), et un 403
(accès refusé) n'est jamais une exposition, quelle que soit la branche
(SQL dumps, répertoires de backup plugin, phpMyAdmin/Adminer, fichiers env).
"""
import re
import responses
from wp_security_forsure.scanner.checks.database_exposure import DatabaseExposureCheck
from tests.conftest import make_check


def _mock_probe_404():
    responses.add(responses.HEAD, re.compile(r".*/wpsf-probe.*"), status=404)
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body="404 Not Found", status=404)


def _exposures(chk):
    return [f for f in chk._result.findings
            if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]


# ── 1) Fallback sans indicateur de contenu => potential, jamais confirmé ──

@responses.activate
def test_sql_dump_accessible_no_indicator_is_potential():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/dump.sql", status=200)
    responses.add(responses.GET, "https://cible.test/dump.sql",
                  body="<html>Unrelated placeholder page, nothing SQL here</html>"
                       + ("x" * 100),
                  status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_sql_dumps()
    findings = [f for f in chk._result.findings if "dump.sql" in f.get("url", "")]
    assert len(findings) == 1
    assert findings[0]["confidence"] == "potential"
    assert not (findings[0]["severity"] == "CRITICAL"
                and findings[0]["confidence"] == "confirmed")


# ── 2) 403 => aucune exposition, sur chaque branche concernée ─────────────

@responses.activate
def test_sql_dump_403_yields_no_exposure():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/dump.sql", status=403)
    responses.add(responses.GET, "https://cible.test/dump.sql",
                  body="<html>Forbidden</html>" + ("x" * 100), status=403)
    chk = make_check(DatabaseExposureCheck)
    chk._check_sql_dumps()
    assert _exposures(chk) == []


@responses.activate
def test_plugin_backup_403_yields_no_exposure():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/wp-content/ai1wm-backups/", status=403)
    responses.add(responses.GET, "https://cible.test/wp-content/ai1wm-backups/",
                  body="<html>Forbidden</html>" + ("x" * 100), status=403)
    chk = make_check(DatabaseExposureCheck)
    chk._check_plugin_backups()
    assert _exposures(chk) == []


@responses.activate
def test_phpmyadmin_403_yields_no_exposure():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/phpmyadmin/", status=403)
    responses.add(responses.GET, "https://cible.test/phpmyadmin/",
                  body="<html>Forbidden</html>" + ("x" * 100), status=403)
    chk = make_check(DatabaseExposureCheck)
    chk._check_phpmyadmin()
    assert _exposures(chk) == []


@responses.activate
def test_env_file_403_yields_no_exposure():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/.env", status=403)
    responses.add(responses.GET, "https://cible.test/.env",
                  body="<html>Forbidden</html>" + ("x" * 100), status=403)
    chk = make_check(DatabaseExposureCheck)
    chk._check_env_files()
    assert _exposures(chk) == []


# ── 3) Vrai indicateur de contenu => reste confirmed (pas de régression) ──

@responses.activate
def test_env_file_real_secret_stays_confirmed():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/.env", status=200)
    responses.add(responses.GET, "https://cible.test/.env",
                  body="DB_PASSWORD=secret\nDB_NAME=wp\n" + ("x" * 100), status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_env_files()
    findings = [f for f in chk._result.findings if "credentials visible" in f["message"]]
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["confidence"] == "confirmed"


# ── Fix A, db-error disclosure : mots-clés faibles vs signatures fortes ──
# "MySQL"/"Table " seuls sont trop génériques (texte de page ordinaire,
# "Table of Contents"...) : ça ne doit jamais produire un finding confirmé.
# Une vraie signature d'erreur SQL leakée reste un vrai positif confirmed.

@responses.activate
def test_db_error_weak_keywords_without_error_context_yield_nothing():
    """Une page ordinaire qui mentionne MySQL/Table sans aucun signe
    d'erreur ne doit produire aucun finding de fuite d'erreur SQL confirmé
    (au mieux rien du tout, mentionner ces mots n'est pas une preuve)."""
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body="<html><body>This site runs on MySQL. See the Table "
                       "of Contents plugin for navigation.</body></html>"
                       + ("x" * 100),
                  status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_db_error_disclosure()
    db_findings = [f for f in chk._result.findings
                   if "Database error disclosure" in f["message"]]
    assert not any(f["confidence"] == "confirmed" for f in db_findings)


@responses.activate
def test_db_error_real_sql_syntax_error_is_confirmed():
    """Une vraie signature d'erreur SQL divulguée reste un vrai positif
    confirmed, pas de régression de la détection réelle."""
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body="<html><body>Warning: You have an error in your SQL "
                       "syntax; check the manual that corresponds to your "
                       "MySQL server version.</body></html>" + ("x" * 100),
                  status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_db_error_disclosure()
    db_findings = [f for f in chk._result.findings
                   if "Database error disclosure" in f["message"]]
    assert len(db_findings) >= 1
    assert any(f["confidence"] == "confirmed" for f in db_findings)


@responses.activate
def test_db_error_disclosure_sends_no_injection_payload():
    """Version publique passive : aucune charge SQL (quote, UNION, tautologie)."""
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body="<html><body>ok</body></html>", status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_db_error_disclosure()
    urls = [c.request.url for c in responses.calls]
    assert urls, "la page d'accueil doit être lue"
    for url in urls:
        assert "'" not in url and "%27" not in url and "UNION" not in url.upper()
