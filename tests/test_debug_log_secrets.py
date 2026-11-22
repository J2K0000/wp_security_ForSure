"""debug.log exposé : fuite de secrets / cookies de session => CRITICAL.

Classe CVE-2024-44000 (LiteSpeed) : le debug.log logue des en-têtes
Set-Cookie post-login, permettant un account takeover. En plus du HIGH
existant (erreurs PHP génériques), on doit émettre un CRITICAL distinct.
"""
import re
import responses
from wp_security_forsure.scanner.checks.file_exposure import FileExposureCheck
from tests.conftest import make_check

# debug.log qui fuit un Set-Cookie de session post-login (account takeover).
LOG_WITH_COOKIES = (
    "[21-Jul-2026 10:00:01 UTC] PHP Notice:  undefined index in foo.php\n"
    "[21-Jul-2026 10:00:02 UTC] Set-Cookie: "
    "wordpress_logged_in_abc123=admin%7C1789...; path=/; HttpOnly\n"
    "[21-Jul-2026 10:00:03 UTC] wordpress_sec_abc123=deadbeef...\n"
    + ("Z" * 400)
)

# debug.log « propre » : uniquement des erreurs PHP génériques => reste HIGH.
LOG_ERRORS_ONLY = (
    "[21-Jul-2026 10:00:01 UTC] PHP Fatal error:  Uncaught Error in bar.php\n"
    "[21-Jul-2026 10:00:02 UTC] PHP Warning:  include failed\n"
    "Stack trace:\n#0 {main}\n"
    + ("Z" * 400)
)


def _findings(chk):
    return [f for f in chk._result.findings if f["severity"] != "INFO"]


def _critical(chk):
    return [f for f in _findings(chk) if f["severity"] == "CRITICAL"]


def _mock_probe_404():
    # Le témoin anti soft-404 doit renvoyer 404 (ressource absente).
    responses.add(responses.HEAD, re.compile(r".*/wpsf-probe.*"), status=404)
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body="404 Not Found", status=404)


@responses.activate
def test_debug_log_with_session_cookies_yields_critical():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/wp-content/debug.log", status=200)
    responses.add(responses.GET, "https://cible.test/wp-content/debug.log",
                  body=LOG_WITH_COOKIES, status=200)
    chk = make_check(FileExposureCheck)
    chk._check_single_path(
        "wp-content/debug.log", "wp-content/debug.log", "HIGH",
        ["PHP", "Fatal", "Error", "Warning", "Stack trace", "Notice", "Parse error"],
        is_directory=False,
    )
    crit = _critical(chk)
    assert len(crit) == 1
    assert "account takeover" in crit[0]["message"]
    assert "CVE-2024-44000" in crit[0]["message"]
    # Le secret complet ne doit pas être recopié tel quel dans l'evidence.
    assert "admin%7C1789" not in crit[0]["evidence"]


@responses.activate
def test_debug_log_errors_only_stays_high_no_critical():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/wp-content/debug.log", status=200)
    responses.add(responses.GET, "https://cible.test/wp-content/debug.log",
                  body=LOG_ERRORS_ONLY, status=200)
    chk = make_check(FileExposureCheck)
    chk._check_single_path(
        "wp-content/debug.log", "wp-content/debug.log", "HIGH",
        ["PHP", "Fatal", "Error", "Warning", "Stack trace", "Notice", "Parse error"],
        is_directory=False,
    )
    assert _critical(chk) == []
    # Le comportement existant (HIGH) ne doit pas régresser.
    assert any(f["severity"] == "HIGH" for f in _findings(chk))


@responses.activate
def test_no_debug_log_yields_nothing():
    _mock_probe_404()
    responses.add(responses.HEAD, "https://cible.test/wp-content/debug.log", status=404)
    responses.add(responses.GET, "https://cible.test/wp-content/debug.log",
                  body="404 Not Found", status=404)
    chk = make_check(FileExposureCheck)
    chk._check_single_path(
        "wp-content/debug.log", "wp-content/debug.log", "HIGH",
        ["PHP", "Fatal", "Error", "Warning", "Stack trace", "Notice", "Parse error"],
        is_directory=False,
    )
    assert _findings(chk) == []
