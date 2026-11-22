"""P4, indicateurs database_exposure trop génériques (« password », « Login »,
« System ») ne doivent plus déclencher de CRITICAL sur une page banale."""
import re
import responses
from wp_security_forsure.scanner.checks.database_exposure import DatabaseExposureCheck
from tests.conftest import make_check


def _hard404_baseline():
    responses.add(responses.HEAD, re.compile(r".*/wpsf-probe.*"), status=404)
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"), body="404", status=404)


@responses.activate
def test_env_password_word_not_critical():
    _hard404_baseline()
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body="<html>Lost your password? Click here.</html>" + ("x" * 100), status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_env_files()
    assert not any("credentials visible" in f["message"] for f in chk._result.findings)


@responses.activate
def test_env_real_db_secret_is_critical():
    _hard404_baseline()
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body="DB_PASSWORD=secret\nDB_NAME=wp\n" + ("x" * 100), status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_env_files()
    assert any("credentials visible" in f["message"] for f in chk._result.findings)


@responses.activate
def test_adminer_login_word_not_critical():
    _hard404_baseline()
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body="<html><body>Login to continue</body></html>" + ("x" * 100), status=200)
    chk = make_check(DatabaseExposureCheck)
    chk._check_phpmyadmin()
    assert not any("Adminer accessible" in f["message"] for f in chk._result.findings)
