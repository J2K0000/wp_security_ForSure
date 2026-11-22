import responses
from wp_security_forsure.scanner.checks.database_exposure import DatabaseExposureCheck
from tests.conftest import make_check

ALREADY = ("<!DOCTYPE html><html lang='fr-FR'><head><title>WordPress &raquo; "
           "Installation</title></head><body><h1>Déjà installé</h1>"
           "<p>Il semblerait que WordPress soit déjà installé.</p></body></html>")


@responses.activate
def test_install_already_installed_is_not_critical():
    responses.add(responses.HEAD, "https://cible.test/wp-admin/install.php", status=200)
    responses.add(responses.GET, "https://cible.test/wp-admin/install.php",
                  body=ALREADY, status=200, content_type="text/html; charset=UTF-8")
    chk = make_check(DatabaseExposureCheck)
    chk._check_install_php()
    for f in chk._result.findings:
        assert f["severity"] != "CRITICAL", f
