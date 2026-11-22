"""P1, file_exposure ne doit rien signaler sur un site soft-404 (200 + home)."""
import re
import responses
from wp_security_forsure.scanner.checks.file_exposure import FileExposureCheck
from tests.conftest import make_check

HOME = "<!DOCTYPE html><html><body>" + ("H" * 3000) + "</body></html>"
SECRET = "<?php\ndefine('DB_NAME','wp');\ndefine('DB_PASSWORD','s3cr3t');\n" + ("X" * 200)


def _findings(chk):
    return [f for f in chk._result.findings if f["severity"] != "INFO"]


@responses.activate
def test_soft404_site_yields_no_file_finding():
    # Tout chemin (témoin inclus) renvoie 200 + home.
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body=HOME, status=200)
    chk = make_check(FileExposureCheck)
    chk._check_single_path("wp-config.php.bak", "wp-config backup",
                           "CRITICAL", ["DB_NAME"], is_directory=False)
    assert _findings(chk) == []


@responses.activate
def test_real_exposed_file_is_still_flagged():
    responses.add(responses.HEAD, re.compile(r".*/wpsf-probe.*"), status=404)
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body="404 Not Found", status=404)
    responses.add(responses.HEAD, "https://cible.test/wp-config.php.bak", status=200)
    responses.add(responses.GET, "https://cible.test/wp-config.php.bak",
                  body=SECRET, status=200)
    chk = make_check(FileExposureCheck)
    chk._check_single_path("wp-config.php.bak", "wp-config backup",
                           "CRITICAL", ["DB_NAME"], is_directory=False)
    assert len(_findings(chk)) == 1
    assert _findings(chk)[0]["severity"] == "CRITICAL"
