"""P4, server_security : le mot-clé « .. » ne doit pas faire croire à un
directory listing (présent dans toute page via les URLs relatives)."""
import re
import responses
from wp_security_forsure.scanner.checks.server_security import ServerSecurityCheck
from tests.conftest import make_check


@responses.activate
def test_dotdot_in_page_is_not_directory_listing():
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"), body="404", status=404)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body='<html><body><a href="../assets/style.css">css</a></body></html>' + ("x" * 100),
                  status=200)
    chk = make_check(ServerSecurityCheck)
    chk._check_directory_listing()
    assert not any("Directory listing ENABLED" in f["message"] for f in chk._result.findings)


@responses.activate
def test_real_index_of_is_flagged():
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"), body="404", status=404)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body='<html><head><title>Index of /uploads</title></head><body>'
                       '<a href="../">Parent Directory</a></body></html>',
                  status=200)
    chk = make_check(ServerSecurityCheck)
    chk._check_directory_listing()
    assert any("Directory listing ENABLED" in f["message"] for f in chk._result.findings)
