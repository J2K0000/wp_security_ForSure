"""Un webshell présumé n'est jamais demandé, même sous --authorized : le
demander exécuterait la porte dérobée d'un tiers sur le serveur audité."""
import re

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.access_tiers import _SCRIPT_RE
from wp_security_forsure.scanner.checks.malware_detection import MalwareDetectionCheck


@responses.activate
def test_authorized_mode_never_requests_webshell_php_names():
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body="<html><body>page</body></html>", status=200)
    chk = make_check(MalwareDetectionCheck, config={"authorized": True})
    chk._check_webshell_files()

    php_names = {f for f in MalwareDetectionCheck.WEBSHELL_FILENAMES if _SCRIPT_RE.search(f)}
    assert php_names, "la liste doit contenir des noms .php pour que le test ait un sens"
    asked = {c.request.url.rsplit("/", 1)[-1] for c in responses.calls}
    assert not (asked & php_names), f"webshells demandés : {sorted(asked & php_names)}"
