"""P5, multisite ne doit pas émettre d'advisory CRITICAL/MEDIUM inconditionnel
sans preuve d'une vulnérabilité réelle."""
import re
import responses
from wp_security_forsure.scanner.checks.multisite import MultisiteCheck
from tests.conftest import make_check


def _sev(chk, s):
    return [f for f in chk._result.findings if f["severity"] == s]


@responses.activate
def test_cross_site_hardened_is_not_critical():
    # Éditeurs bloqués (403) = durci → pas de CRITICAL.
    responses.add(responses.HEAD, re.compile(r".*"), status=403)
    responses.add(responses.GET, re.compile(r".*"), body="Forbidden", status=403)
    chk = make_check(MultisiteCheck)
    chk._check_cross_site_contamination()
    assert _sev(chk, "CRITICAL") == []


@responses.activate
def test_cross_site_editor_open_is_critical():
    # Éditeur de plugin accessible (200) = DISALLOW_FILE_MODS absent → vrai vecteur.
    responses.add(responses.HEAD, re.compile(r".*"), status=200)
    responses.add(responses.GET, re.compile(r".*"),
                  body="<html>plugin editor</html>" + ("x" * 200), status=200)
    chk = make_check(MultisiteCheck)
    chk._check_cross_site_contamination()
    assert len(_sev(chk, "CRITICAL")) >= 1


@responses.activate
def test_upload_space_unknown_is_not_medium():
    responses.add(responses.HEAD, re.compile(r".*"), status=403)
    responses.add(responses.GET, re.compile(r".*"), body="Forbidden", status=403)
    chk = make_check(MultisiteCheck)
    chk._check_upload_space()
    assert not any("assume unlimited" in f["message"] and f["severity"] == "MEDIUM"
                   for f in chk._result.findings)


@responses.activate
def test_archived_generic_note_is_not_medium():
    responses.add(responses.HEAD, re.compile(r".*"), status=403)
    responses.add(responses.GET, re.compile(r".*"), body="Forbidden", status=403)
    chk = make_check(MultisiteCheck)
    chk._check_archived_sites()
    assert not any("may still serve" in f["message"] and f["severity"] == "MEDIUM"
                   for f in chk._result.findings)
