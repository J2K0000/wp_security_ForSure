"""P9 : forms_upload, comment-nonce natif = LOW ; le test de XSS réfléchi de
la recherche (charge d'attaque) a été retiré : aucune charge n'est envoyée."""
import re
import responses
from wp_security_forsure.scanner.checks.forms_upload import FormsUploadCheck
from tests.conftest import make_check


@responses.activate
def test_comment_form_without_nonce_is_low():
    responses.add(responses.GET, "https://cible.test/",
                  body='<html><body><form id="commentform">...</form></body></html>',
                  status=200)
    chk = make_check(FormsUploadCheck)
    fs = chk._check_comment_nonce()
    hi = [f for f in fs if f["severity"] in ("HIGH", "CRITICAL")]
    assert hi == []
    assert any(f["severity"] == "LOW" for f in fs)


@responses.activate
def test_search_xss_payload_is_never_sent():
    responses.add(responses.GET, re.compile(r".*"), body="<html></html>", status=200)
    responses.add(responses.HEAD, re.compile(r".*"), status=404)
    chk = make_check(FormsUploadCheck)
    chk.run()
    assert not hasattr(FormsUploadCheck, "_check_search_xss")
    for call in responses.calls:
        url = call.request.url.lower()
        assert "?s=" not in url, url
        for needle in ("<script", "%3cscript", "onerror"):
            assert needle not in url, url
