"""P1 : forms_upload, un site soft-404 ne doit pas déclencher de faux « upload
accessible ». (Les sondes POST admin-ajax.php ont été retirées : voir
test_upload_actions_are_never_probed.)"""
import re
import responses
from wp_security_forsure.scanner.checks.forms_upload import FormsUploadCheck
from tests.conftest import make_check

HOME = "<!DOCTYPE html><html><body>" + ("H" * 3000) + "</body></html>"


def _real(fs):
    return [x for x in fs if x["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]


@responses.activate
def test_upload_actions_are_never_probed():
    """Plus aucun POST admin-ajax.php (actions d'upload) : sous-contrôle non
    évaluable passivement, signalé en INFO."""
    responses.add(responses.POST, re.compile(r".*"), body="ok", status=200)
    responses.add(responses.HEAD, re.compile(r".*"), status=404)
    responses.add(responses.GET, re.compile(r".*"), body="nope", status=404)
    chk = make_check(FormsUploadCheck)
    result = chk.run()
    assert not hasattr(FormsUploadCheck, "_check_upload_actions")
    assert not hasattr(FormsUploadCheck, "UPLOAD_ACTIONS")
    assert {c.request.method for c in responses.calls} <= {"GET", "HEAD"}
    assert not any("admin-ajax" in c.request.url for c in responses.calls)
    info = [f for f in result.findings if "non évaluables passivement" in f["message"]]
    assert len(info) == 1 and info[0]["severity"] == "INFO"
    assert "admin-ajax" in info[0]["message"]


@responses.activate
def test_plugin_upload_path_soft404_not_flagged():
    responses.add(responses.HEAD, re.compile(r".*"), status=200)
    responses.add(responses.GET, re.compile(r".*"), body=HOME, status=200)
    chk = make_check(FormsUploadCheck)
    assert _real(chk._check_plugin_upload_paths()) == []
