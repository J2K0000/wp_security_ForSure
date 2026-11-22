"""P9, ssl_tls : PFS ne doit pas être conclu sur un handshake rejeté, et les
liens <a href="http://"> ne sont pas du mixed content."""
import responses
from wp_security_forsure.scanner.checks.ssl_tls import SSLTLSChannel
from tests.conftest import make_check

NONE = "New, (NONE), Cipher is (NONE)\n"


def _mk_openssl(outputs_by_args):
    chk = make_check(SSLTLSChannel)

    def fake_run(hostname, port, extra_args=None, timeout=15):
        return outputs_by_args.get(" ".join(extra_args or []), "")

    chk._run_openssl = fake_run
    return chk


def _pfs(chk):
    return [f for f in chk._result.findings if "PFS" in f["message"] or "Forward Secrecy" in f["message"]]


def test_pfs_rejected_ecdhe_not_reported_supported():
    # ECDHE/DHE en TLS1.2 rejetés ((NONE)), mais TLS1.3 présent = PFS via TLS1.3.
    chk = _mk_openssl({
        "-cipher ECDHE -no_tls1_3": NONE,
        "-cipher DHE -no_tls1_3": NONE,
        "": "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n",
        "-no_tls1_3": NONE,
    })
    chk._check_pfs("h", 443)
    assert not any(f["severity"] == "HIGH" for f in _pfs(chk))
    assert not any("via ECDHE" in f["message"] for f in _pfs(chk))
    assert _pfs(chk)  # une note PFS (INFO) existe


def test_pfs_real_ecdhe_is_reported():
    chk = _mk_openssl({
        "-cipher ECDHE -no_tls1_3": "New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\n",
    })
    chk._check_pfs("h", 443)
    assert any("ECDHE" in f["message"] and f["severity"] == "INFO" for f in _pfs(chk))


@responses.activate
def test_anchor_http_link_is_not_mixed_content():
    html = '<!DOCTYPE html><html><body><a href="http://example.org/page">lien</a></body></html>'
    responses.add(responses.GET, "https://cible.test/", body=html, status=200)
    chk = make_check(SSLTLSChannel)
    chk._check_mixed_content()
    assert not any("Mixed content" in f["message"] for f in chk._result.findings)


@responses.activate
def test_img_http_src_is_mixed_content():
    html = '<!DOCTYPE html><html><body><img src="http://example.org/x.png"></body></html>'
    responses.add(responses.GET, "https://cible.test/", body=html, status=200)
    chk = make_check(SSLTLSChannel)
    chk._check_mixed_content()
    assert any("Mixed content" in f["message"] for f in chk._result.findings)
