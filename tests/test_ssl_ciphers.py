"""Fiabilité, le check ssl_tls ne doit PAS remonter de cipher faible faux positif.

Faux positif observé (OpenSSL 3.5, cible TLS 1.3) : `-cipher NULL` négocie un
ciphersuite TLS 1.3 fort, et le garde-fou testait `"Cipher is NONE"` alors
qu'openssl écrit `Cipher is (NONE)`. Résultat : CRITICAL confirmé sur des sites
parfaitement sains. Sorties openssl ci-dessous = captures réelles.
"""
from wp_security_forsure.scanner.checks.ssl_tls import SSLTLSChannel
from tests.conftest import make_check

_FAMILIES = ("NULL", "aNULL", "EXPORT", "RC4", "DES", "3DES")

# Captures réelles OpenSSL 3.5.3
TLS13_STRONG = "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
REJECTED_NONE = ("New, (NONE), Cipher is (NONE)\n    Protocol  : TLSv1.2\n"
                 "error:0A0000B5:SSL routines:...:no ciphers available\n")
NO_CIPHER_MATCH = ("28410000:error:0A0000B9:SSL routines:"
                   "SSL_CTX_set_cipher_list:no cipher match:\n")


def _mk(outputs_by_cipher):
    chk = make_check(SSLTLSChannel)

    def fake_run(hostname, port, extra_args=None, timeout=15):
        cipher = None
        if extra_args and "-cipher" in extra_args:
            cipher = extra_args[extra_args.index("-cipher") + 1]
        return outputs_by_cipher.get(cipher, "")

    chk._run_openssl = fake_run
    return chk


def _weak(chk):
    return [f for f in chk._result.findings if "Weak cipher" in f["message"]]


def test_tls13_strong_cipher_is_not_flagged_weak():
    chk = _mk({c: TLS13_STRONG for c in _FAMILIES})
    chk._check_weak_ciphers("example.com", 443)
    assert _weak(chk) == []


def test_rejected_none_cipher_is_not_flagged():
    chk = _mk({c: REJECTED_NONE for c in _FAMILIES})
    chk._check_weak_ciphers("example.com", 443)
    assert _weak(chk) == []


def test_no_cipher_match_error_is_not_flagged():
    chk = _mk({c: NO_CIPHER_MATCH for c in _FAMILIES})
    chk._check_weak_ciphers("example.com", 443)
    assert _weak(chk) == []


def test_strong_cipher_not_in_family_is_not_flagged():
    outs = {c: REJECTED_NONE for c in _FAMILIES}
    # handshake réussit avec un cipher FORT alors qu'on testait NULL
    outs["NULL"] = "New, TLSv1.2, Cipher is ECDHE-ECDSA-CHACHA20-POLY1305\n"
    chk = _mk(outs)
    chk._check_weak_ciphers("example.com", 443)
    assert _weak(chk) == []


def test_genuine_rc4_accepted_is_flagged_critical():
    outs = {c: REJECTED_NONE for c in _FAMILIES}
    outs["RC4"] = "New, TLSv1.2, Cipher is RC4-SHA\n"
    chk = _mk(outs)
    chk._check_weak_ciphers("example.com", 443)
    f = _weak(chk)
    assert len(f) == 1
    assert f[0]["severity"] == "CRITICAL"
    assert "RC4-SHA" in f[0]["message"]


def test_genuine_anon_cipher_accepted_is_flagged():
    outs = {c: REJECTED_NONE for c in _FAMILIES}
    outs["aNULL"] = "New, TLSv1.2, Cipher is ADH-AES256-GCM-SHA384\n"
    chk = _mk(outs)
    chk._check_weak_ciphers("example.com", 443)
    f = _weak(chk)
    assert len(f) == 1
    assert "ADH-AES256-GCM-SHA384" in f[0]["message"]
