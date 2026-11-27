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


# Versions de protocole : un refus du serveur affiche « Cipher is (NONE) ».
# Le test « "Cipher is " in output » signalait TLS 1.0 et 1.1 actifs (HIGH) sur
# un serveur qui les refuse : faux positif du premier audit réel.

PROTO_REFUSED = ("CONNECTED(00000003)\n"
                 "40D7:error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version\n"
                 "---\nno peer certificate available\n---\n"
                 "New, (NONE), Cipher is (NONE)\n")
TLS12_OK = ("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            "New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384\n")


def _proto_check(outputs_by_flag):
    chk = make_check(SSLTLSChannel)

    def fake_run(hostname, port, extra_args=None, timeout=15):
        flag = (extra_args or [""])[0]
        return outputs_by_flag.get(flag, "")

    chk._run_openssl = fake_run
    return chk


def test_refused_old_protocols_are_not_reported_enabled():
    chk = _proto_check({"-tls1_3": TLS13_STRONG, "-tls1_2": TLS12_OK,
                        "-tls1_1": PROTO_REFUSED, "-tls1": PROTO_REFUSED})
    chk._check_protocol_versions("example.com", 443)
    enabled = [f["message"] for f in chk._result.findings if "ENABLED" in f["message"]]
    assert enabled == []


def test_accepted_old_protocol_is_reported():
    accepted = "New, TLSv1, Cipher is ECDHE-RSA-AES256-SHA\n"
    chk = _proto_check({"-tls1_3": TLS13_STRONG, "-tls1_2": TLS12_OK,
                        "-tls1_1": PROTO_REFUSED, "-tls1": accepted})
    chk._check_protocol_versions("example.com", 443)
    enabled = [f for f in chk._result.findings if "ENABLED" in f["message"]]
    assert [f["message"] for f in enabled] == ["TLS 1.0 is ENABLED (deprecated protocol)"]
    assert enabled[0]["severity"] == "HIGH"


# Capture réelle OpenSSL 3.5.3 (2026-11-27) : le client local refuse TLS 1.0
# avant tout échange ; et un serveur qui refuse TLS 1.3 renvoie l'alerte 70.
LOCAL_REFUSES = ("no peer certificate available\nNew, (NONE), Cipher is (NONE)\n"
                 "error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available\n")
SERVER_REFUSES_13 = ("no peer certificate available\nNew, (NONE), Cipher is (NONE)\n"
                     "error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol "
                     "version:SSL alert number 70\n")


def test_locally_untestable_protocol_is_declared_not_enabled():
    chk = _proto_check({"-tls1_3": SERVER_REFUSES_13, "-tls1_2": TLS12_OK,
                        "-tls1_1": LOCAL_REFUSES, "-tls1": LOCAL_REFUSES})
    chk._check_protocol_versions("example.com", 443)
    msgs = {f["message"]: f["severity"] for f in chk._result.findings}
    assert not any("ENABLED" in m for m in msgs)
    assert msgs["TLS 1.0 non testable : l'openssl local refuse de proposer ce protocole"] == "INFO"
    assert "TLS 1.3 supported" not in msgs
    assert msgs.get("TLS 1.3 not supported") == "MEDIUM"


def test_old_protocols_are_offered_at_security_level_zero():
    seen = []
    chk = make_check(SSLTLSChannel)

    def fake_run(hostname, port, extra_args=None, timeout=15):
        seen.append(list(extra_args or []))
        return SERVER_REFUSES_13

    chk._run_openssl = fake_run
    chk._check_protocol_versions("example.com", 443)
    by_flag = {a[0]: a for a in seen}
    assert by_flag["-tls1"][1:] == ["-cipher", "DEFAULT@SECLEVEL=0"]
    assert by_flag["-tls1_1"][1:] == ["-cipher", "DEFAULT@SECLEVEL=0"]
    assert by_flag["-tls1_2"] == ["-tls1_2"]


# OCSP : un certificat sans URL OCSP (Let's Encrypt depuis mai 2025) n'a rien à
# agrafer ; « no response sent » n'est alors pas un défaut (faux MEDIUM du
# premier audit réel).
NO_STAPLE = ("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
             "OCSP response: no response sent\n")


def _ocsp_check(uri):
    chk = make_check(SSLTLSChannel)
    chk._run_openssl = lambda hostname, port, extra_args=None, timeout=15: NO_STAPLE
    chk._certificate_ocsp_uri = staticmethod(lambda output: uri)
    return chk


def test_no_stapling_without_ocsp_url_is_info():
    chk = _ocsp_check("")
    chk._check_ocsp_stapling("example.com", 443)
    assert [f["severity"] for f in chk._result.findings] == ["INFO"]


def test_no_stapling_with_ocsp_url_stays_medium():
    chk = _ocsp_check("http://ocsp.example.com")
    chk._check_ocsp_stapling("example.com", 443)
    assert [f["severity"] for f in chk._result.findings] == ["MEDIUM"]
