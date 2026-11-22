"""Masquage des secrets : jamais de mot de passe, clé, sel, jeton ou chaîne de
connexion recopié en clair dans les preuves ni dans les trois rapports."""
import hashlib
import json

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner import status as st
from wp_security_forsure.scanner.checks.base import CheckResult
from wp_security_forsure.scanner.checks.database_exposure import DatabaseExposureCheck
from wp_security_forsure.scanner.checks.file_exposure import FileExposureCheck
from wp_security_forsure.scanner.redact import mask_secret, redact_obj, redact_text
from wp_security_forsure.scanner.reporters.html_reporter import HTMLReporter
from wp_security_forsure.scanner.reporters.json_reporter import JSONReporter
from wp_security_forsure.scanner.reporters.terminal_reporter import TerminalReporter

TARGET = "https://cible.test"
DB_PASS = "Sup3r-S3cret-DbPass!"
AUTH_KEY = "k8#Q]v2Lx!p@9zR&w4Ye%T1mN6^bC0sD"
SALT = "aZ9-salt-value-that-is-long-enough-1234"
API_TOKEN = "tok_live_9f8e7d6c5b4a3210"

ENV_BODY = (
    "APP_ENV=production\n"
    "DB_NAME=wordpress\n"
    "DB_USER=wp\n"
    f"DB_PASSWORD={DB_PASS}\n"
    f"AUTH_KEY='{AUTH_KEY}'\n"
    f'NONCE_SALT="{SALT}"\n'
    f"API_TOKEN={API_TOKEN}\n"
    "DATABASE_URL=mysql://wp:ConnPass99@db.internal:3306/wordpress\n"
)
SECRETS = [DB_PASS, AUTH_KEY, SALT, API_TOKEN, "ConnPass99"]


def _sha8(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def test_mask_secret_format():
    masked = mask_secret("abcdefghijklmnop")
    assert masked == "abcd***(16 car.)"
    assert "sha256" not in masked          # pas d'empreinte : confirmable hors ligne


def test_mask_secret_keeps_fewer_chars_on_short_values():
    masked = mask_secret("s3cr3t")
    assert "s3cr" not in masked
    assert "(6 car.)" in masked


def test_mask_secret_is_idempotent():
    once = mask_secret(DB_PASS)
    assert mask_secret(once) == once
    assert redact_text(f"DB_PASSWORD={once}") == f"DB_PASSWORD={once}"


def test_wordpress_defines_are_masked():
    text = ("define( 'DB_NAME', 'wordpress' );\n"
            f"define( 'DB_PASSWORD', '{DB_PASS}' );\n"
            f"define('AUTH_KEY', '{AUTH_KEY}');\n"
            f"define('SECURE_AUTH_KEY', '{AUTH_KEY}x');\n"
            f"define('LOGGED_IN_KEY', '{AUTH_KEY}y');\n"
            f"define('NONCE_KEY', '{AUTH_KEY}z');\n"
            f"define('AUTH_SALT', '{SALT}');\n"
            f"define('SECURE_AUTH_SALT', '{SALT}a');\n"
            f"define('LOGGED_IN_SALT', '{SALT}b');\n"
            f"define('NONCE_SALT', '{SALT}c');\n")
    out = redact_text(text)
    for secret in (DB_PASS, AUTH_KEY, SALT):
        assert secret not in out
    assert "'wordpress'" in out            # DB_NAME reste visible : preuve utile
    assert f"***({len(DB_PASS)} car.)" in out


def test_env_json_query_and_connection_strings_are_masked():
    out = redact_text(ENV_BODY)
    for secret in SECRETS:
        assert secret not in out
    assert "DB_USER=wp" in out
    assert "mysql://wp:" in out and "@db.internal" in out
    js = redact_text('{"api_key": "AIzaSyA-1234567890abcdefghijklmnopqrstu", "user": "bob"}')
    assert "AIzaSyA-1234567890abcdefghijklmnopqrstu" not in js and '"bob"' in js
    qs = redact_text("https://cible.test/cb?access_token=abc123def456&page=2")
    assert "abc123def456" not in qs and "page=2" in qs
    bearer = redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
    assert "eyJhbGciOiJIUzI1NiJ9" not in bearer


def test_truncated_quoted_secret_is_still_masked():
    out = redact_text(f"define( 'DB_PASSWORD', '{DB_PASS[:10]}")
    assert DB_PASS[:10] not in out


def test_password_hashes_and_private_keys_are_masked():
    phpass = "$P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0"
    pem = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretmaterial\n"
           "-----END RSA PRIVATE KEY-----")
    out = redact_text(f"INSERT INTO wp_users VALUES (1,'admin','{phpass}');\n{pem}")
    assert phpass not in out
    assert "MIIEowIBAAKCAQEAsecretmaterial" not in out
    assert "'admin'" in out


def test_redact_obj_walks_nested_structures():
    data = {"a": [f"DB_PASSWORD={DB_PASS}", {"b": f"token={API_TOKEN}"}], "n": 3}
    out = redact_obj(data)
    dumped = json.dumps(out)
    assert DB_PASS not in dumped and API_TOKEN not in dumped
    assert out["n"] == 3


def test_plain_text_is_untouched():
    text = "Matched indicators: DB_, AUTH_KEY, API_KEY, SECRET\nHTTP 200 | Size: 12"
    assert redact_text(text) == text


# ── Bout en bout : .env exposé simulé, aucun secret dans les trois rapports ──

def _register_env_exposure():
    responses.add(responses.HEAD, f"{TARGET}/.env", status=200)
    responses.add(responses.GET, f"{TARGET}/.env", body=ENV_BODY, status=200,
                  content_type="text/plain")


def _assert_no_secret(text, where):
    for secret in SECRETS:
        assert secret not in text, f"{secret!r} recopié en clair dans {where}"


@responses.activate
def test_exposed_env_leaks_no_secret_in_any_report(capsys):
    _register_env_exposure()
    results = []
    for cls in (FileExposureCheck, DatabaseExposureCheck):
        chk = make_check(cls)
        chk.context = {}
        result = chk.run()
        st.set_status(result, st.STATUS_OK)
        results.append(result)

    evidences = [f["evidence"] for r in results for f in r.findings]
    assert any(".env" in f["url"] for r in results for f in r.findings)
    for ev in evidences:
        _assert_no_secret(ev, "la preuve à la source")
    assert any(f"***({len(DB_PASS)} car.)" in ev for ev in evidences)

    _assert_no_secret(JSONReporter(results, TARGET, {}).generate(), "le rapport JSON")
    _assert_no_secret(HTMLReporter(results, TARGET, {}).generate(), "le rapport HTML")
    text = TerminalReporter(results, TARGET, {}).generate()
    _assert_no_secret(text + capsys.readouterr().out, "le rapport terminal")


def test_reporters_redact_even_if_a_check_forgot(capsys):
    """Défense en profondeur : un check qui recopie un secret brut."""
    r = CheckResult("file_exposure", "Fichiers", "d", "CRITICAL", True)
    r.add_finding(f"Fuite DB_PASSWORD={DB_PASS}", severity="CRITICAL",
                  evidence=ENV_BODY, url=f"{TARGET}/.env?token={API_TOKEN}")
    st.set_status(r, st.STATUS_OK)
    _assert_no_secret(JSONReporter([r], TARGET, {}).generate(), "le rapport JSON")
    _assert_no_secret(HTMLReporter([r], TARGET, {}).generate(), "le rapport HTML")
    text = TerminalReporter([r], TARGET, {}).generate()
    _assert_no_secret(text + capsys.readouterr().out, "le rapport terminal")
    # le résultat d'origine n'est pas modifié par les reporters
    assert DB_PASS in r.findings[0]["evidence"]
