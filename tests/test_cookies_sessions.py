"""cookies_sessions, sécurité des cookies WordPress (flags, fixation,
scope de domaine, remember-me, application passwords, multi-instances).

Chaque sous-check est exercé isolément (appel direct de la méthode privée)
avec les seules requêtes HTTP qu'il émet réellement mockées via `responses`.
Un cas positif (condition non sécurisée -> finding attendu) et un cas négatif
(condition saine -> pas de finding) couvrent chaque sous-check majeur.
"""
import responses

from wp_security_forsure.scanner.checks.cookies_sessions import CookiesSessionsCheck
from tests.conftest import make_check

TARGET = "https://cible.test"
HOME = f"{TARGET}/"
LOGIN = f"{TARGET}/wp-login.php"
AJAX = f"{TARGET}/wp-admin/admin-ajax.php"
REST_ME = f"{TARGET}/wp-json/wp/v2/users/me"


def _mk():
    return make_check(CookiesSessionsCheck, target=TARGET)


def _no_cookie(url, method=responses.GET, body="<html></html>"):
    responses.add(method, url, body=body, status=200)


# ---------------------------------------------------------------------------
# 1) Flags de cookie, Secure / HttpOnly / SameSite
# ---------------------------------------------------------------------------

@responses.activate
def test_cookie_flags_insecure_cookie_triggers_critical_and_medium():
    """Cookie sans Secure/HttpOnly/SameSite -> 2x CRITICAL + 1x MEDIUM."""
    responses.add(responses.GET, HOME, body="<html></html>", status=200,
                   headers=[("Set-Cookie", "wordpress_test=abc; Path=/")])
    _no_cookie(LOGIN)
    _no_cookie(AJAX)

    chk = _mk()
    chk._check_cookie_flags()

    critical = [f for f in chk._result.findings if f["severity"] == "CRITICAL"]
    medium = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    assert len(critical) == 2
    assert any("missing Secure flag" in f["message"] for f in critical)
    assert any("missing HttpOnly flag" in f["message"] for f in critical)
    assert len(medium) == 1
    assert "no SameSite attribute" in medium[0]["message"]
    assert chk._result.passed is False


@responses.activate
def test_cookie_flags_secure_cookie_yields_no_finding():
    """Cookie Secure+HttpOnly+SameSite=Lax -> aucun finding CRITICAL/HIGH/MEDIUM."""
    responses.add(
        responses.GET, HOME, body="<html></html>", status=200,
        headers=[("Set-Cookie",
                  "wordpress_test=abc; Path=/; Secure; HttpOnly; SameSite=Lax")],
    )
    _no_cookie(LOGIN)
    _no_cookie(AJAX)

    chk = _mk()
    chk._check_cookie_flags()

    bad = [f for f in chk._result.findings
           if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    assert bad == []


@responses.activate
def test_cookie_flags_samesite_none_is_high():
    responses.add(
        responses.GET, HOME, body="<html></html>", status=200,
        headers=[("Set-Cookie",
                  "sid=abc; Path=/; Secure; HttpOnly; SameSite=None")],
    )
    _no_cookie(LOGIN)
    _no_cookie(AJAX)

    chk = _mk()
    chk._check_cookie_flags()

    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    assert "SameSite=None" in high[0]["message"]


@responses.activate
def test_cookie_flags_no_cookies_at_all_yields_info_only():
    _no_cookie(HOME)
    _no_cookie(LOGIN)
    _no_cookie(AJAX)

    chk = _mk()
    chk._check_cookie_flags()

    assert len(chk._result.findings) == 1
    assert chk._result.findings[0]["severity"] == "INFO"
    assert "No Set-Cookie headers found" in chk._result.findings[0]["message"]


@responses.activate
def test_cookie_flags_parses_multiple_set_cookie_headers_independently():
    """Deux en-têtes Set-Cookie distincts sur la même réponse -> analysés
    indépendamment (empreinte du parsing custom multi-Set-Cookie)."""
    responses.add(
        responses.GET, HOME, body="<html></html>", status=200,
        headers=[
            ("Set-Cookie", "session_id=aaa; Path=/; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "wordpress_logged_in_x=bbb; Path=/; HttpOnly"),
        ],
    )
    _no_cookie(LOGIN)
    _no_cookie(AJAX)

    chk = _mk()
    chk._check_cookie_flags()

    critical = [f for f in chk._result.findings if f["severity"] == "CRITICAL"]
    # Seul wordpress_logged_in_x (2e Set-Cookie) est fautif (Secure absent).
    assert len(critical) == 1
    assert "wordpress_logged_in_x" in critical[0]["message"]
    assert "auth cookie" in critical[0]["message"]
    assert "missing Secure flag" in critical[0]["message"]
    # session_id est intégralement conforme -> aucun finding le concernant.
    assert not any("session_id" in f["message"] for f in chk._result.findings
                   if f["severity"] != "INFO")
    medium = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    assert any("wordpress_logged_in_x" in f["message"] for f in medium)


# ---------------------------------------------------------------------------
# 2) Test cookie WordPress (wordpress_test_cookie)
# ---------------------------------------------------------------------------

@responses.activate
def test_test_cookie_detected_in_headers():
    responses.add(
        responses.GET, LOGIN, body="<html></html>", status=200,
        headers=[("Set-Cookie", "wordpress_test_cookie=WP+Cookie+check; Path=/")],
    )
    _no_cookie(HOME)

    chk = _mk()
    chk._check_test_cookie()

    info = [f for f in chk._result.findings if f["severity"] == "INFO"]
    assert any("WordPress test cookie" in f["message"] for f in info)


@responses.activate
def test_test_cookie_absent_yields_no_finding():
    _no_cookie(LOGIN)
    _no_cookie(HOME, body="<html><body>Bienvenue</body></html>")

    chk = _mk()
    chk._check_test_cookie()

    assert chk._result.findings == []


# ---------------------------------------------------------------------------
# 3) Fixation de session (pré-authentification)
# ---------------------------------------------------------------------------

@responses.activate
def test_session_fixation_auth_cookie_preauth_is_high():
    responses.add(
        responses.GET, LOGIN, body="<html></html>", status=200,
        headers=[("Set-Cookie", "wordpress_logged_in_x=abc; Path=/")],
    )
    chk = _mk()
    chk._check_session_fixation()

    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    assert "before authentication" in high[0]["message"]


@responses.activate
def test_session_fixation_php_session_preauth_is_medium():
    responses.add(
        responses.GET, LOGIN, body="<html></html>", status=200,
        headers=[("Set-Cookie", "PHPSESSID=deadbeef; Path=/")],
    )
    chk = _mk()
    chk._check_session_fixation()

    medium = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    assert len(medium) == 1
    assert "session fixation" in medium[0]["message"]


@responses.activate
def test_session_fixation_no_cookies_yields_info():
    _no_cookie(LOGIN)
    chk = _mk()
    chk._check_session_fixation()

    assert len(chk._result.findings) == 1
    assert chk._result.findings[0]["severity"] == "INFO"
    assert "No pre-login session cookies" in chk._result.findings[0]["message"]


# ---------------------------------------------------------------------------
# 4) Portée de domaine (Domain wildcard)
# ---------------------------------------------------------------------------

@responses.activate
def test_domain_scope_wildcard_domain_is_high():
    responses.add(
        responses.GET, HOME, body="<html></html>", status=200,
        headers=[("Set-Cookie", "sid=abc; Domain=.cible.test; Path=/")],
    )
    _no_cookie(LOGIN)

    chk = _mk()
    chk._check_domain_scope()

    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    assert "wildcard domain" in high[0]["message"]


@responses.activate
def test_domain_scope_origin_only_cookie_yields_no_finding():
    responses.add(
        responses.GET, HOME, body="<html></html>", status=200,
        headers=[("Set-Cookie", "sid=abc; Domain=cible.test; Path=/")],
    )
    _no_cookie(LOGIN)

    chk = _mk()
    chk._check_domain_scope()

    assert chk._result.findings == []


# ---------------------------------------------------------------------------
# 5) Remember-me (durée de vie du cookie wordpress_logged_in_*)
# ---------------------------------------------------------------------------

@responses.activate
def test_remember_me_excessive_maxage_is_high():
    responses.add(
        responses.GET, HOME, body="<html></html>", status=200,
        headers=[("Set-Cookie", "wordpress_logged_in_x=abc; Max-Age=3000000; Path=/")],
    )
    _no_cookie(LOGIN)

    chk = _mk()
    chk._check_remember_me()

    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    assert "excessively long expiry" in high[0]["message"]


@responses.activate
def test_remember_me_moderately_long_maxage_is_medium():
    responses.add(
        responses.GET, HOME, body="<html></html>", status=200,
        headers=[("Set-Cookie", "wordpress_logged_in_x=abc; Max-Age=1500000; Path=/")],
    )
    _no_cookie(LOGIN)

    chk = _mk()
    chk._check_remember_me()

    medium = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    assert len(medium) == 1
    assert "long expiry" in medium[0]["message"]


@responses.activate
def test_remember_me_absent_yields_info():
    _no_cookie(HOME)
    _no_cookie(LOGIN)

    chk = _mk()
    chk._check_remember_me()

    assert len(chk._result.findings) == 1
    assert chk._result.findings[0]["severity"] == "INFO"
    assert "No wordpress_logged_in_ cookies found" in chk._result.findings[0]["message"]


# ---------------------------------------------------------------------------
# 6) Application Passwords / auth stateless
# ---------------------------------------------------------------------------

@responses.activate
def test_application_passwords_rest_api_sets_cookies_is_medium():
    responses.add(
        responses.GET, REST_ME, body="{}", status=200,
        headers=[("Set-Cookie", "PHPSESSID=abc; Path=/; Secure")],
    )
    chk = _mk()
    chk._check_application_passwords()

    medium = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    assert len(medium) == 1
    assert "stateless" in medium[0]["message"]


@responses.activate
def test_application_passwords_rest_api_stateless_yields_info():
    responses.add(responses.GET, REST_ME, body="{}", status=200)
    chk = _mk()
    chk._check_application_passwords()

    info = [f for f in chk._result.findings if f["severity"] == "INFO"]
    assert any("does not set cookies" in f["message"] for f in info)
    assert not any(f["severity"] == "MEDIUM" for f in chk._result.findings)


# ---------------------------------------------------------------------------
# 7) Multi-instances de cookies d'authentification
# ---------------------------------------------------------------------------

@responses.activate
def test_multiple_auth_cookies_same_name_multiple_pages_is_medium():
    same_cookie = [("Set-Cookie", "wordpress_logged_in_abc=xyz; Path=/; Secure; HttpOnly")]
    responses.add(responses.GET, HOME, body="<html></html>", status=200, headers=same_cookie)
    responses.add(responses.GET, LOGIN, body="<html></html>", status=200, headers=same_cookie)
    responses.add(responses.GET, AJAX, body="", status=200, headers=same_cookie)

    chk = _mk()
    chk._check_multiple_auth_cookies()

    medium = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    assert len(medium) == 1
    assert "3 different pages" in medium[0]["message"]


@responses.activate
def test_multiple_auth_cookies_none_present_yields_info():
    _no_cookie(HOME)
    _no_cookie(LOGIN)
    _no_cookie(AJAX)

    chk = _mk()
    chk._check_multiple_auth_cookies()

    assert len(chk._result.findings) == 1
    assert chk._result.findings[0]["severity"] == "INFO"
    assert "No auth cookies found" in chk._result.findings[0]["message"]


@responses.activate
def test_multiple_auth_cookies_many_prefixes_is_low():
    """4 préfixes de cookie d'auth distincts sur une même page -> LOW."""
    responses.add(
        responses.GET, HOME, body="<html></html>", status=200,
        headers=[
            ("Set-Cookie", "wordpress_sec_1=a; Path=/"),
            ("Set-Cookie", "wordpress_logged_in_1=b; Path=/"),
            ("Set-Cookie", "wordpress_1=c; Path=/"),
            ("Set-Cookie", "wp-settings-1=d; Path=/"),
        ],
    )
    _no_cookie(LOGIN)
    _no_cookie(AJAX)

    chk = _mk()
    chk._check_multiple_auth_cookies()

    low = [f for f in chk._result.findings if f["severity"] == "LOW"]
    assert len(low) == 1
    assert "Multiple auth cookie prefixes" in low[0]["message"]


# ---------------------------------------------------------------------------
# 8) Parcours complet run(), vérifie l'absence d'exception et la présence
#    de tous les sous-résultats sur un site globalement insecure.
# ---------------------------------------------------------------------------

@responses.activate
def test_full_run_on_insecure_site_produces_findings_across_subchecks():
    insecure_cookie = [("Set-Cookie", "wordpress_test=abc; Path=/")]
    responses.add(responses.GET, HOME, body="<html></html>", status=200, headers=insecure_cookie)
    responses.add(responses.GET, LOGIN, body="<html></html>", status=200, headers=insecure_cookie)
    responses.add(responses.GET, AJAX, body="", status=200, headers=insecure_cookie)
    responses.add(responses.GET, REST_ME, body="{}", status=200)

    chk = _mk()
    result = chk.run()

    assert result.check_name == "cookies_sessions"
    assert result.findings  # au moins un finding remonté
    assert result.passed is False
    assert any(f["severity"] == "CRITICAL" for f in result.findings)


# ---------------------------------------------------------------------------
# Cookie de test du cœur : ni cookie d'authentification, ni attribut à reprocher
# (faux HIGH et faux MEDIUM du premier audit réel)
# ---------------------------------------------------------------------------

TEST_COOKIE_HEADER = ("Set-Cookie", "wordpress_test_cookie=WP%20Cookie%20check; "
                      "path=/; secure; HttpOnly")


@responses.activate
def test_test_cookie_is_not_an_auth_cookie_before_login():
    responses.add(responses.GET, LOGIN, body="<html></html>", status=200,
                  headers=[TEST_COOKIE_HEADER])
    chk = _mk()
    chk._check_session_fixation()
    assert not [f for f in chk._result.findings if f["severity"] in ("HIGH", "CRITICAL")]


@responses.activate
def test_test_cookie_without_samesite_is_not_reported():
    responses.add(responses.GET, LOGIN, body="<html></html>", status=200,
                  headers=[TEST_COOKIE_HEADER])
    _no_cookie(HOME)
    _no_cookie(AJAX)
    chk = _mk()
    chk._check_cookie_flags()
    assert not [f for f in chk._result.findings
                if "wordpress_test_cookie" in f["message"] and f["severity"] != "INFO"]
