"""P9, brute_force_login : redirection ?author vers l'accueil = protection (pas
un user) ; absence d'assets 2FA = non concluant (LOW), pas HIGH."""
import re
import responses
from wp_security_forsure.scanner.checks.brute_force_login import BruteForceLoginCheck
from tests.conftest import make_check


def _enum(chk):
    return [f for f in chk._result.findings if "User enumeration" in f["message"]]


@responses.activate
def test_author_redirect_to_home_is_not_enumeration():
    # Archives auteur désactivées : ?author=N redirige vers l'accueil.
    responses.add(responses.GET, re.compile(r".*[?&]author=\d.*"),
                  status=302, headers={"Location": "https://cible.test/"})
    chk = make_check(BruteForceLoginCheck)
    chk._check_user_enumeration_author()
    assert _enum(chk) == []


@responses.activate
def test_author_redirect_to_author_archive_is_enumeration():
    responses.add(responses.GET, re.compile(r".*[?&]author=\d.*"),
                  status=302, headers={"Location": "https://cible.test/author/john/"})
    chk = make_check(BruteForceLoginCheck)
    chk._check_user_enumeration_author()
    assert len(_enum(chk)) == 1


@responses.activate
def test_no_2fa_assets_is_low_not_high():
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=404)
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"), status=404)
    chk = make_check(BruteForceLoginCheck)
    chk._check_twofa_detection()
    assert not any(f["severity"] == "HIGH" for f in chk._result.findings)
