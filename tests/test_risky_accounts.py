"""SEC-20, comptes à risque : une liste unique de noms d'utilisateurs à risque
(génériques et dérivés du domaine), appliquée à chaque source d'énumération
(?author=N, API REST wp/v2/users, oEmbed de l'accueil, plan de site des
auteurs), et masquage RGPD des autres noms dans les preuves."""
import json
import re
from urllib.parse import parse_qs, urlsplit

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.brute_force_login import BruteForceLoginCheck
from wp_security_forsure.scanner.checks.rest_api import RestApiCheck
from wp_security_forsure.scanner.redact import (
    GENERIC_USERNAMES, is_risky_username, mask_username, risky_usernames)

BASE = "https://cible.test"
JSON = "application/json; charset=UTF-8"
XML = "application/xml; charset=UTF-8"


def _risky(chk):
    return [f for f in chk._result.findings
            if f["message"].startswith("Compte à risque exposé")]


def _risky_named(chk, name):
    return [f for f in _risky(chk) if f"« {name} »" in f["message"]]


def _all_text(chk):
    return "\n".join(f"{f['message']}\n{f.get('evidence', '')}\n{f.get('url', '')}"
                     for f in chk._result.findings)


# ── Liste unique des noms à risque ───────────────────────────────────────

def test_generic_list_is_the_documented_one():
    assert set(GENERIC_USERNAMES) == {
        "admin", "administrator", "test", "tester", "demo", "root",
        "wordpress", "wp", "user", "guest"}


def test_domain_label_and_obvious_variants_are_risky():
    names = risky_usernames("https://www.mon-site.test")
    for expected in ("mon-site", "monsite", "mon_site", "monsite-admin",
                     "admin-monsite", "adminmonsite", "mon-siteadmin"):
        assert expected in names, expected
    assert "www" not in names
    assert "test" in names  # générique, pas le TLD


def test_risky_match_is_case_insensitive_and_exact():
    assert is_risky_username("Admin", BASE)
    assert is_risky_username(" ROOT ", BASE)
    assert is_risky_username("cible", BASE)          # libellé du domaine
    assert not is_risky_username("julien", BASE)
    assert not is_risky_username("admin-julien", BASE)  # pas de sous-chaîne
    assert not is_risky_username("", BASE)


def test_ip_target_has_no_domain_label():
    assert risky_usernames("https://93.184.216.34") == frozenset(GENERIC_USERNAMES)


# ── Masquage ─────────────────────────────────────────────────────────────

def test_non_generic_username_is_masked():
    assert mask_username("julien", BASE) == "ju***"
    assert mask_username("Julien Dupont", BASE) == "Ju***"


def test_short_usernames_never_fully_revealed():
    assert mask_username("jo", BASE) == "j***"
    assert mask_username("j", BASE) == "***"


def test_risky_username_stays_readable():
    assert mask_username("admin", BASE) == "admin"
    assert mask_username("Administrator", BASE) == "Administrator"
    assert mask_username("cible", BASE) == "cible"


def test_masking_is_idempotent_and_can_be_disabled():
    assert mask_username(mask_username("julien", BASE), BASE) == "ju***"
    assert mask_username("julien", BASE, enabled=False) == "julien"


# ── Source 1 : ?author=N ─────────────────────────────────────────────────

def _author_redirects(mapping):
    def cb(req):
        n = int(parse_qs(urlsplit(req.url).query)["author"][0])
        slug = mapping.get(n)
        if slug is None:
            return 404, {}, ""
        return 302, {"Location": f"{BASE}/author/{slug}/"}, ""
    responses.add_callback(responses.GET, re.compile(r".*[?&]author=\d+.*"),
                           callback=cb)


@responses.activate
def test_author_source_flags_test_account_high_and_masks_others():
    _author_redirects({1: "julien", 2: "test"})
    chk = make_check(BruteForceLoginCheck)
    chk._check_user_enumeration_author()
    chk._report_risky_accounts()

    found = _risky_named(chk, "test")
    assert len(found) == 1
    f = found[0]
    assert f["severity"] == "HIGH"
    assert f["confidence"] == "confirmed"
    assert "?author=2" in f["evidence"]
    assert "supprimer ou renommer" in f["evidence"]
    assert "réattribuer ses contenus" in f["evidence"]
    text = _all_text(chk)
    assert "julien" not in text
    assert "ju***" in text
    assert not _risky_named(chk, "julien")


@responses.activate
def test_admin_via_author_is_flagged_once_by_the_shared_list():
    _author_redirects({1: "admin"})
    chk = make_check(BruteForceLoginCheck)
    chk._check_user_enumeration_author()
    chk._report_risky_accounts()
    assert len(_risky_named(chk, "admin")) == 1
    assert _risky_named(chk, "admin")[0]["severity"] == "HIGH"


# ── Source 2 : API REST wp/v2/users (liste et fiches) ────────────────────

USERS = [
    {"id": 1, "name": "Julien Dupont", "slug": "jdupont",
     "link": f"{BASE}/author/jdupont/"},
    {"id": 2, "name": "demo", "slug": "demo", "link": f"{BASE}/author/demo/"},
]


@responses.activate
def test_rest_list_flags_risky_slug_in_brute_force_login():
    responses.add(responses.GET, f"{BASE}/wp-json/wp/v2/users",
                  json=USERS, content_type=JSON)
    chk = make_check(BruteForceLoginCheck)
    chk._check_rest_api_users()
    chk._report_risky_accounts()
    f = _risky_named(chk, "demo")
    assert len(f) == 1 and f[0]["severity"] == "HIGH"
    assert "wp-json/wp/v2/users" in f[0]["evidence"]
    text = _all_text(chk)
    assert "jdupont" not in text and "Julien" not in text
    assert "jd***" in text


@responses.activate
def test_rest_list_flags_risky_slug_in_rest_api_with_same_message():
    responses.add(responses.GET, f"{BASE}/wp-json/wp/v2/users",
                  json=USERS, content_type=JSON)
    rest = make_check(RestApiCheck)
    rest._check_user_enumeration()
    bf = make_check(BruteForceLoginCheck)
    responses.calls.reset()
    bf._check_rest_api_users()
    bf._report_risky_accounts()
    r_found = _risky_named(rest, "demo")
    b_found = _risky_named(bf, "demo")
    assert len(r_found) == 1 and r_found[0]["severity"] == "HIGH"
    # Même message et même URL : le moteur ne garde qu'un constat.
    assert (r_found[0]["message"], r_found[0]["url"].rstrip("/")) == \
        (b_found[0]["message"], b_found[0]["url"].rstrip("/"))
    text = _all_text(rest)
    assert "jdupont" not in text and "Julien" not in text


@responses.activate
def test_rest_single_user_endpoint_is_a_source():
    responses.add(responses.GET, f"{BASE}/wp-json/wp/v2/users/1",
                  json={"id": 1, "name": "root", "slug": "root"}, content_type=JSON)
    chk = make_check(RestApiCheck)
    chk._check_user_enumeration_ids()
    chk._report_risky_accounts()
    f = _risky_named(chk, "root")
    assert len(f) == 1 and "wp-json/wp/v2/users/1" in f[0]["evidence"]


@responses.activate
def test_rest_display_name_only_is_medium_potential():
    # Nom affiché « admin », identifiant public différent : à confirmer.
    responses.add(responses.GET, f"{BASE}/wp-json/wp/v2/users",
                  json=[{"id": 3, "name": "Admin", "slug": "jdupont"}],
                  content_type=JSON)
    chk = make_check(BruteForceLoginCheck)
    chk._check_rest_api_users()
    chk._report_risky_accounts()
    f = _risky_named(chk, "admin")
    assert len(f) == 1
    assert f[0]["severity"] == "MEDIUM" and f[0]["confidence"] == "potential"
    assert "jdupont" not in _all_text(chk)


@responses.activate
def test_rest_emails_are_masked():
    responses.add(responses.GET, f"{BASE}/wp-json/wp/v2/users/1",
                  json={"id": 1, "name": "Julien", "slug": "julien",
                        "email": "julien@cible.test"}, content_type=JSON)
    chk = make_check(RestApiCheck)
    chk._check_user_enumeration_ids()
    text = _all_text(chk)
    assert "julien" not in text.lower()
    assert "ju***@cible.test" in text


@responses.activate
def test_masking_can_be_disabled_by_config():
    responses.add(responses.GET, f"{BASE}/wp-json/wp/v2/users",
                  json=USERS, content_type=JSON)
    chk = make_check(BruteForceLoginCheck, config={"mask_usernames": False})
    chk._check_rest_api_users()
    assert "jdupont" in _all_text(chk)


# ── Source 3 : oEmbed de la page d'accueil ───────────────────────────────

@responses.activate
def test_oembed_author_name_of_home_is_a_source():
    responses.add(responses.GET, re.compile(rf"{BASE}/wp-json/oembed/1\.0/embed\?.*"),
                  json={"version": "1.0", "type": "rich",
                        "author_name": "cible",
                        "author_url": f"{BASE}/author/cible/"},
                  content_type=JSON)
    chk = make_check(BruteForceLoginCheck, config={"authorized": False})
    chk._check_oembed_author()
    chk._report_risky_accounts()
    f = _risky_named(chk, "cible")
    assert len(f) == 1 and f[0]["severity"] == "HIGH"
    assert "oEmbed" in f[0]["evidence"]
    sent = responses.calls[0].request.url
    assert parse_qs(urlsplit(sent).query)["url"] == [f"{BASE}/"]


@responses.activate
def test_oembed_display_name_without_author_url_is_medium():
    responses.add(responses.GET, re.compile(rf"{BASE}/wp-json/oembed/1\.0/embed\?.*"),
                  json={"version": "1.0", "author_name": "guest"},
                  content_type=JSON)
    chk = make_check(BruteForceLoginCheck)
    chk._check_oembed_author()
    chk._report_risky_accounts()
    f = _risky_named(chk, "guest")
    assert len(f) == 1 and f[0]["severity"] == "MEDIUM"


@responses.activate
def test_oembed_404_yields_nothing():
    responses.add(responses.GET, re.compile(rf"{BASE}/wp-json/oembed/1\.0/embed\?.*"),
                  status=404, json={"code": "oembed_invalid_url"}, content_type=JSON)
    chk = make_check(BruteForceLoginCheck)
    chk._check_oembed_author()
    chk._report_risky_accounts()
    assert _risky(chk) == []


# ── Source 4 : plan de site des auteurs ──────────────────────────────────

INDEX_WITH_USERS = (
    '<?xml version="1.0" encoding="UTF-8"?><sitemapindex '
    'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    f"<sitemap><loc>{BASE}/wp-sitemap-posts-post-1.xml</loc></sitemap>"
    f"<sitemap><loc>{BASE}/wp-sitemap-users-1.xml</loc></sitemap>"
    "</sitemapindex>")
INDEX_WITHOUT_USERS = (
    '<?xml version="1.0" encoding="UTF-8"?><sitemapindex '
    'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    f"<sitemap><loc>{BASE}/wp-sitemap-posts-post-1.xml</loc></sitemap>"
    "</sitemapindex>")
USERS_SITEMAP = (
    '<?xml version="1.0" encoding="UTF-8"?><urlset '
    'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    f"<url><loc>{BASE}/author/wordpress/</loc></url>"
    f"<url><loc>{BASE}/author/marie-curie/</loc></url>"
    "</urlset>")


@responses.activate
def test_referenced_users_sitemap_is_read_without_authorized():
    responses.add(responses.GET, f"{BASE}/wp-sitemap.xml", body=INDEX_WITH_USERS,
                  content_type=XML)
    responses.add(responses.GET, f"{BASE}/wp-sitemap-users-1.xml",
                  body=USERS_SITEMAP, content_type=XML)
    chk = make_check(BruteForceLoginCheck, config={"authorized": False})
    chk._check_sitemap_users()
    chk._report_risky_accounts()
    f = _risky_named(chk, "wordpress")
    assert len(f) == 1 and f[0]["severity"] == "HIGH"
    assert "wp-sitemap-users-1.xml" in f[0]["evidence"]
    assert "marie-curie" not in _all_text(chk)


@responses.activate
def test_unreferenced_users_sitemap_is_not_requested_by_default():
    responses.add(responses.GET, f"{BASE}/wp-sitemap.xml", body=INDEX_WITHOUT_USERS,
                  content_type=XML)
    responses.add(responses.GET, f"{BASE}/wp-sitemap-users-1.xml",
                  body=USERS_SITEMAP, content_type=XML)
    chk = make_check(BruteForceLoginCheck, config={"authorized": False})
    chk._check_sitemap_users()
    chk._report_risky_accounts()
    assert not any("wp-sitemap-users" in c.request.url for c in responses.calls)
    assert _risky(chk) == []
    assert any("wp-sitemap-users-1.xml" in f["message"] and f["severity"] == "INFO"
               for f in chk._result.findings)


@responses.activate
def test_unreferenced_users_sitemap_is_requested_with_authorized():
    responses.add(responses.GET, f"{BASE}/wp-sitemap.xml", body=INDEX_WITHOUT_USERS,
                  content_type=XML)
    responses.add(responses.GET, f"{BASE}/wp-sitemap-users-1.xml",
                  body=USERS_SITEMAP, content_type=XML)
    chk = make_check(BruteForceLoginCheck, config={"authorized": True})
    chk._check_sitemap_users()
    chk._report_risky_accounts()
    assert len(_risky_named(chk, "wordpress")) == 1


# ── Consolidation ────────────────────────────────────────────────────────

@responses.activate
def test_one_finding_per_risky_name_listing_every_source():
    _author_redirects({1: "admin"})
    responses.add(responses.GET, f"{BASE}/wp-json/wp/v2/users",
                  json=[{"id": 1, "name": "admin", "slug": "admin"}],
                  content_type=JSON)
    responses.add(responses.GET, re.compile(rf"{BASE}/wp-json/oembed/1\.0/embed\?.*"),
                  json={"author_name": "admin"}, content_type=JSON)
    chk = make_check(BruteForceLoginCheck)
    chk._check_user_enumeration_author()
    chk._check_rest_api_users()
    chk._check_oembed_author()
    chk._report_risky_accounts()
    found = _risky_named(chk, "admin")
    assert len(found) == 1
    ev = found[0]["evidence"]
    assert "?author=1" in ev and "wp-json/wp/v2/users" in ev and "oEmbed" in ev


@responses.activate
def test_full_run_reports_risky_accounts():
    _author_redirects({1: "user"})
    chk = make_check(BruteForceLoginCheck)
    chk.run()
    assert len(_risky_named(chk, "user")) == 1
    assert {c.request.method for c in responses.calls} <= {"GET", "HEAD"}


def test_new_texts_have_no_em_dash():
    import inspect
    from wp_security_forsure.scanner.checks import brute_force_login, rest_api
    from wp_security_forsure.scanner import redact
    for mod in (brute_force_login, rest_api, redact):
        assert "—" not in inspect.getsource(mod), mod.__name__
