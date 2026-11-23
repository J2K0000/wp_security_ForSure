"""SEC-20, commentaires : test sur un article réel (URL tirée de l'API REST,
niveau 1, ou d'un lien de la page d'accueil, niveau 0), recherche du
formulaire (#commentform, action vers wp-comments-post.php) et du flux
comments/feed/. Rien n'est jamais soumis."""
import re

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.forms_upload import FormsUploadCheck
from wp_security_forsure.scanner.checks.wp_features import WPFeaturesCheck

BASE = "https://cible.test"
ARTICLE = f"{BASE}/2026/11/bonjour-tout-le-monde/"
HTML = "text/html; charset=UTF-8"
JSON = "application/json; charset=UTF-8"

HOME_PLAIN = "<html><body><h1>Accueil</h1><p>Bienvenue</p></body></html>"
HOME_WITH_BOOKMARK = (
    "<html><body><article class='post-7 post type-post'>"
    "<h2 class='entry-title'><a href='" + ARTICLE + "' rel='bookmark'>Bonjour</a></h2>"
    "</article><a href='" + BASE + "/wp-login.php'>Connexion</a></body></html>")
ARTICLE_OPEN = (
    "<html><body><article><p>Texte</p></article>"
    "<div id='respond'><form action='" + BASE + "/wp-comments-post.php' "
    "method='post' id='commentform' class='comment-form'>"
    "<textarea name='comment'></textarea><input type='hidden' name='comment_post_ID' value='7'>"
    "</form></div></body></html>")
ARTICLE_CLOSED = (
    "<html><body><article><p>Texte</p></article>"
    "<p class='no-comments'>Les commentaires sont fermés.</p></body></html>")
COMMENTS_FEED = (
    '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
    "<title>Commentaires</title><item><title>Un commentaire</title></item>"
    "<item><title>Un autre</title></item></channel></rss>")


def _comment_findings(chk):
    return [f for f in chk._result.findings if "ommentaire" in f["message"]]


def _open(chk):
    return [f for f in chk._result.findings
            if f["message"].startswith("Commentaires ouverts")]


def _mock_site(home=HOME_PLAIN, article=ARTICLE_OPEN, rest=True, feed=True):
    responses.add(responses.GET, f"{BASE}/", body=home, content_type=HTML)
    if rest:
        responses.add(responses.GET, re.compile(rf"{BASE}/wp-json/wp/v2/posts\?per_page=1$"),
                      json=[{"id": 7, "link": ARTICLE}], content_type=JSON)
    responses.add(responses.GET, ARTICLE, body=article, content_type=HTML)
    if feed:
        responses.add(responses.GET, f"{BASE}/comments/feed/", body=COMMENTS_FEED,
                      content_type="application/rss+xml; charset=UTF-8")


@responses.activate
def test_open_comments_on_article_from_rest_are_low():
    _mock_site()
    chk = make_check(WPFeaturesCheck, config={"authorized": False})
    chk._check_comments_open()
    found = _open(chk)
    assert len(found) == 1
    f = found[0]
    assert f["severity"] == "LOW"
    assert f["confidence"] == "confirmed"
    assert ARTICLE in f["evidence"]
    assert "wp-json/wp/v2/posts" in f["evidence"]
    assert "#commentform" in f["evidence"]
    assert "wp-comments-post.php" in f["evidence"]
    assert "2 commentaire(s)" in f["evidence"]
    assert "les fermer s'ils ne servent pas" in f["evidence"]
    assert "une porte d'entrée en moins" in f["evidence"]
    # Rien n'est soumis : aucune requête vers wp-comments-post.php, GET seul.
    assert not any("wp-comments-post.php" in c.request.url for c in responses.calls)
    assert {c.request.method for c in responses.calls} <= {"GET", "HEAD"}


@responses.activate
def test_closed_comments_on_article_are_not_flagged():
    _mock_site(article=ARTICLE_CLOSED)
    chk = make_check(WPFeaturesCheck, config={"authorized": False})
    chk._check_comments_open()
    assert _open(chk) == []
    closed = [f for f in _comment_findings(chk) if f["severity"] == "INFO"]
    assert closed and ARTICLE in closed[0]["evidence"]


@responses.activate
def test_article_found_from_home_link_when_rest_is_closed():
    _mock_site(home=HOME_WITH_BOOKMARK, rest=False)
    responses.add(responses.GET, re.compile(rf"{BASE}/wp-json/wp/v2/posts.*"),
                  status=401, json={"code": "rest_forbidden"}, content_type=JSON)
    chk = make_check(WPFeaturesCheck, config={"authorized": False})
    chk._check_comments_open()
    found = _open(chk)
    assert len(found) == 1
    assert "lien de la page d'accueil" in found[0]["evidence"]


@responses.activate
def test_no_article_and_plain_home_yields_no_open_finding():
    responses.add(responses.GET, f"{BASE}/", body=HOME_PLAIN, content_type=HTML)
    responses.add(responses.GET, re.compile(rf"{BASE}/wp-json/wp/v2/posts.*"),
                  json=[], content_type=JSON)
    chk = make_check(WPFeaturesCheck, config={"authorized": False})
    chk._check_comments_open()
    assert _open(chk) == []


@responses.activate
def test_off_site_article_link_is_never_requested():
    responses.add(responses.GET, f"{BASE}/", body=HOME_PLAIN, content_type=HTML)
    responses.add(responses.GET, re.compile(rf"{BASE}/wp-json/wp/v2/posts.*"),
                  json=[{"id": 7, "link": "https://ailleurs.test/article/"}],
                  content_type=JSON)
    chk = make_check(WPFeaturesCheck, config={"authorized": False})
    chk._check_comments_open()
    assert not any("ailleurs.test" in c.request.url for c in responses.calls)
    assert _open(chk) == []


@responses.activate
def test_comment_nonce_check_also_reads_the_article():
    _mock_site()
    chk = make_check(FormsUploadCheck, config={"authorized": False})
    found = chk._check_comment_nonce()
    assert found and found[0]["url"] == ARTICLE
    assert not any("wp-comments-post.php" in c.request.url for c in responses.calls)


def test_comment_texts_have_no_em_dash():
    import inspect
    from wp_security_forsure.scanner.checks import forms_upload, wp_features
    for mod in (wp_features, forms_upload):
        assert "—" not in inspect.getsource(mod), mod.__name__
