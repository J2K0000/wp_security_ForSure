"""Passivité des nouvelles sources (SEC-20), moteur complet : oEmbed de
l'accueil, plan de site des auteurs, article réel et flux des commentaires.

Reprend le harnais de tests/test_passivity.py (même cible simulée, mêmes
garde-fous) en enrichissant la cible : un plan de site qui NE référence PAS
wp-sitemap-users-1.xml, une route oEmbed, une liste d'articles REST qui pointe
vers un article dont les commentaires sont ouverts, et un flux des
commentaires. Par défaut : aucune requête de niveau 2, le plan de site des
auteurs non référencé n'est pas demandé, rien n'est soumis.
"""
import json
from urllib.parse import urlsplit

import pytest

from tests import test_passivity as tp

ARTICLE = "https://cible.test/2026/11/bonjour/"
SITEMAP_INDEX = (
    '<?xml version="1.0" encoding="UTF-8"?><sitemapindex '
    'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    "<sitemap><loc>https://cible.test/wp-sitemap-posts-post-1.xml</loc></sitemap>"
    "</sitemapindex>")
ARTICLE_HTML = (
    "<html><body><article>Texte</article><form "
    "action='https://cible.test/wp-comments-post.php' method='post' "
    "id='commentform'><textarea name='comment'></textarea></form></body></html>")
FEED = ('<?xml version="1.0"?><rss version="2.0"><channel><item><title>c'
        "</title></item></channel></rss>")

_original_route_get = tp._route_get


def _route_get(req):
    parts = urlsplit(req.url)
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if host in ("cible.test", "www.cible.test"):
        js = {"Content-Type": "application/json; charset=UTF-8"}
        xml = {"Content-Type": "application/xml; charset=UTF-8"}
        if path == "/wp-sitemap.xml":
            return 200, xml, SITEMAP_INDEX
        if path == "/wp-sitemap-users-1.xml":
            return 200, xml, ('<urlset><url><loc>https://cible.test/author/demo/'
                              "</loc></url></urlset>")
        if path == "/wp-json/oembed/1.0/embed":
            return 200, js, json.dumps({"version": "1.0", "author_name": "admin",
                                        "author_url": "https://cible.test/author/admin/"})
        if path == "/wp-json/wp/v2/posts" and "status" not in (parts.query or ""):
            return 200, js, json.dumps([{"id": 7, "link": ARTICLE}])
        if path == urlsplit(ARTICLE).path:
            return 200, {"Content-Type": "text/html; charset=UTF-8"}, ARTICLE_HTML
        if path == "/comments/feed/":
            return 200, {"Content-Type": "application/rss+xml"}, FEED
    return _original_route_get(req)


def _scan(tmp_path_factory, authorized):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(tp, "_route_get", _route_get)
        return tp._run_engine(mp, tmp_path_factory.mktemp("vulncache"),
                              authorized=authorized)


@pytest.fixture(scope="module")
def default_scan(tmp_path_factory):
    return _scan(tmp_path_factory, authorized=False)


@pytest.fixture(scope="module")
def authorized_scan(tmp_path_factory):
    return _scan(tmp_path_factory, authorized=True)


def _urls(scan, check=None):
    return [req.url for c, req in scan["recorded"] if check in (None, c)]


def _messages(scan):
    return [f["message"] for r in scan["results"] for f in r.findings]


def test_default_run_with_new_sources_sends_no_level_2_request(default_scan):
    found = tp._tier2(default_scan)
    assert not found, tp._report(found)


def test_default_run_stays_read_only(default_scan):
    assert not tp._violations(default_scan["recorded"])
    assert not any("wp-comments-post.php" in u for u in _urls(default_scan))


def test_default_run_reads_new_sources(default_scan):
    urls = _urls(default_scan)
    assert any("/wp-json/oembed/1.0/embed?url=" in u for u in urls)
    assert any(u.rstrip("/") == ARTICLE.rstrip("/") for u in urls)
    assert any(u.endswith("/comments/feed/") for u in urls)
    # Non référencé par wp-sitemap.xml : jamais demandé sans --authorized.
    assert not any("wp-sitemap-users-1.xml" in u for u in urls)


def test_default_run_reports_risky_account_and_open_comments(default_scan):
    msgs = _messages(default_scan)
    assert sum(m == "Compte à risque exposé par énumération : « admin »"
               for m in msgs) == 1  # dédupliqué entre checks
    assert any(m.startswith("Commentaires ouverts") for m in msgs)


def test_authorized_run_reads_unreferenced_users_sitemap(authorized_scan):
    assert any("wp-sitemap-users-1.xml" in u for u in _urls(authorized_scan))
    assert any(m == "Compte à risque exposé par énumération : « demo »"
               for m in _messages(authorized_scan))
