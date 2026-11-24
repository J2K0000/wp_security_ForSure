"""Lecture des pages (scanner/htmlscan.py) : scripts, iframes, redirections."""
from wp_security_forsure.scanner import htmlscan as hs

BASE = "https://cible.test/"


def test_parse_page_scripts_iframes_and_redirects():
    html = """<html><head>
    <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
    <script src="https://cdn.tiers.example/x.js"></script>
    <script type="application/ld+json">{"@type":"Organization"}</script>
    <script>var a=1; window.location.href='https://ailleurs.example/go';</script>
    <script src="data:text/javascript;base64,YWxlcnQoMSk="></script>
    <meta http-equiv="refresh" content="0;url=https://autre.example/">
    </head><body><a href="/2026/05/article/">a</a>
    <iframe src="https://lure.example/captcha.html"></iframe></body></html>"""
    f = hs.parse_page(html, BASE)
    assert f.script_srcs == ["https://cible.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
                             "https://cdn.tiers.example/x.js"]
    assert len(f.inline_scripts) == 1          # JSON-LD n'est pas exécutable
    assert f.data_scripts == ["data:text/javascript;base64,YWxlcnQoMSk="]
    assert f.js_redirects == ["https://ailleurs.example/go"]
    assert f.meta_refresh == "https://autre.example/"
    assert f.iframes == ["https://lure.example/captcha.html"]
    assert f.links == ["https://cible.test/2026/05/article/"]


def test_unclosed_script_and_broken_html():
    f = hs.parse_page("<script>eval(atob('x'))", BASE)
    assert f.inline_scripts == ["eval(atob('x'))"]


def test_registrable_domain_and_same_site():
    assert hs.registrable_domain("m.cible.test") == "cible.test"
    assert hs.registrable_domain("cdn.exemple.co.uk") == "exemple.co.uk"
    assert hs.same_site("www.cible.test", "cible.test")
    assert not hs.same_site("cible.test.evil.example", "cible.test")
    assert hs.registrable_domain("127.0.0.1") == "127.0.0.1"


def test_internal_pages_skip_queries_admin_and_static():
    links = ["https://cible.test/?add-to-cart=12", "https://cible.test/wp-admin/",
             "https://cible.test/contact/", "https://cible.test/2026/05/article/",
             "https://cible.test/wp-content/uploads/a.pdf", "https://autre.example/x/",
             "https://www.cible.test/blog/post-2/", "https://cible.test/contact/"]
    assert hs.internal_pages(links, "https://cible.test", limit=3) == [
        "https://cible.test/2026/05/article/", "https://www.cible.test/blog/post-2/",
        "https://cible.test/contact/"]


def test_checkout_page():
    assert hs.checkout_page(["https://cible.test/checkout/"], "https://cible.test") \
        == "https://cible.test/checkout/"
    assert hs.checkout_page(["https://cible.test/checkout/?x=1"], "https://cible.test") is None


def test_inline_loader_shape():
    blob = "QUJD" * 120
    assert hs.is_inline_loader(f"var p='{blob}';eval(atob(p));")
    assert not hs.is_inline_loader(f"var img='{blob}';")
    assert not hs.is_inline_loader("eval(atob('c2hvcnQ='))")


def test_normalized_hash_ignores_nonces_and_versions():
    a = hs.normalized_hash("var n='a1b2c3d4e5f6a7b8c9d0'; load('x.js?ver=1234');")
    b = hs.normalized_hash("var n='ffeeddccbbaa99887766'; load('x.js?ver=9876');")
    assert a == b
