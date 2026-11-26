"""Check php_runtime : branche de PHP (php.net) et erreurs PHP affichées."""
import datetime

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.php_runtime import (
    PhpRuntimeCheck, branch_status, load_php_support, php_errors)
from wp_security_forsure.scanner.htmlscan import parse_page

HOME = "https://cible.test/"
DAY = datetime.date(2026, 11, 24)


def run(headers=None, body="<html><body>ok</body></html>", context=None, pages=None,
        day=DAY):
    import wp_security_forsure.scanner.checks.php_runtime as mod
    real, mod.today = mod.today, (lambda: day)
    try:
        return _run(headers, body, context, pages)
    finally:
        mod.today = real


def _run(headers, body, context, pages):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.GET, HOME, body=body, headers=headers or {},
                 content_type="text/html")
        for url, page_body in (pages or {}).items():
            rsps.add(responses.GET, url, body=page_body, content_type="text/html")
        chk = make_check(PhpRuntimeCheck, config={"authorized": False})
        chk.context = context or {}
        if pages:
            from wp_security_forsure.scanner import access_tiers
            access_tiers.add_references(chk.references(), list(pages), chk.target,
                                        access_tiers.TIER_HOME)
        result = chk.run()
    return result


def test_table_matches_php_net_reading():
    t = load_php_support()
    assert t["as_of"] == "2026-11-24"
    assert t["supported"]["8.2"]["security_until"] == "2026-12-31"
    assert t["eol"]["8.1"] == {"eol": "2025-12-31", "last_release": "8.1.34"}
    assert all(src.startswith("https://www.php.net/") for src in t["source"])


def test_branch_states():
    assert branch_status("8.1.2", DAY)["state"] == "eol"
    assert branch_status("7.4.33", DAY)["until"] == datetime.date(2022, 11, 28)
    assert branch_status("8.2.20", DAY)["state"] == "security_only"
    assert branch_status("8.3.1", DAY)["state"] == "security_only"
    assert branch_status("8.4.5", DAY)["state"] == "active"
    # 8.2 au-delà de sa fin de correctifs : fin de vie, même absente de la liste eol.
    assert branch_status("8.2.20", datetime.date(2027, 1, 2))["state"] == "eol"
    assert branch_status("9.0.0", DAY)["state"] == "unknown"


def test_eol_branch_from_header_is_high_confirmed():
    result = run({"X-Powered-By": "PHP/7.4.33"})
    f = [x for x in result.findings if x["severity"] == "HIGH"][0]
    assert f["message"].startswith("PHP 7.4 en fin de vie depuis le 2022-11-28")
    assert f["confidence"] == "confirmed"
    assert "php.net" in f["evidence"] and "7.4.33" in f["evidence"]


def test_supported_branch_is_informational():
    result = run({"X-Powered-By": "PHP/8.4.10"})
    assert [f["severity"] for f in result.findings] == ["INFO"]
    assert result.findings[0]["message"].startswith("PHP 8.4 supporté")


def test_hidden_version_says_where_to_look():
    result = run({})
    assert result.findings[0]["severity"] == "INFO"
    assert "Santé du site" in result.findings[0]["evidence"]


def test_php_error_patterns():
    html = ("<br />\n<b>Warning</b>:  Undefined variable $x in "
            "<b>/var/www/site/wp-content/themes/t/header.php</b> on line <b>12</b><br />")
    assert php_errors(html) == [("Warning", "/var/www/site/wp-content/themes/t/header.php", "12")]
    text = "PHP Fatal error:  Uncaught Error: x in C:\\inetpub\\wp\\index.php on line 3"
    assert php_errors(text)[0][0] == "Fatal error"
    assert php_errors("<p>Warning: ce produit contient des noix.</p>") == []


def test_displayed_errors_on_home_and_internal_page():
    warn = ("<b>Deprecated</b>: x is deprecated in <b>/home/a/public_html/wp-includes/"
            "functions.php</b> on line <b>6121</b>")
    fatal = ("<b>Fatal error</b>: Uncaught TypeError in <b>/home/a/public_html/"
             "wp-content/plugins/p/p.php</b> on line <b>40</b>")
    article = "https://cible.test/2026/05/article/"
    context = {"visit_profiles": {"pages": {HOME: {"victim_google": parse_page("", HOME)},
                                            article: {"victim_google": parse_page("", article)}}}}
    result = run({"X-Powered-By": "PHP/8.4.1"}, body=f"<html>{warn}</html>",
                 context=context, pages={article: f"<html>{fatal}</html>"})
    errs = [f for f in result.findings if f["message"].startswith("Erreur PHP affichée")]
    assert [(f["url"], f["severity"]) for f in errs] == [(HOME, "LOW"), (article, "MEDIUM")]
    assert all(f["confidence"] == "confirmed" for f in errs)


def test_security_only_branch_near_its_end_is_medium():
    f = run({"X-Powered-By": "PHP/8.2.29"}).findings[0]
    assert f["severity"] == "MEDIUM" and "fin proche" in f["message"]
    far = run({"X-Powered-By": "PHP/8.3.20"}).findings[0]
    assert far["severity"] == "LOW" and "2027-12-31" in far["message"]

