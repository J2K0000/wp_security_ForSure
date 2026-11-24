"""Profils de visite (check visit_profiles) : une injection servie seulement à
certains visiteurs se voit dans l'écart entre profils."""
import hashlib
import re

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.visit_profiles import (
    FAKE_LOGIN_VALUE, PROFILES, VisitProfilesCheck, compare, logged_in_cookie_name,
    Variant)

TARGET = "https://cible.test"
PAGE = re.compile(r"https://cible\.test/.*")


def html(extra=""):
    return ("<html><head><script src='/wp-includes/js/jquery/jquery.min.js'></script>"
            f"{extra}</head><body><a href='/2026/05/article/'>Article</a>"
            "<a href='/contact/'>Contact</a></body></html>")


def serve(rsps, decide):
    """`decide(headers, url)` -> HTML servi."""
    calls = []

    def cb(req):
        calls.append(req)
        return 200, {"Content-Type": "text/html; charset=utf-8"}, decide(req.headers, req.url)
    rsps.add_callback(responses.GET, PAGE, callback=cb)
    return calls


def run(decide, config=None):
    cfg = {"authorized": False}
    cfg.update(config or {})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        calls = serve(rsps, decide)
        chk = make_check(VisitProfilesCheck, config=cfg)
        chk.context = {}
        result = chk.run()
    return result, calls, chk


def real(findings):
    return [f for f in findings if f["severity"] != "INFO"]


def from_google(h):
    return h.get("Referer", "").startswith("https://www.google.")


def logged(h):
    return "wordpress_logged_in_" in h.get("Cookie", "")


INJECT = "<script src='https://lure.exemple.invalid/l.js'></script>"


def test_stable_site_gives_only_the_summary():
    result, calls, _ = run(lambda h, u: html())
    assert real(result.findings) == []
    summary = [f for f in result.findings if f["message"] == "Profils de visite comparés"]
    assert summary and "8 profils sur 3 page(s)" in summary[0]["evidence"]
    assert len(calls) == 3 * len(PROFILES) + 1   # 3 pages x 8 profils + agent du scanner


def test_first_request_is_the_victim_profile():
    _, calls, _ = run(lambda h, u: html())
    first = calls[0]
    assert first.url == "https://cible.test/"
    assert first.headers["Referer"] == "https://www.google.com/"
    assert "Chrome/" in first.headers["User-Agent"]
    assert "wp_security_ForSure" not in first.headers["User-Agent"]
    # L'agent du scanner ne passe qu'après les profils de navigateur de l'accueil.
    tool = [i for i, c in enumerate(calls)
            if not c.headers["User-Agent"].startswith("Mozilla/")]
    assert tool == [len(PROFILES)]


def test_no_query_string_and_get_only():
    _, calls, _ = run(lambda h, u: html())
    assert {c.method for c in calls} == {"GET"}
    assert not [c.url for c in calls if "?" in c.url]


def test_fake_login_cookie_is_invalid_and_named_like_wordpress():
    _, calls, _ = run(lambda h, u: html())
    cookies = [c.headers.get("Cookie", "") for c in calls if logged(c.headers)]
    expected = "wordpress_logged_in_" + hashlib.md5(TARGET.encode()).hexdigest()
    assert logged_in_cookie_name(TARGET) == expected
    assert cookies and all(c == f"{expected}={FAKE_LOGIN_VALUE}" for c in cookies)


def test_referer_gated_injection_that_spares_admins_is_high():
    """Comme la campagne décrite par Rapid7 : seulement depuis Google, jamais
    pour un visiteur connecté."""
    result, _, _ = run(lambda h, u: html(INJECT) if from_google(h) and not logged(h) else html())
    found = [f for f in real(result.findings) if "lure.exemple.invalid" in f["message"]]
    assert found and all(f["severity"] == "HIGH" for f in found)
    ev = found[0]["evidence"]
    assert "clic depuis Google (bureau)" in ev.split("Absent")[0]
    assert "visite directe (1)" in ev.split("Absent")[1]
    assert "Referer Google" in ev and "administrateurs" in ev
    assert found[0]["confidence"] == "potential"


def test_injection_hidden_from_logged_in_visitors_only():
    result, _, _ = run(lambda h, u: html() if logged(h) else html(INJECT))
    home = [f for f in real(result.findings) if f["url"] == "https://cible.test/"]
    assert len(home) == 1 and home[0]["severity"] == "HIGH"
    assert "cookie de connexion" in home[0]["evidence"]
    assert "Referer Google" not in home[0]["evidence"]


def test_page_noise_downgrades_severity():
    """Une page qui change déjà de régie entre deux visites directes : l'écart
    reste signalé, une sévérité plus bas."""
    counter = {"n": 0}

    def decide(h, u):
        counter["n"] += 1
        return html(f"<script src='https://ads{counter['n']}.regie.example/a.js'></script>")
    result, _, _ = run(decide)
    sev = {f["severity"] for f in real(result.findings)}
    assert sev and "HIGH" not in sev
    assert any("Sévérité abaissée" in f["evidence"] for f in real(result.findings))


def test_mobile_only_offsite_redirect_is_high():
    def decide(h, u):
        if "Mobile" in h.get("User-Agent", ""):
            return "<html><script>location.replace('https://autre.exemple.invalid/x')</script></html>"
        return html()
    result, _, _ = run(decide)
    found = [f for f in real(result.findings) if "redirection vers autre.exemple.invalid" in f["message"]]
    assert found and found[0]["severity"] == "HIGH"


def test_blockchain_node_only_for_victims_is_critical():
    inj = "<script src='https://bsc-dataseed.binance.org/x.js'></script>"
    result, _, _ = run(lambda h, u: html(inj) if from_google(h) else html())
    assert any(f["severity"] == "CRITICAL" for f in real(result.findings))


def test_context_is_shared_with_client_injection():
    _, _, chk = run(lambda h, u: html())
    shared = chk.context["visit_profiles"]
    assert set(shared["pages"]) == {"https://cible.test/", "https://cible.test/2026/05/article/",
                                    "https://cible.test/contact/"}
    assert "victim_google" in shared["pages"]["https://cible.test/"]
    assert shared["tool"] is not None


def test_static_assets_of_variants_become_readable_but_not_php():
    inj = ("<script src='/wp-content/themes/t/inj.js'></script>"
           "<script src='/wp-content/uploads/x.php'></script>")
    _, _, chk = run(lambda h, u: html(inj) if from_google(h) else html())
    assert chk.may_request("https://cible.test/wp-content/themes/t/inj.js")
    assert not chk.may_request("https://cible.test/wp-content/uploads/x.php")


def test_disabled_by_configuration():
    result, calls, _ = run(lambda h, u: html(), {"visit_profiles": False})
    assert calls == [] and real(result.findings) == []


def test_compare_ignores_failed_profiles():
    ok = Variant("direct_a", status=200, items={("script", "a.example")})
    failed = Variant("victim_google", error="ConnectionError")
    gates, volatile = compare({"direct_a": ok, "victim_google": failed})
    assert gates == {} and volatile == set()


def test_unreachable_target_stops_after_the_first_profile():
    import requests as rq
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.GET, PAGE, body=rq.exceptions.ConnectionError("refusé"))
        chk = make_check(VisitProfilesCheck, config={"authorized": False})
        chk.context = {}
        result = chk.run()
        assert len(rsps.calls) == 1
    assert real(result.findings) == []
    assert "ne répond pas" in result.findings[0]["message"]
