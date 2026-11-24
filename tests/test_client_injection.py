"""Check client_injection : signatures dans les scripts servis aux visiteurs."""
import base64
import re

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.client_injection import ClientInjectionCheck
from wp_security_forsure.scanner.htmlscan import parse_page

HOME = "https://cible.test/"
CLIP = "navigator.clipboard." + "writeText"
PS = "power" + "shell"
IOC = "0xA1decFB75C8C0CA28C10517ce56B710baf727d2e"


def check(context=None):
    chk = make_check(ClientInjectionCheck, config={"authorized": False})
    chk.context = context or {}
    return chk


def shared(pages, tool_html=None):
    return {"visit_profiles": {
        "pages": {url: {pid: parse_page(h, url) for pid, h in variants.items()}
                  for url, variants in pages.items()},
        "tool": parse_page(tool_html, HOME) if tool_html is not None else None}}


def real(findings):
    return [f for f in findings if f["severity"] != "INFO"]


@responses.activate
def test_data_script_is_decoded_and_scanned_per_profile():
    payload = (f"{CLIP}('{PS} -w h -c x');"
               "t.innerText='Verify you are human: Windows + R, Ctrl + V'")
    src = "data:text/javascript;base64," + base64.b64encode(payload.encode()).decode()
    inj = f"<html><head><script src='{src}'></script></head></html>"
    clean = "<html><head></head></html>"
    chk = check(shared({HOME: {"victim_google": inj, "direct_a": clean, "direct_b": clean}}))
    result = chk.run()
    by_msg = {f["message"]: f for f in real(result.findings)}
    full = [f for m, f in by_msg.items() if m.startswith("ClickFix : ")]
    assert full and full[0]["severity"] == "CRITICAL"
    assert "clic depuis Google (bureau)" in full[0]["evidence"]
    assert "visite directe" not in full[0]["evidence"]
    assert any(m.startswith("Script data:") for m in by_msg)


@responses.activate
def test_site_javascript_file_with_published_contract():
    js = "https://cible.test/wp-content/themes/t/app.js"
    responses.add(responses.GET, js, body=f"var c='{IOC}';",
                  content_type="application/javascript")
    page = f"<html><head><script src='{js}'></script></head></html>"
    chk = check(shared({HOME: {"victim_google": page}}))
    from wp_security_forsure.scanner import access_tiers
    access_tiers.add_references(chk.references(), [js], chk.target, access_tiers.TIER_HOME)
    result = chk.run()
    crit = [f for f in result.findings if f["severity"] == "CRITICAL"]
    assert crit and crit[0]["confidence"] == "confirmed" and crit[0]["url"] == js


@responses.activate
def test_web3_library_is_not_content_scanned():
    lib = "https://cdn.jsdelivr.net/npm/web3@latest/dist/web3.min.js"
    page = f"<html><head><script src='{lib}'></script></head></html>"
    result = check(shared({HOME: {"victim_google": page}})).run()
    assert not [c for c in responses.calls if "web3" in c.request.url]
    assert [f["severity"] for f in real(result.findings)] == ["MEDIUM"]


@responses.activate
def test_unknown_external_scripts_are_read_conditional_first_and_bounded():
    srcs = [f"https://t{i}.inconnu.example/s.js" for i in range(15)]
    for s in srcs:
        responses.add(responses.GET, s, body="var ok=1;", content_type="application/javascript")
    page_all = "<html>" + "".join(f"<script src='{s}'></script>" for s in srcs) + "</html>"
    page_base = "<html>" + "".join(f"<script src='{s}'></script>" for s in srcs[1:]) + "</html>"
    chk = check(shared({HOME: {"victim_google": page_all, "direct_a": page_base}}))
    chk.run()
    fetched = [c.request.url for c in responses.calls]
    assert len(fetched) == 10
    assert fetched[0] == srcs[0]      # absent des visites directes : lu en premier


@responses.activate
def test_well_known_services_are_not_fetched():
    page = ("<html><script src='https://www.googletagmanager.com/gtag/js?id=G-1'></script>"
            "<script src='https://static.hotjar.com/c/hotjar.js'></script></html>")
    check(shared({HOME: {"victim_google": page}})).run()
    assert len(responses.calls) == 0


@responses.activate
def test_falls_back_to_the_home_page_without_visit_profiles():
    responses.add(responses.GET, HOME,
                  body="<html><script>console.log('Road unavaible:')</script></html>",
                  content_type="text/html")
    result = check().run()
    assert any("UNC5142" in f["message"] for f in result.findings)


@responses.activate
def test_clean_site_has_no_finding():
    page = "<html><script>document.querySelector('nav').classList.add('ok')</script></html>"
    result = check(shared({HOME: {"victim_google": page, "direct_a": page}})).run()
    assert result.findings == []
