"""Subdomain / subresource takeover, détection légère + énumération étendue.

Matrice couverte :
  - home référence un hôte tiers dont le fetch renvoie une empreinte de service
    déprovisionné (NoSuchBucket)                          → HIGH potential
  - hôte tiers sain (aucune empreinte)                     → pas de HIGH
  - hôte tiers référencé mais NXDOMAIN (_resolve False)    → MEDIUM potential
  - mode étendu (takeover_enum) : crt.sh renvoie 2 sous-domaines dont un dangling
                                                            → HIGH sur le dangling

Les seams réseau (_resolve, _fetch_external, _crtsh_subdomains) sont monkeypatchés :
aucun accès DNS/HTTP réel hors de la home (mockée par `responses`).
"""
import re

import responses

from wp_security_forsure.scanner.checks.takeover import TakeoverCheck, DANGLING_FINGERPRINTS
from tests.conftest import make_check

HOME_URL = "https://cible.test/"

# Home référençant une ressource externe hébergée sur un hôte tiers (bucket S3).
_HOME_WITH_EXTERNAL = (
    "<html><head>"
    "<link rel='stylesheet' href='https://assets.tiers-cdn.test/app.css'>"
    "<script src='https://assets.tiers-cdn.test/app.js'></script>"
    "<img src='/local/logo.png'>"  # relative → même origine, ignorée
    "</head><body>ok</body></html>"
)

# Home sans aucune ressource externe (pour isoler certains cas).
_HOME_PLAIN = "<html><head></head><body>Bienvenue</body></html>"


def _make(config=None):
    chk = make_check(TakeoverCheck, config=config)
    chk.context = {"inventory": {"core": {}, "plugins": [], "themes": []}}
    return chk


def test_fingerprints_base_shape():
    """La base d'empreintes couvre les fournisseurs clés et a la forme attendue."""
    assert DANGLING_FINGERPRINTS
    for service, info in DANGLING_FINGERPRINTS.items():
        assert "fingerprint" in info and info["fingerprint"], service
        assert "desc" in info and info["desc"], service
    # Quelques fournisseurs incontournables.
    for svc in ("aws_s3", "github_pages", "heroku", "fastly", "azure"):
        assert svc in DANGLING_FINGERPRINTS
    assert DANGLING_FINGERPRINTS["aws_s3"]["fingerprint"] == "NoSuchBucket"


@responses.activate
def test_external_host_with_dangling_fingerprint_is_high():
    """(a) Hôte tiers référencé → fetch = 'NoSuchBucket' → HIGH potential."""
    responses.add(responses.GET, HOME_URL, body=_HOME_WITH_EXTERNAL, status=200)
    chk = _make()
    chk._resolve = lambda host: True
    chk._fetch_external = lambda url: "<html>... NoSuchBucket ...</html>"
    chk.run()
    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    f = high[0]
    assert "assets.tiers-cdn.test" in f["message"]
    assert "takeover probable" in f["message"]
    assert f["confidence"] == "potential"
    assert "NoSuchBucket" in f["evidence"]
    assert chk._result.passed is False


@responses.activate
def test_healthy_external_host_yields_no_high():
    """(b) Hôte tiers sain (aucune empreinte) → pas de HIGH."""
    responses.add(responses.GET, HOME_URL, body=_HOME_WITH_EXTERNAL, status=200)
    chk = _make()
    chk._resolve = lambda host: True
    chk._fetch_external = lambda url: "<html><body>Welcome to our CDN</body></html>"
    chk.run()
    assert not any(f["severity"] == "HIGH" for f in chk._result.findings)
    # Le récap INFO reste émis.
    assert any(f["severity"] == "INFO" for f in chk._result.findings)
    assert chk._result.passed is True


@responses.activate
def test_referenced_host_nxdomain_is_medium():
    """(c) Hôte référencé mais NXDOMAIN (_resolve False) → MEDIUM potential."""
    responses.add(responses.GET, HOME_URL, body=_HOME_WITH_EXTERNAL, status=200)
    chk = _make()
    chk._resolve = lambda host: False  # NXDOMAIN
    # _fetch_external ne doit pas être atteint ; on le neutralise malgré tout.
    chk._fetch_external = lambda url: None
    chk.run()
    medium = [f for f in chk._result.findings if f["severity"] == "MEDIUM"]
    assert len(medium) == 1
    f = medium[0]
    assert "NXDOMAIN" in f["message"]
    assert "assets.tiers-cdn.test" in f["message"]
    assert f["confidence"] == "potential"
    assert not any(x["severity"] == "HIGH" for x in chk._result.findings)


@responses.activate
def test_enum_mode_finds_dangling_subdomain():
    """(d) Mode étendu : crt.sh renvoie 2 sous-domaines dont un dangling → HIGH."""
    responses.add(responses.GET, HOME_URL, body=_HOME_PLAIN, status=200)
    chk = _make(config={"takeover_enum": True})
    chk._resolve = lambda host: True
    chk._crtsh_subdomains = lambda domain: ["ok.cible.test", "dangling.cible.test"]

    def fake_fetch(url):
        # Seul le sous-domaine dangling sert l'empreinte GitHub Pages.
        if "dangling.cible.test" in url:
            return "<html>There isn't a GitHub Pages site here.</html>"
        return "<html><body>OK</body></html>"

    chk._fetch_external = fake_fetch
    chk.run()
    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    assert "dangling.cible.test" in high[0]["message"]
    assert "github_pages" in high[0]["evidence"] or "GitHub Pages" in high[0]["evidence"]
    # Récap mentionnant le mode étendu.
    info = [f for f in chk._result.findings if f["severity"] == "INFO"]
    assert any("étendu" in f["message"] for f in info)


@responses.activate
def test_target_home_itself_captured_is_high():
    """La cible elle-même : home servant une empreinte de service → HIGH."""
    responses.add(responses.GET, HOME_URL,
                  body="<html>Fastly error: unknown domain</html>", status=200)
    chk = _make()
    chk._resolve = lambda host: True
    chk._fetch_external = lambda url: None
    chk.run()
    high = [f for f in chk._result.findings if f["severity"] == "HIGH"]
    assert len(high) == 1
    assert "cible.test" in high[0]["message"]
    assert "Fastly" in high[0]["evidence"]


def test_ip_literal_resources_are_not_takeover_candidates():
    """Une ressource sur IP littérale (réseau interne, métadonnées cloud,
    bouclage) n'est jamais un candidat takeover : elle n'est pas requêtée
    (SSRF depuis une page piégée). La garde SSRF de BaseCheck reste le
    rempart final pour tout le reste."""
    for raw in ("http://10.0.0.5/x.js", "https://169.254.169.254/latest/",
                "//[::1]/a.js", "http://127.0.0.1:8080/", "http://[fe80::1]/"):
        assert TakeoverCheck._url_host(raw) is None, raw
    assert TakeoverCheck._url_host("https://cdn.tiers.test/x.js") == "cdn.tiers.test"


@responses.activate
def test_external_fetch_refuses_private_destination():
    """_fetch_external passe par le client passif : une IP interne n'est
    jamais contactée (None renvoyé, aucune requête émise)."""
    responses.add(responses.GET, re.compile(r".*"), body="NoSuchBucket", status=404)
    chk = _make()
    assert chk._fetch_external("http://169.254.169.254/") is None
    assert len(responses.calls) == 0
