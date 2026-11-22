"""cache_security : plus aucune sonde active de cache (retirées de la version
publique, même en opt-in).

Avant : empoisonnement de cache (en-tête X-Forwarded-Host forgé), web cache
deception (URL d'apparence statique piégées, requêtées deux fois pour amorcer
le cache) et tests d'isolation par faux cookie de session WordPress.

Matrice couverte (run() complet, même avec l'ancienne clé active_exploitation) :
  - aucune requête vers une variante piégée (nonexistent-*.css/.js, %2f, ;)
  - aucun en-tête X-Forwarded-Host, aucun cookie wordpress_logged_in_* forgé
  - les méthodes actives n'existent plus
  - un constat INFO « non évaluable passivement » remplace ces sous-contrôles
"""
import re

import responses

from wp_security_forsure.scanner.checks.cache_security import CacheSecurityCheck
from tests.conftest import make_check

TARGET_RE = re.compile(r"https://cible\.test/.*")

DYN_BODY = "<html><body>contenu dynamique</body></html>"


def _run_full(config=None):
    # Cible qui semble tout mettre en cache (HIT partout) et derrière
    # Cloudflare + LiteSpeed : c'est ce qui déclenchait les anciennes sondes.
    headers = {"X-Cache": "HIT", "CF-Cache-Status": "HIT", "CF-Ray": "abc-CDG",
               "X-LiteSpeed-Cache": "hit", "Set-Cookie": "litespeed_vary=1"}
    responses.add_callback(responses.GET, TARGET_RE,
                           callback=lambda r: (200, headers, DYN_BODY))
    responses.add(responses.HEAD, TARGET_RE, status=404)
    chk = make_check(CacheSecurityCheck, config=config)
    chk.run()
    return chk


@responses.activate
def test_no_active_cache_probe_even_with_legacy_opt_in():
    chk = _run_full(config={"active_exploitation": True})

    assert responses.calls, "le check doit au moins lire la cible"
    for call in responses.calls:
        req = call.request
        assert req.method in ("GET", "HEAD"), req.method
        assert "nonexistent" not in req.url, req.url
        assert "%2f" not in req.url.lower(), req.url
        assert ";" not in req.url, req.url
        names = {k.lower() for k in req.headers}
        assert "x-forwarded-host" not in names, req.url
        assert "wordpress_logged_in" not in req.headers.get("Cookie", ""), req.url

    real = [f for f in chk._result.findings if f["severity"] != "INFO"]
    assert not any("cache deception" in f["message"].lower() for f in real)
    assert not any("poisoning" in f["message"].lower() for f in real)
    assert not any("cookie de session" in f["message"].lower() for f in real)


def test_active_cache_methods_are_gone():
    for attr in ("_check_cache_poisoning", "_check_web_cache_deception",
                 "_wcd_probe", "_wcd_variants", "_wcd_cache_buster"):
        assert not hasattr(CacheSecurityCheck, attr), attr


@responses.activate
def test_not_assessable_info_is_reported():
    chk = _run_full()
    info = [f for f in chk._result.findings
            if "non évaluables passivement" in f["message"]]
    assert len(info) == 1
    assert info[0]["severity"] == "INFO"
