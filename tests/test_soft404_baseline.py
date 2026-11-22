"""P1, helper baseline soft-404 partagé dans BaseCheck.

Beaucoup de sites renvoient 200 + page d'accueil pour toute URL inexistante.
_is_soft404(resp) doit reconnaître qu'une réponse ≈ la réponse d'un chemin bidon
(témoin), pour que les checks ne confondent pas « HTTP 200 » avec « ressource
réellement exposée ».
"""
import re
import responses
from wp_security_forsure.scanner.checks.base import BaseCheck
from tests.conftest import make_check

HOME = "<!DOCTYPE html><html><body>" + ("H" * 3000) + "</body></html>"
SECRET = "DB_NAME='wp'; DB_PASSWORD='s3cr3t'; " + ("X" * 200)


class _Probe(BaseCheck):
    name = "probe_soft404"; title = "p"; description = "d"
    def run(self):
        return self._result


@responses.activate
def test_generic_200_matching_baseline_is_soft404():
    # N'importe quel chemin inexistant renvoie 200 + home.
    responses.add(responses.GET, re.compile(r"https://cible\.test/.*"),
                  body=HOME, status=200)
    chk = make_check(_Probe)
    resp = chk.http_get("/wp-config.php.bak")
    assert chk._is_soft404(resp) is True


@responses.activate
def test_distinct_content_is_not_soft404():
    # Le témoin renvoie la home ; une VRAIE fuite renvoie un corps distinct.
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body=HOME, status=200)
    responses.add(responses.GET, "https://cible.test/wp-config.php.bak",
                  body=SECRET, status=200)
    chk = make_check(_Probe)
    resp = chk.http_get("/wp-config.php.bak")
    assert chk._is_soft404(resp) is False


@responses.activate
def test_hard_404_site_marks_404_as_absent():
    # Site sain : chemin inexistant = vrai 404. Le témoin est 404.
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body="404 Not Found", status=404)
    responses.add(responses.GET, "https://cible.test/ghost.txt",
                  body="404 Not Found", status=404)
    chk = make_check(_Probe)
    resp = chk.http_get("/ghost.txt")
    assert chk._is_soft404(resp) is True  # ≈ témoin « absent »


@responses.activate
def test_hard_404_site_real_hit_is_not_absent():
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body="404 Not Found", status=404)
    responses.add(responses.GET, "https://cible.test/real.txt",
                  body=SECRET, status=200)
    chk = make_check(_Probe)
    resp = chk.http_get("/real.txt")
    assert chk._is_soft404(resp) is False
