"""Régression, cloaking_seo_spam : un mot-clé de spam en SOUS-CHAÎNE d'un mot
français légitime (« cialis » dans « spécialisés ») ne doit PAS déclencher."""
import re
import responses
from wp_security_forsure.scanner.checks.cloaking_seo_spam import CloakingSeoSpamCheck
from tests.conftest import make_check

# Contient « spécialisés », « commercialisation », « socialise » → sous-chaîne
# "cialis" ; et « suggestion » → sous-chaîne "ugg". Aucun VRAI mot-clé de spam.
BENIGN = ("<!DOCTYPE html><html lang='fr'><body>"
          "Nous sommes spécialisés dans la commercialisation de solutions. "
          "Notre équipe socialise et fait des suggestions. " + ("x" * 500) +
          "</body></html>")


@responses.activate
def test_french_words_containing_spam_substrings_not_flagged():
    responses.add(responses.GET, re.compile(r".*/wpsf-probe.*"),
                  body="404", status=404)
    responses.add(responses.GET, "https://cible.test/", body=BENIGN, status=200)
    responses.add(responses.GET, re.compile(r".*/sitemap\.xml"), status=404)
    responses.add(responses.GET, re.compile(r".*/robots\.txt"), status=404)
    chk = make_check(CloakingSeoSpamCheck)
    chk.context = {}
    chk.run()
    real = [f for f in chk._result.findings if f["severity"] != "INFO"]
    assert real == [], real
