"""Énumération réseau d'un multisite : noms d'utilisateurs masqués (RGPD),
noms à risque lisibles et signalés, adresses e-mail masquées."""
import re

import responses

from tests.conftest import make_check
from wp_security_forsure.scanner.checks.multisite import MultisiteCheck

USERS = [
    {"id": 1, "name": "Julienne Martin", "slug": "julienne", "email": "julienne@exemple.test"},
    {"id": 2, "name": "test", "slug": "test"},
]


@responses.activate
def test_network_user_enumeration_masks_names_and_flags_risky_ones():
    responses.add(responses.GET, re.compile(r"https://cible\.test/wp-json/wp/v2/users/1.*"),
                  json=USERS[0], status=200)
    responses.add(responses.GET, re.compile(r"https://cible\.test/wp-json/wp/v2/users/\d+.*"),
                  json={"code": "rest_user_invalid_id"}, status=404)
    responses.add(responses.GET, re.compile(r"https://cible\.test/wp-json/wp/v2/users.*"),
                  json=USERS, status=200, headers={"X-WP-Total": "2"})
    responses.add(responses.HEAD, re.compile(r"https://cible\.test/.*"), status=200,
                  headers={"X-WP-Total": "2"})
    chk = make_check(MultisiteCheck)
    chk._check_user_enumeration()
    text = "\n".join(f["message"] + "\n" + f.get("evidence", "") for f in chk._result.findings)
    assert "julienne" not in text.lower(), text      # nom réel masqué
    assert "ju***" in text
    assert "julienne@exemple.test" not in text        # e-mail masqué
    assert "Noms à risque exposés : ['test']" in text # nom à risque lisible et signalé
