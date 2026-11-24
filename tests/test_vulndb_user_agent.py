"""Le client wpvulnerability.net envoie l'agent identifiable de l'outil."""
import requests

from wp_security_forsure import USER_AGENT
from wp_security_forsure.scanner.vulndb.client import WpvulnClient


def test_new_client_replaces_the_requests_default_agent():
    assert WpvulnClient().session.headers["User-Agent"] == USER_AGENT


def test_caller_agent_is_kept():
    s = requests.Session()
    s.headers["User-Agent"] = "agent-choisi/1.0"
    assert WpvulnClient(session=s).session.headers["User-Agent"] == "agent-choisi/1.0"
