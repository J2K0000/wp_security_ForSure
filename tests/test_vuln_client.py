import responses
from wp_security_forsure.scanner.vulndb.client import WpvulnClient


@responses.activate
def test_fetch_plugin_ok():
    responses.add(responses.GET,
                  "https://www.wpvulnerability.net/plugin/contact-form-7/",
                  json={"error": 0, "data": {"plugin": "contact-form-7"}}, status=200)
    c = WpvulnClient(timeout=5)
    payload = c.fetch("plugin", "contact-form-7")
    assert payload["data"]["plugin"] == "contact-form-7"


@responses.activate
def test_fetch_network_error_returns_none():
    responses.add(responses.GET,
                  "https://www.wpvulnerability.net/plugin/x/", status=500)
    c = WpvulnClient(timeout=5)
    assert c.fetch("plugin", "x") is None


@responses.activate
def test_fetch_core_normalizes_version():
    responses.add(responses.GET,
                  "https://www.wpvulnerability.net/core/6.4.3/",
                  json={"error": 0, "data": {"core": "6.4.3", "vulnerability": None}}, status=200)
    responses.add(responses.GET,
                  "https://www.wpvulnerability.net/core/6.4/",
                  json={"error": 0, "data": {"core": "6.4",
                        "vulnerability": [{"uuid": "z"}]}}, status=200)
    c = WpvulnClient(timeout=5)
    payload = c.fetch("core", "6.4.3")
    assert payload["data"]["vulnerability"] == [{"uuid": "z"}]
