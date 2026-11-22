"""P3, rest_api : média orphelin (normal) et endpoints block/pattern-directory
(destination fixe wp.org) ne sont pas des HIGH."""
import re
import responses
from wp_security_forsure.scanner.checks.rest_api import RestApiCheck
from tests.conftest import make_check


def _high(chk):
    return [f for f in chk._result.findings if f["severity"] == "HIGH"]


@responses.activate
def test_orphaned_media_not_high():
    responses.add(responses.GET, re.compile(r".*/wp-json/wp/v2/media.*"),
                  json=[{"id": 1, "post": None, "title": {"rendered": "logo"},
                         "meta": {}, "source_url": "https://cible.test/x.png"}],
                  status=200, headers={"X-WP-Total": "1"})
    chk = make_check(RestApiCheck)
    chk._check_media_endpoint()
    assert _high(chk) == []


@responses.activate
def test_block_directory_not_high():
    responses.add(responses.GET, re.compile(r".*/wp-json/wp/v2/block-directory/search.*"),
                  json=[{"name": "x"}], status=200)
    chk = make_check(RestApiCheck)
    chk._check_block_directory()
    assert _high(chk) == []


@responses.activate
def test_pattern_directory_not_high():
    responses.add(responses.GET, re.compile(r".*/wp-json/wp/v2/pattern-directory/patterns.*"),
                  json=[{"title": "x"}], status=200)
    chk = make_check(RestApiCheck)
    chk._check_pattern_directory()
    assert _high(chk) == []


@responses.activate
def test_oembed_surface_from_index_without_submitting_any_url():
    """oEmbed : surface signalée d'après l'index REST, sans jamais soumettre
    d'URL (interne ou non) aux routes oEmbed."""
    responses.add(responses.GET, "https://cible.test/wp-json/",
                  json={"namespaces": ["oembed/1.0"],
                        "routes": {"/oembed/1.0/embed": {}, "/oembed/1.0/proxy": {}}},
                  status=200)
    responses.add(responses.GET, re.compile(r".*oembed.*"), json={}, status=200)
    chk = make_check(RestApiCheck)
    chk._check_oembed_ssrf()
    found = [f for f in chk._result.findings if "oembed" in f["message"].lower()]
    assert len(found) == 1
    assert found[0]["severity"] == "INFO"
    assert "non évaluable passivement" in found[0]["message"]
    assert not any("oembed" in c.request.url for c in responses.calls)
    for c in responses.calls:
        assert "url=" not in c.request.url
