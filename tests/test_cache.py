from wp_security_forsure.scanner.vulndb.cache import VulnCache


def test_miss_then_fetch_then_hit(tmp_path):
    calls = {"n": 0}
    def client(t, slug):
        calls["n"] += 1
        return {"data": {"plugin": slug, "vulnerability": []}}
    c = VulnCache(str(tmp_path / "c.sqlite"))
    r1, stale1 = c.get_or_fetch("plugin", "cf7", client, ttl_days=7, now=1000)
    assert calls["n"] == 1 and stale1 is False and r1["data"]["plugin"] == "cf7"
    r2, stale2 = c.get_or_fetch("plugin", "cf7", client, ttl_days=7, now=1000)
    assert calls["n"] == 1 and stale2 is False


def test_expired_refetch(tmp_path):
    calls = {"n": 0}
    def client(t, slug):
        calls["n"] += 1
        return {"data": {"plugin": slug}}
    c = VulnCache(str(tmp_path / "c.sqlite"))
    c.get_or_fetch("plugin", "cf7", client, ttl_days=1, now=0)
    c.get_or_fetch("plugin", "cf7", client, ttl_days=1, now=2 * 86400)
    assert calls["n"] == 2


def test_network_fail_returns_stale(tmp_path):
    c = VulnCache(str(tmp_path / "c.sqlite"))
    c.get_or_fetch("plugin", "cf7", lambda t, s: {"data": {"plugin": s}}, ttl_days=1, now=0)
    payload, stale = c.get_or_fetch("plugin", "cf7", lambda t, s: None,
                                    ttl_days=1, now=10 * 86400)
    assert stale is True and payload["data"]["plugin"] == "cf7"


def test_no_cache_no_network(tmp_path):
    c = VulnCache(str(tmp_path / "c.sqlite"))
    payload, stale = c.get_or_fetch("plugin", "x", lambda t, s: None, ttl_days=1, now=0)
    assert payload is None
