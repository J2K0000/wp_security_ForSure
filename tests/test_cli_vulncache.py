from wp_security_forsure.scanner.vulndb.cache import VulnCache


def test_vulncache_info_and_clear(tmp_path):
    db = str(tmp_path / "c.sqlite")
    c = VulnCache(db)
    c.put("plugin", "cf7", {"data": {}}, now=1000)
    assert c.info()["entries"] == 1
    c.clear()
    assert c.info()["entries"] == 0
