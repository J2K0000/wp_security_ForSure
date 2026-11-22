"""refresh-epss écrit un snapshot EPSS décompressé (chantier B)."""
import gzip
import io
from wp_security_forsure.__main__ import refresh_epss
from wp_security_forsure.scanner.vulndb.epss import load_epss


def test_refresh_epss_writes_decompressed_csv(tmp_path):
    raw = (b"#model_version:test\n"
           b"cve,epss,percentile\n"
           b"CVE-2021-24145,0.94210,0.99900\n")
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb") as g:
        g.write(raw)
    payload = gz.getvalue()

    class _Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_opener(url, timeout=0):
        return _Resp(payload)

    dest = tmp_path / "epss.csv"
    refresh_epss(dest, url="https://example.test/epss.csv.gz", opener=fake_opener)

    assert dest.exists()
    idx = load_epss(dest)
    assert idx.score_for(["CVE-2021-24145"]) == 0.9421
