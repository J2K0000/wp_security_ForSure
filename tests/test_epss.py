"""Chargeur EPSS local (chantier B)."""
from pathlib import Path

from wp_security_forsure.scanner.vulndb.epss import load_epss, EpssIndex

_FIXTURE = Path(__file__).parent / "fixtures" / "epss_sample.csv"


def test_load_parses_rows_and_skips_comments_and_header():
    idx = load_epss(_FIXTURE)
    assert isinstance(idx, EpssIndex)
    assert idx.score_for(["CVE-2021-24145"]) == 0.9421


def test_score_for_returns_max_over_multiple_cves():
    idx = load_epss(_FIXTURE)
    assert idx.score_for(["CVE-2022-1234", "CVE-2020-9999"]) == 0.5


def test_score_for_unknown_cve_is_none():
    idx = load_epss(_FIXTURE)
    assert idx.score_for(["CVE-0000-0000"]) is None


def test_score_for_empty_or_none_is_none():
    idx = load_epss(_FIXTURE)
    assert idx.score_for([]) is None
    assert idx.score_for(None) is None


def test_missing_file_gives_empty_index():
    idx = load_epss(Path("does-not-exist.csv"))
    assert isinstance(idx, EpssIndex)
    assert idx.score_for(["CVE-2021-24145"]) is None


def test_case_insensitive_cve_lookup():
    idx = load_epss(_FIXTURE)
    assert idx.score_for(["cve-2021-24145"]) == 0.9421


def test_malformed_rows_are_skipped(tmp_path):
    csv_path = tmp_path / "epss.csv"
    csv_path.write_text(
        "cve,epss,percentile\n"
        "CVE-2021-0001,0.5,0.9\n"
        "CVE-2021-0002\n"              # ligne tronquée (pas de colonne epss)
        "CVE-2021-0003,not-a-number,0.1\n"  # epss non numérique
        "CVE-2021-0004,0.25,0.4\n",
        encoding="utf-8")
    idx = load_epss(csv_path)
    # les lignes valides sont chargées, les malformées ignorées sans planter
    assert idx.score_for(["CVE-2021-0001"]) == 0.5
    assert idx.score_for(["CVE-2021-0004"]) == 0.25
    assert idx.score_for(["CVE-2021-0002"]) is None
    assert idx.score_for(["CVE-2021-0003"]) is None


def test_score_for_mixed_known_and_unknown_returns_known_max():
    idx = load_epss(_FIXTURE)
    assert idx.score_for(["CVE-2021-24145", "CVE-0000-0000"]) == 0.9421
