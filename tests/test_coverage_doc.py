"""La carte de couverture (docs/COVERAGE.md, docs/COUVERTURE.md) reste
cohérente avec le code : checks cités existants, effectifs annoncés exacts,
mêmes classes au même statut dans les deux langues."""
import re
from pathlib import Path

import pytest

from wp_security_forsure.scanner.engine import CHECK_REGISTRY

DOCS = Path(__file__).resolve().parent.parent / "docs"
SECTIONS = {
    "COVERAGE.md": ("Tested", "Partly tested", "Invisible from outside", "Active only"),
    "COUVERTURE.md": ("Testées", "Testées en partie", "Invisibles de l'extérieur",
                      "Actives seulement"),
}
EXPECTED = (11, 15, 10, 14)


def sections(name):
    text = (DOCS / name).read_text(encoding="utf-8")
    out = {}
    for title in SECTIONS[name]:
        m = re.search(r"^## " + re.escape(title) + r"\n(.*?)(?=^## |\Z)", text, re.M | re.S)
        assert m, (name, title)
        out[title] = re.findall(r"^\| (C\d\d) \|", m.group(1), re.M)
    return text, out


@pytest.mark.parametrize("name", list(SECTIONS))
def test_counts_match_the_announced_figures(name):
    text, found = sections(name)
    counts = tuple(len(found[t]) for t in SECTIONS[name])
    assert counts == EXPECTED
    for n in EXPECTED:
        assert f"({n})" in text
    ids = [i for ids in found.values() for i in ids]
    assert sorted(ids) == [f"C{n:02d}" for n in range(1, 51)]


def test_both_languages_classify_alike():
    _, en = sections("COVERAGE.md")
    _, fr = sections("COUVERTURE.md")
    for en_title, fr_title in zip(SECTIONS["COVERAGE.md"], SECTIONS["COUVERTURE.md"]):
        assert sorted(en[en_title]) == sorted(fr[fr_title]), en_title


@pytest.mark.parametrize("name", list(SECTIONS))
def test_every_cited_check_exists(name):
    text = (DOCS / name).read_text(encoding="utf-8")
    # Tout identifiant en minuscules entre accents graves est un nom de check,
    # sauf les réglages et commandes listés ici.
    cited = set(re.findall(r"`([a-z][a-z0-9_]*)`", text))
    not_checks = {"display_errors", "auto_prepend_file", "openssl", "wp_",
                  "admin", "test", "integrity"}  # noms de comptes, attribut HTML
    unknown = sorted(c for c in cited - not_checks if c not in CHECK_REGISTRY)
    assert unknown == [], unknown
    assert "fingerprint" in cited and "ssl_tls" in cited


def test_readmes_link_the_map():
    root = DOCS.parent
    assert "docs/COVERAGE.md" in (root / "README.md").read_text(encoding="utf-8")
    assert "docs/COUVERTURE.md" in (root / "README.fr.md").read_text(encoding="utf-8")
