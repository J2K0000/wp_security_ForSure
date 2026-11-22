"""P7, matcher CVE : un operator sans aucune borne exploitable ne doit PAS
matcher toutes les versions (sinon une install à jour est signalée vulnérable).
Les bornes lt/le explicites restent respectées (pas de faux négatif)."""
from wp_security_forsure.scanner.vulndb.matcher import matches


def test_no_bound_operator_matches_nothing():
    assert matches("5.0", {}) is False
    assert matches("5.0", {"unfixed": "1"}) is False  # pas de min/max exploitable


def test_min_only_still_works():
    op = {"min_version": "4.0", "min_operator": "ge"}
    assert matches("5.0", op) is True
    assert matches("3.0", op) is False


def test_max_lt_excludes_fixed_version():
    # max_version = version corrigée, operator lt → la version corrigée n'est PAS vulnérable
    op = {"max_version": "5.2", "max_operator": "lt"}
    assert matches("5.1", op) is True
    assert matches("5.2", op) is False


def test_max_le_includes_last_affected():
    op = {"max_version": "5.2", "max_operator": "le"}
    assert matches("5.2", op) is True
    assert matches("5.3", op) is False


def test_range_min_max():
    op = {"min_version": "4.0", "min_operator": "ge",
          "max_version": "5.2", "max_operator": "lt"}
    assert matches("4.5", op) is True
    assert matches("5.2", op) is False
    assert matches("3.9", op) is False
