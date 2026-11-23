"""Garde-fou : aucun check enregistré ne tombe sur un défaut de classe oublié."""
from wp_security_forsure.scanner.engine import CHECK_REGISTRY
from wp_security_forsure.scanner.reporters.impact import _CLASS_BY_CHECK, _CLASS_ORDER
from wp_security_forsure.scanner.reporters import impact


# Checks récents dont la classe par défaut reste à ajouter à


def test_every_registered_check_has_a_default_class():
    missing = sorted(set(CHECK_REGISTRY) - set(_CLASS_BY_CHECK))
    assert not missing, f"Checks sans classe par défaut : {missing}"


def test_all_default_classes_are_valid():
    invalid = {name: cls for name, cls in _CLASS_BY_CHECK.items()
               if cls not in _CLASS_ORDER}
    assert not invalid, f"Classes invalides : {invalid}"


def test_classify_ignores_unknown_access_class_and_falls_through():
    # access_class hors vocabulaire => on ignore et on retombe sur l'affinage
    # message / défaut du check (ici user-enum => pii), sans planter.
    f = {"message": "user enumeration via /wp/v2/users",
         "access_class": "not-a-real-class"}
    assert impact.classify("rest_api", f["message"], f) == "pii"


def test_narrative_survives_unknown_access_class():
    # narrative ne doit pas lever KeyError sur une classe inconnue.
    f = {"message": "en-tête HSTS manquant", "access_class": "bogus"}
    n = impact.narrative("security_headers", f["message"], f)
    assert n["classe"] in impact._CLASS_ORDER
