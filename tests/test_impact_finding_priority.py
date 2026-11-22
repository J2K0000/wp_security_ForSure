"""classify()/narrative() donnent priorité aux champs du finding (chantier A)."""
from wp_security_forsure.scanner.reporters import impact


def test_classify_prefers_finding_access_class():
    # Le check défaut de rest_api est 'recon' ; le finding force 'pii'.
    f = {"message": "endpoint générique", "access_class": "pii"}
    assert impact.classify("rest_api", f["message"], f) == "pii"


def test_classify_without_finding_class_keeps_message_refine():
    # Sans access_class explicite : comportement historique (affinage message).
    f = {"message": "user enumeration via /wp/v2/users"}
    assert impact.classify("rest_api", f["message"], f) == "pii"


def test_classify_falls_back_to_check_default():
    f = {"message": "en-tête HSTS manquant"}
    assert impact.classify("security_headers", f["message"], f) == "recon"


def test_narrative_prefers_finding_impact():
    f = {"message": "peu importe",
         "access_class": "controle",
         "impact": {"data": "D", "path": "P", "enables": "E"}}
    n = impact.narrative("forms_upload", f["message"], f)
    assert n["classe"] == "controle"
    assert (n["data"], n["path"], n["enables"]) == ("D", "P", "E")


def test_narrative_without_finding_impact_uses_message():
    f = {"message": "wp2shell RCE pré-auth via batch"}
    n = impact.narrative("rest_batch", f["message"], f)
    assert n["classe"] == "controle"
    assert "code arbitraire" in n["data"].lower()


def test_backward_compatible_two_arg_calls():
    # Les appels existants à 2 arguments doivent continuer de marcher.
    assert impact.classify("ssl_tls", "TLS 1.0 accepté") == "recon"
    n = impact.narrative("rest_batch", "wp2shell RCE pré-auth")
    assert n["classe"] == "controle"
