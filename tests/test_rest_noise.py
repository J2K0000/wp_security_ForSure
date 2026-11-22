import inspect
from wp_security_forsure.scanner.checks import rest_api


def test_sensitive_term_search_removed():
    src = inspect.getsource(rest_api)
    # La constante et sa boucle doivent avoir disparu.
    assert "SEARCH_SENSITIVE_TERMS" not in src


def test_search_leakage_has_no_term_loop():
    src = inspect.getsource(rest_api.RestApiCheck._check_search_data_leakage)
    assert "for term in" not in src


def test_unknown_namespace_finding_is_info():
    src = inspect.getsource(rest_api.RestApiCheck)
    i = src.find("Namespace REST personnalisé")
    assert i != -1, "message namespace introuvable"
    window = src[i - 200:i + 400]
    assert 'severity="INFO"' in window
    assert 'severity="HIGH"' not in window
