"""Rate-limiting, redesign passif (voir aussi test_brute_force_login_passive.py).

_check_rate_limiting ne soumet plus JAMAIS de tentative de connexion : elle
se contente d'un GET de wp-login.php et compare le corps/en-têtes à des
signatures de protection connues. Ce test vérifie qu'un login introuvable
(404) ne produit pas de faux positif CRITICAL, ET qu'aucun POST n'est
jamais envoyé (même si un mock POST existe, il ne doit pas être appelé)."""
import responses
from wp_security_forsure.scanner.checks.brute_force_login import BruteForceLoginCheck
from tests.conftest import make_check


@responses.activate
def test_login_404_no_false_rate_limit_critical():
    # wp-login.php introuvable → login relocalise
    responses.add(responses.GET, "https://cible.test/wp-login.php", status=404)
    responses.add(responses.POST, "https://cible.test/wp-login.php", status=404)
    chk = make_check(BruteForceLoginCheck)
    chk._check_rate_limiting()
    for f in chk._result.findings:
        assert not (f["severity"] == "CRITICAL"
                    and "rate limit" in f["message"].lower()), f

    # Détection 100% passive : aucune tentative de connexion n'est jamais
    # soumise, même quand un endpoint POST est mocké et disponible.
    post_calls = [c for c in responses.calls if c.request.method == "POST"]
    assert post_calls == [], post_calls
