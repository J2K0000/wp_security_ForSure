"""P3, wp_features : fonctionnalités WordPress par défaut & protégées (401,
endpoints natifs) ne doivent pas être signalées HIGH/CRITICAL."""
import re
import responses
from wp_security_forsure.scanner.checks.wp_features import WPFeaturesCheck
from tests.conftest import make_check


def _sev(chk, *sevs):
    return [f for f in chk._result.findings if f["severity"] in sevs]


@responses.activate
def test_app_passwords_401_not_high():
    responses.add(responses.GET,
                  "https://cible.test/wp-json/wp/v2/users/me/application-passwords",
                  json={"code": "rest_not_logged_in"}, status=401)
    chk = make_check(WPFeaturesCheck)
    chk._check_application_passwords()
    assert _sev(chk, "HIGH", "CRITICAL") == []


@responses.activate
def test_app_passwords_200_still_critical():
    responses.add(responses.GET,
                  "https://cible.test/wp-json/wp/v2/users/me/application-passwords",
                  json=[{"uuid": "x"}], status=200)
    chk = make_check(WPFeaturesCheck)
    chk._check_application_passwords()
    assert _sev(chk, "CRITICAL")


@responses.activate
def test_oembed_embed_not_high():
    """oEmbed lu dans l'index REST : INFO, et la route n'est jamais appelée
    avec une URL (aucune récupération déclenchée côté cible)."""
    responses.add(responses.GET, "https://cible.test/wp-json/",
                  json={"namespaces": ["oembed/1.0"],
                        "routes": {"/oembed/1.0/embed": {}}}, status=200)
    responses.add(responses.GET, re.compile(r".*/wp-json/oembed/1\.0/embed.*"),
                  json={"title": "Home", "provider_name": "WP"}, status=200,
                  content_type="application/json")
    chk = make_check(WPFeaturesCheck)
    chk._check_oembed()
    assert _sev(chk, "HIGH", "CRITICAL") == []
    assert [f["severity"] for f in chk._result.findings] == ["INFO"]
    assert not any("oembed" in c.request.url for c in responses.calls)


@responses.activate
def test_site_health_401_without_open_tests_not_high():
    responses.add(responses.GET, "https://cible.test/wp-json/wp-site-health/v1",
                  json={"code": "rest_forbidden"}, status=401)
    # sous-endpoints de test tous protégés (401)
    responses.add(responses.GET, re.compile(r".*/wp-site-health/v1/tests/.*"),
                  json={"code": "rest_forbidden"}, status=401)
    chk = make_check(WPFeaturesCheck)
    chk._check_site_health()
    assert _sev(chk, "HIGH", "CRITICAL") == []


@responses.activate
def test_heartbeat_is_never_probed():
    """Inversé : la sonde Heartbeat (POST admin-ajax.php) est retirée."""
    responses.add(responses.POST, "https://cible.test/wp-admin/admin-ajax.php",
                  body="-1", status=200)
    assert not hasattr(WPFeaturesCheck, "_check_heartbeat")
    assert len(responses.calls) == 0


@responses.activate
def test_wp_cron_is_never_requested():
    """Inversé : wp-cron.php n'est plus demandé (un GET lance les tâches
    planifiées du site) ; constat INFO « non évaluable de l'extérieur »."""
    responses.add(responses.HEAD, "https://cible.test/wp-cron.php", status=200)
    responses.add(responses.GET, "https://cible.test/wp-cron.php",
                  body="<html>" + ("x" * 1000) + "</html>", status=200)
    chk = make_check(WPFeaturesCheck)
    chk._check_wp_cron()
    assert len(responses.calls) == 0
    assert _sev(chk, "HIGH", "MEDIUM", "LOW") == []
    msgs = [f["message"] for f in chk._result.findings]
    assert any("wp-cron.php" in m and "non évaluable de l'extérieur" in m
               for m in msgs), msgs
