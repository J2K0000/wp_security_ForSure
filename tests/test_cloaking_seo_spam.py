"""Tests TDD, check cloaking + SEO spam (Japanese Keyword Hack, pharma/casino).

Le check récupère la home deux fois : une en visiteur normal, une en se faisant
passer pour Googlebot. On distingue les deux réponses via le header User-Agent
(`responses.matchers.header_matcher`).
"""
import responses
from responses.matchers import header_matcher

from wp_security_forsure.scanner.checks.cloaking_seo_spam import (
    CloakingSeoSpamCheck,
    GOOGLEBOT_UA,
)
from tests.conftest import make_check


URL = "https://cible.test/"

# Home bénigne, aucun marqueur de spam, aucun caractère japonais.
NORMAL_BODY = (
    "<html><head><title>Boulangerie Dupont</title></head><body>"
    "<h1>Bienvenue chez Dupont</h1>"
    "<p>Pain, viennoiseries et gateaux faits maison a Lyon. "
    "Ouvert du mardi au dimanche.</p>"
    "</body></html>"
)

# Home servie à Googlebot : bourrée de spam pharma/contrefaçon + japonais.
SPAM_BODY = (
    "<html><head><title>激安ブランドコピー "
    "販売店</title></head><body>"
    "<h1>スーパーコピー時計 "
    "ロレックス</h1>"
    "<p>buy cheap viagra and cialis online, best casino bonus, "
    "replica oakley and ugg boots for sale. "
    "ブランドコピー 財布 バッグ "
    "販売。</p>"
    "</body></html>"
)


def _non_info(findings):
    return [f for f in findings if f["severity"] != "INFO"]


@responses.activate
def test_cloaking_spam_served_to_googlebot():
    """(a) Googlebot reçoit du spam que le visiteur normal ne voit pas."""
    responses.add(
        responses.GET, URL, body=SPAM_BODY, status=200,
        content_type="text/html; charset=UTF-8",
        match=[header_matcher({"User-Agent": GOOGLEBOT_UA})],
    )
    responses.add(
        responses.GET, URL, body=NORMAL_BODY, status=200,
        content_type="text/html; charset=UTF-8",
    )
    chk = make_check(CloakingSeoSpamCheck)
    result = chk.run()

    findings = _non_info(result.findings)
    assert findings, "un finding est attendu quand le spam est masqué au visiteur"
    assert any(f["severity"] in ("HIGH", "CRITICAL") for f in findings), findings
    assert any(
        "cloak" in f["message"].lower() or "spam" in f["message"].lower()
        for f in findings
    ), findings
    # Le check échoue (au moins un finding non-INFO).
    assert result.passed is False


@responses.activate
def test_no_finding_when_both_ua_benign():
    """(b) Même contenu bénin pour les deux UA → aucun finding non-INFO."""
    responses.add(
        responses.GET, URL, body=NORMAL_BODY, status=200,
        content_type="text/html; charset=UTF-8",
        match=[header_matcher({"User-Agent": GOOGLEBOT_UA})],
    )
    responses.add(
        responses.GET, URL, body=NORMAL_BODY, status=200,
        content_type="text/html; charset=UTF-8",
    )
    chk = make_check(CloakingSeoSpamCheck)
    result = chk.run()

    assert _non_info(result.findings) == [], result.findings


@responses.activate
def test_runs_without_exception_when_unreachable():
    """(c) Aucune réponse enregistrée → toutes les requêtes échouent, mais le
    check ne doit pas lever d'exception."""
    chk = make_check(CloakingSeoSpamCheck)
    result = chk.run()
    assert result is chk._result


@responses.activate
def test_spam_visible_to_everyone_is_flagged():
    """Le spam servi aux deux UA (pas de cloaking) reste détecté comme spam."""
    responses.add(
        responses.GET, URL, body=SPAM_BODY, status=200,
        content_type="text/html; charset=UTF-8",
        match=[header_matcher({"User-Agent": GOOGLEBOT_UA})],
    )
    responses.add(
        responses.GET, URL, body=SPAM_BODY, status=200,
        content_type="text/html; charset=UTF-8",
    )
    chk = make_check(CloakingSeoSpamCheck)
    result = chk.run()

    findings = _non_info(result.findings)
    assert any("spam" in f["message"].lower() for f in findings), findings
    # Contenu japonais massif → au moins un CRITICAL.
    assert any(f["severity"] == "CRITICAL" for f in findings), findings


def test_registered_name():
    """Le check s'auto-enregistre sous un nom snake_case unique."""
    assert CloakingSeoSpamCheck.name == "cloaking_seo_spam"
