"""P8, une erreur réseau vers api.wordpress.org ne doit pas être interprétée
comme « plugin absent = nullé »."""
import responses
from wp_security_forsure.scanner.checks.null_plugins import NulledPluginsCheck, KNOWN_NULLED_PLUGINS
from tests.conftest import make_check
from wp_security_forsure.scanner.vulndb.wporg import plugin_info_url

# Client wordpress.org partagé (vulndb.wporg) : API 1.2 plugin_information.
WPORG = plugin_info_url("contact-form-7")
REVSLIDER_WPORG = plugin_info_url("revslider")


def _crit(findings):
    return [f for f in findings if f["severity"] == "CRITICAL"]


@responses.activate
def test_network_error_does_not_flag_nulled():
    NulledPluginsCheck._wp_org_cache.clear()
    responses.add(responses.GET, WPORG, body=ConnectionError("boom"))
    chk = make_check(NulledPluginsCheck)
    plugin = {"slug": "contact-form-7", "name": "Contact Form 7", "is_premium": False}
    findings = chk._check_wp_org(plugin, {"Version": "5.0"}, "5.0")
    assert _crit(findings) == []


@responses.activate
def test_definitive_not_found_still_flags_nulled():
    NulledPluginsCheck._wp_org_cache.clear()
    responses.add(responses.GET, WPORG, json={"error": "Plugin not found."}, status=200)
    chk = make_check(NulledPluginsCheck)
    plugin = {"slug": "contact-form-7", "name": "Contact Form 7", "is_premium": False}
    findings = chk._check_wp_org(plugin, {"Version": "5.0"}, "5.0")
    crit = _crit(findings)
    assert len(crit) == 1
    # Absence sur wp.org = heuristique, pas une preuve de backdoor → potential.
    assert crit[0]["confidence"] == "potential"
    assert "backdoor" not in crit[0]["message"].lower()


@responses.activate
def test_non_200_is_indeterminate_not_nulled():
    NulledPluginsCheck._wp_org_cache.clear()
    responses.add(responses.GET, WPORG, status=429)  # rate-limit = indéterminé
    chk = make_check(NulledPluginsCheck)
    plugin = {"slug": "contact-form-7", "name": "Contact Form 7", "is_premium": False}
    findings = chk._check_wp_org(plugin, {"Version": "5.0"}, "5.0")
    assert _crit(findings) == []


@responses.activate
def test_removed_premium_plugin_is_potential_not_backdoor_certain():
    """Plugin premium dont le slug wp.org existait puis a disparu du repo :
    c'est un signal de plugin non maintenu (pas de MAJ sécurité), PAS une
    preuve de backdoor. Doit rester heuristique (confidence=potential)."""
    NulledPluginsCheck._wp_org_cache.clear()
    responses.add(responses.GET, REVSLIDER_WPORG, json={"error": "Plugin not found."}, status=200)
    chk = make_check(NulledPluginsCheck)
    plugin = {
        "slug": "revslider", "name": "Slider Revolution",
        "is_premium": True, "wp_org_slug": "revslider",
    }
    findings = chk._check_wp_org(plugin, {"Version": "6.0"}, "6.0")
    crit = _crit(findings)
    assert len(crit) == 1
    assert crit[0]["confidence"] == "potential"
    assert "backdoor" not in crit[0]["message"].lower()
    assert "assurée" not in crit[0]["message"].lower()
    assert "quasi certaine" not in crit[0]["message"].lower()


@responses.activate
def test_closed_plugin_is_potential_not_backdoor_certain():
    """Plugin marqué 'closed' sur wp.org mais encore installé : non maintenu,
    pas de preuve de backdoor. Doit rester heuristique (confidence=potential)."""
    NulledPluginsCheck._wp_org_cache.clear()
    responses.add(
        responses.GET, REVSLIDER_WPORG,
        json={"name": "Slider Revolution", "version": "6.0", "closed": True},
        status=200,
    )
    chk = make_check(NulledPluginsCheck)
    plugin = {
        "slug": "revslider", "name": "Slider Revolution",
        "is_premium": True, "wp_org_slug": "revslider",
    }
    findings = chk._check_wp_org(plugin, {"Version": "6.0"}, "6.0")
    crit = _crit(findings)
    assert len(crit) == 1
    assert crit[0]["confidence"] == "potential"
    assert "backdoor" not in crit[0]["message"].lower()
    assert "assurée" not in crit[0]["message"].lower()


@responses.activate
def test_real_content_marker_in_readme_stays_confirmed():
    """Un marqueur textuel réel de nullé trouvé dans le contenu du fichier
    (preuve directe, pas une inférence d'absence) doit rester confirmed."""
    NulledPluginsCheck._wp_org_cache.clear()
    cf7 = next(p for p in KNOWN_NULLED_PLUGINS if p["slug"] == "contact-form-7")
    base = "https://cible.test/"
    responses.add(responses.HEAD, base + cf7["paths"][0], status=200)
    responses.add(
        responses.GET, base + cf7["paths"][1],
        body="Plugin Name: Contact Form 7\nVersion: 5.0\nAuthor: Takayuki Miyoshi\n",
        status=200,
    )
    responses.add(
        responses.GET, base + cf7["paths"][2],
        body="Stable tag: 5.0\nSome text: nulled by gplfreak team\n",
        status=200,
    )
    responses.add(
        responses.GET, WPORG,
        json={"name": "Contact Form 7", "version": "5.0", "closed": False},
        status=200,
    )
    chk = make_check(NulledPluginsCheck)
    findings = chk._check_plugin(cf7)
    marker = [f for f in findings if "marqueur de nullé" in f["message"]]
    assert marker, findings
    assert marker[0].get("confidence", "confirmed") == "confirmed"


@responses.activate
def test_closed_plugin_served_as_404_by_api_1_2_is_seen_closed():
    """API 1.2 : une extension fermée est servie en HTTP 404 avec
    `error: closed` (forme réelle, fixture reset-database) : le client
    partagé la voit fermée, pas « indéterminée »."""
    import json
    from pathlib import Path
    NulledPluginsCheck._wp_org_cache.clear()
    body = json.loads((Path(__file__).parent / "fixtures" / "wporg_kev"
                       / "wp_reset-database.json").read_text(encoding="utf-8"))
    body = dict(body, slug="contact-form-7")
    responses.add(responses.GET, WPORG, json=body, status=404)
    chk = make_check(NulledPluginsCheck)
    plugin = {"slug": "contact-form-7", "name": "Contact Form 7", "is_premium": False}
    findings = chk._check_wp_org(plugin, {"Version": "5.0"}, "5.0")
    closed = [f for f in findings if "FERMÉ" in f["message"]]
    assert len(closed) == 1 and closed[0]["confidence"] == "potential"
