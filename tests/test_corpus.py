"""Mesure de rappel : chaque scénario connu doit rester détecté."""
import pytest
from tests.corpus.scenarios import SCENARIOS


@pytest.mark.parametrize("sid,run,check", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_scenario_detected(sid, run, check, monkeypatch):
    result = run(monkeypatch)
    assert check(result.findings), f"scénario non détecté : {sid}"


def test_corpus_has_required_floor():
    # Plancher figé sur le nombre réel de scénarios : toute suppression sans
    # ajout compensatoire fait échouer ce garde-fou (pas de contraction
    # silencieuse du corpus de validation).
    assert len(SCENARIOS) >= 6
