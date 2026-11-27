"""Helpers de test : instancier un check avec une session requests réelle
(les réponses HTTP sont mockées par la lib `responses` dans chaque test)."""
import pytest
import requests


@pytest.fixture(autouse=True)
def _isolated_cache_dir(tmp_path_factory, monkeypatch):
    """Cache CVE et snapshot EPSS dans un dossier temporaire : aucun test
    n'écrit dans le dossier de cache utilisateur réel."""
    cache_dir = tmp_path_factory.mktemp("wpsf-cache")
    monkeypatch.setenv("WP_SECURITY_FORSURE_CACHE_DIR", str(cache_dir))


def make_check(check_cls, target="https://cible.test", config=None):
    """Instancie un check prêt à l'emploi avec une session requests neuve.

    Par défaut en mode `authorized` : les tests unitaires éprouvent la logique
    de chaque sonde, y compris celles de niveau 2. Le mode par défaut du
    scanner (sans autorisation) est éprouvé en passant
    `config={"authorized": False}` (test_access_tiers, test_authorized_mode,
    test_passivity)."""
    cfg = {"timeout": 5, "user_agent": "wp_security_ForSure-test",
           "authorized": True}
    if config:
        cfg.update(config)
    session = requests.Session()
    session.verify = False
    return check_cls(target, cfg, session)


# ── DNS hors ligne ───────────────────────────────────────────────────────
# La garde SSRF de BaseCheck résout chaque hôte avant d'émettre une requête.
# Pour que la suite reste 100 % hors ligne (et rapide), socket.getaddrinfo est
# remplacé par un faux résolveur : une IP littérale se résout en elle-même, un
# nom en une adresse publique fixe. Un test qui veut simuler un nom pointant
# vers une plage interne remonkeypatche socket.getaddrinfo (ou resolve_host).
import ipaddress
import socket

import pytest

FAKE_PUBLIC_IP = "93.184.216.34"


def offline_getaddrinfo(host, port=None, *args, **kwargs):
    name = host.decode() if isinstance(host, bytes) else str(host or "")
    name = name.strip("[]")
    try:
        addr = str(ipaddress.ip_address(name.split("%", 1)[0]))
    except ValueError:
        addr = FAKE_PUBLIC_IP
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port or 0))]


@pytest.fixture(autouse=True)
def _dns_hors_ligne(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", offline_getaddrinfo)


# ── Cadence ──────────────────────────────────────────────────────────────
# Le client HTTP espace les requêtes vers la cible (request_delay). Les tests
# n'attendent pas : l'attente est remplacée par un relevé, que
# tests/test_target_guard.py lit pour vérifier les délais.
@pytest.fixture(autouse=True)
def _sans_attente(monkeypatch):
    from wp_security_forsure.scanner.checks import base
    waits = []
    monkeypatch.setattr(base, "_sleep", waits.append)
    # Les mocks `responses` répondent ConnectionError à toute URL non prévue :
    # sans réglage explicite, ni nouvelle tentative ni détection de blocage
    # (les tests qui chargent config.yaml, et test_target_guard.py, les ont).
    monkeypatch.setattr(base, "DEFAULT_BLOCK_STREAK", 0)
    monkeypatch.setattr(base, "DEFAULT_CONNECTION_RETRIES", 0)
    return waits
