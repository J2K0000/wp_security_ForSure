"""Cache CVE et snapshot EPSS : dossier de cache utilisateur, jamais le dossier
du paquet (casse une installation pip), surchargeable par variable d'env."""
from pathlib import Path

import wp_security_forsure
from wp_security_forsure import __main__ as cli
from wp_security_forsure.scanner.checks.vulnerability_scan import VulnerabilityScanCheck
from wp_security_forsure.scanner.vulndb import cache as cache_mod
from tests.conftest import make_check

PACKAGE_DIR = Path(wp_security_forsure.__file__).resolve().parent


def test_env_override_wins(tmp_path):
    env = {"WP_SECURITY_FORSURE_CACHE_DIR": str(tmp_path / "x"),
           "LOCALAPPDATA": "C:/Users/u/AppData/Local"}
    assert cache_mod.user_cache_dir(environ=env, platform="win32") == tmp_path / "x"


def test_windows_uses_localappdata():
    env = {"LOCALAPPDATA": "C:/Users/u/AppData/Local"}
    assert cache_mod.user_cache_dir(environ=env, platform="win32") == \
        Path("C:/Users/u/AppData/Local") / "wp_security_forsure"


def test_xdg_cache_home_on_posix():
    env = {"XDG_CACHE_HOME": "/srv/cache"}
    assert cache_mod.user_cache_dir(environ=env, platform="linux") == \
        Path("/srv/cache") / "wp_security_forsure"


def test_relative_xdg_is_ignored_and_home_cache_used(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    env = {"XDG_CACHE_HOME": "relative/cache"}
    assert cache_mod.user_cache_dir(environ=env, platform="darwin") == \
        tmp_path / ".cache" / "wp_security_forsure"


def test_paths_live_in_cache_dir_not_package(tmp_path, monkeypatch):
    monkeypatch.setenv("WP_SECURITY_FORSURE_CACHE_DIR", str(tmp_path))
    assert cache_mod.vulncache_path() == tmp_path / "vulncache.sqlite"
    assert cache_mod.epss_path() == tmp_path / "epss.csv"
    assert PACKAGE_DIR not in cache_mod.vulncache_path().resolve().parents


def test_tests_never_use_the_real_user_cache():
    # La fixture autouse de conftest isole chaque test.
    real = cache_mod.user_cache_dir(environ={}, platform="win32")
    assert cache_mod.user_cache_dir() != real


def test_vulnerability_scan_backend_uses_cache_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("WP_SECURITY_FORSURE_CACHE_DIR", str(tmp_path))
    chk = make_check(VulnerabilityScanCheck)
    chk._ensure_backend()
    assert Path(chk._cache.db_path) == tmp_path / "vulncache.sqlite"
    assert (tmp_path / "vulncache.sqlite").exists()


def test_vulnerability_scan_without_component_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("WP_SECURITY_FORSURE_CACHE_DIR", str(tmp_path / "c"))
    chk = make_check(VulnerabilityScanCheck)
    chk.context = {"inventory": {"core": {}, "plugins": [], "themes": []}}
    chk.run()
    assert not (tmp_path / "c").exists()


def test_cli_vulncache_uses_cache_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WP_SECURITY_FORSURE_CACHE_DIR", str(tmp_path))
    assert cli.main(["vulncache", "--info"]) == 0
    out = capsys.readouterr().out
    assert str(tmp_path) in out
    assert (tmp_path / "vulncache.sqlite").exists()


def test_cli_refresh_epss_writes_to_cache_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WP_SECURITY_FORSURE_CACHE_DIR", str(tmp_path))
    seen = {}

    def fake_refresh(dest, *a, **k):
        seen["dest"] = Path(dest)
        return Path(dest)

    monkeypatch.setattr(cli, "refresh_epss", fake_refresh)
    assert cli.main(["refresh-epss"]) == 0
    assert seen["dest"] == tmp_path / "epss.csv"
