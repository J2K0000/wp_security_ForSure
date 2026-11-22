from wp_security_forsure.scanner.checks import signatures as sig


def test_already_installed_fr():
    body = "<h1>Déjà installé</h1><p>Il semblerait que WordPress soit déjà installé.</p>"
    assert sig.is_already_installed(body) is True


def test_already_installed_en():
    body = "<h1>Already Installed</h1><p>You appear to have already installed WordPress.</p>"
    assert sig.is_already_installed(body) is True


def test_install_form_is_not_already_installed():
    body = "<form><input name='weblog_title'><input name='admin_email'></form>"
    assert sig.is_already_installed(body) is False


def test_benign_after_html_cache_comment():
    txt = "<!-- Page cached by LiteSpeed Cache 7.8.1 on 2026-07-15 14:17:08 -->"
    assert sig.is_benign_after_html(txt) is True


def test_benign_after_html_real_injection():
    txt = "<script>document.location='http://evil.com'</script>"
    assert sig.is_benign_after_html(txt) is False


def test_matches_baseline_same():
    base = {"status": 200, "size": 208000, "prefix": "<!DOCTYPE html>"}
    assert sig.matches_baseline(200, 208050, "<!DOCTYPE html>", base) is True


def test_matches_baseline_different_status():
    base = {"status": 200, "size": 208000, "prefix": "<!DOCTYPE html>"}
    assert sig.matches_baseline(201, 12, "created", base) is False
