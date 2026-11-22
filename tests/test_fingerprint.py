import responses
from wp_security_forsure.scanner.checks.fingerprint import FingerprintCheck
from tests.conftest import make_check

HOME = """<html><head>
<meta name="generator" content="WordPress 6.4.3" />
<link rel="stylesheet" href="https://cible.test/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.2.0" />
<link rel="stylesheet" href="https://cible.test/wp-content/themes/astra/style.css?ver=4.0.0" />
<script src="https://cible.test/wp-content/plugins/akismet/akismet.js?ver=5.1"></script>
</head><body>ok</body></html>"""


@responses.activate
def test_fingerprint_builds_inventory():
    responses.add(responses.GET, "https://cible.test/", body=HOME, status=200,
                  content_type="text/html; charset=UTF-8")
    responses.add(responses.GET,
                  "https://cible.test/wp-content/plugins/contact-form-7/readme.txt",
                  body="=== Contact Form 7 ===\nStable tag: 5.2.0\n", status=200)
    responses.add(responses.GET,
                  "https://cible.test/wp-content/plugins/akismet/readme.txt", status=404)
    responses.add(responses.GET,
                  "https://cible.test/wp-content/themes/astra/style.css",
                  body="/*\nTheme Name: Astra\nVersion: 4.0.0\n*/", status=200)
    chk = make_check(FingerprintCheck)
    chk.context = {}
    chk.run()
    inv = chk.context["inventory"]
    assert inv["core"]["version"] == "6.4.3"
    plugins = {p["slug"]: p for p in inv["plugins"]}
    assert plugins["contact-form-7"]["version"] == "5.2.0"
    assert plugins["contact-form-7"]["source"] == "readme"
    assert plugins["akismet"]["version"] == "5.1"
    assert plugins["akismet"]["source"] == "ver_param"
    themes = {t["slug"]: t for t in inv["themes"]}
    assert themes["astra"]["version"] == "4.0.0"
