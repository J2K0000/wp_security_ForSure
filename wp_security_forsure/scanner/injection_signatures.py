"""Signatures d'injections côté navigateur : ClickFix et EtherHiding.

Les motifs sont dans ``wp_security_forsure/signatures/injection_signatures.yaml``,
avec leurs sources. Ce module ne fait aucune requête : il lit un texte (script
en ligne, fichier JavaScript, contenu décodé d'un script ``data:``, contenu du
presse-papiers capturé par la passe de rendu) et rend des constats.

Règles de combinaison, pour limiter les faux positifs (un blog technique peut
citer PowerShell, une bibliothèque de coloration syntaxique contient à la fois
une grammaire PowerShell et un bouton « copier ») :

ClickFix, dans un même script :
  - écriture dans le presse-papiers + commande + (raccourci ou terme de faux
    CAPTCHA) : CRITICAL ;
  - écriture dans le presse-papiers + commande : HIGH ;
  - raccourci clavier + terme de faux CAPTCHA : HIGH ;
  - écriture dans le presse-papiers + raccourci clavier : HIGH.

EtherHiding, dans un même script :
  - adresse de contrat publiée comme infrastructure : CRITICAL, confirmé ;
  - sélecteur de fonction UNC5142 ou marqueur de campagne : CRITICAL ;
  - appel JSON-RPC ``eth_call`` ou client Web3, avec un nœud RPC connu ou une
    adresse de contrat : HIGH ;
  - chaîne atob, puis ungzip ou inflate, puis eval ou Function : HIGH.

Sauf mention, la confiance est « potential » : une signature statique est un
indice à confirmer, pas une observation du comportement de la page.
"""

from __future__ import annotations

import base64
import binascii
import functools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import yaml

SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "signatures" / "injection_signatures.yaml"

# Taille maximale analysée par texte (les scripts plus longs sont tronqués).
MAX_SCAN_CHARS = 3 * 1024 * 1024
# Taille maximale d'un script data: décodé.
MAX_DATA_SCRIPT_BYTES = 1024 * 1024
_FLAGS = re.IGNORECASE


@dataclass(frozen=True)
class Hit:
    """Un constat de signature."""
    family: str          # "clickfix" | "etherhiding" | "campaign"
    rule: str            # identifiant stable de la règle
    severity: str        # CRITICAL | HIGH | MEDIUM
    confidence: str      # confirmed | potential
    label: str           # description lisible (français)
    excerpt: str = ""    # extrait neutralisé (hxxp), borné
    source: str = ""     # URL de la source publique


@dataclass
class Signatures:
    """Motifs compilés depuis le fichier YAML."""
    keystrokes: List[Tuple[str, str, re.Pattern]] = field(default_factory=list)
    lure_terms: List[re.Pattern] = field(default_factory=list)
    clipboard_write: List[re.Pattern] = field(default_factory=list)
    commands: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    rpc_hosts: List[Tuple[str, re.Pattern, str]] = field(default_factory=list)
    contracts: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    selectors: List[str] = field(default_factory=list)
    rpc_call: Dict[str, re.Pattern] = field(default_factory=dict)
    loader_chain: Dict[str, re.Pattern] = field(default_factory=dict)
    libraries: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    campaign_markers: List[Tuple[str, re.Pattern, str, str]] = field(default_factory=list)
    clickfix_sources: List[str] = field(default_factory=list)
    version: int = 0


def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern, _FLAGS)


def parse_signatures(data: dict) -> Signatures:
    """Compile le contenu du fichier YAML. Lève ValueError si un motif est
    invalide ou si une section attendue manque."""
    try:
        cf, eh = data["clickfix"], data["etherhiding"]
        sig = Signatures(version=int(data.get("version", 0)))
        sig.keystrokes = [(k["id"], k["label"], _compile(k["pattern"]))
                          for k in cf["keystrokes"]]
        sig.lure_terms = [_compile(p) for p in cf["lure_terms"]]
        sig.clipboard_write = [_compile(p) for p in cf["clipboard_write"]]
        sig.commands = [(c["id"], _compile(c["pattern"])) for c in cf["commands"]]
        sig.clickfix_sources = list(cf.get("source") or [])
        sig.rpc_hosts = [(h["id"], _compile(h["pattern"]), h["source"])
                         for h in eh["rpc_hosts"]]
        sig.contracts = {c["address"].lower(): (c["family"], c["source"])
                         for c in eh["contracts"]}
        sig.selectors = [s.lower() for s in eh["selectors"]]
        sig.rpc_call = {k: _compile(v) for k, v in eh["rpc_call"].items()}
        sig.loader_chain = {k: _compile(v) for k, v in eh["loader_chain"].items()}
        sig.libraries = [(lib["id"], _compile(lib["pattern"])) for lib in eh["libraries"]]
        sig.campaign_markers = [(m["id"], _compile(m["pattern"]), m["family"], m["source"])
                                for m in data["campaign_markers"]]
    except (KeyError, TypeError, re.error) as exc:
        raise ValueError(f"injection_signatures.yaml invalide : {exc}") from exc
    for address in sig.contracts:
        if not re.fullmatch(r"0x[0-9a-f]{40}", address):
            raise ValueError(f"adresse de contrat invalide : {address}")
    return sig


@functools.lru_cache(maxsize=1)
def load_signatures() -> Signatures:
    """Signatures livrées avec le paquet (lues une fois)."""
    with open(SIGNATURES_PATH, encoding="utf-8") as fh:
        return parse_signatures(yaml.safe_load(fh))


# ── Mise en forme des extraits ───────────────────────────────────────────

def defang(text: str) -> str:
    """Neutralise les URL d'un extrait (http -> hxxp) pour qu'aucun lecteur
    du rapport ne les ouvre par un clic."""
    return re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", text or "")


def excerpt(text: str, match: Optional[re.Match], width: int = 70) -> str:
    """Extrait borné autour d'une correspondance, espaces réduits, neutralisé."""
    if not text:
        return ""
    if match is None:
        start, end = 0, min(len(text), 2 * width)
    else:
        start, end = max(0, match.start() - width), min(len(text), match.end() + width)
    snippet = re.sub(r"\s+", " ", text[start:end]).strip()
    return defang(snippet)[:240]


def _first(patterns: Iterable[re.Pattern], text: str) -> Optional[re.Match]:
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            return m
    return None


# ── Commandes (presse-papiers et scripts) ────────────────────────────────

def command_matches(text: str, sig: Optional[Signatures] = None) -> List[str]:
    """Identifiants des motifs de commande présents dans `text`."""
    sig = sig or load_signatures()
    return [cid for cid, pattern in sig.commands if pattern.search(text or "")]


def keystroke_matches(text: str, sig: Optional[Signatures] = None) -> List[str]:
    sig = sig or load_signatures()
    return [label for _, label, pattern in sig.keystrokes if pattern.search(text or "")]


def has_lure_terms(text: str, sig: Optional[Signatures] = None) -> bool:
    sig = sig or load_signatures()
    return _first(sig.lure_terms, text or "") is not None


# ── Analyse d'un script ──────────────────────────────────────────────────

def _clickfix_hits(text: str, sig: Signatures) -> List[Hit]:
    clip = _first(sig.clipboard_write, text)
    commands = [(cid, p.search(text)) for cid, p in sig.commands]
    commands = [(cid, m) for cid, m in commands if m]
    keys = [(label, p.search(text)) for _, label, p in sig.keystrokes]
    keys = [(label, m) for label, m in keys if m]
    lure = _first(sig.lure_terms, text)
    source = sig.clickfix_sources[0] if sig.clickfix_sources else ""
    hits: List[Hit] = []
    if clip and commands and (keys or lure):
        hits.append(Hit(
            "clickfix", "clickfix_full", "CRITICAL", "potential",
            "ClickFix : le script copie une commande dans le presse-papiers et "
            "affiche des instructions de faux CAPTCHA ("
            + ", ".join(sorted({cid for cid, _ in commands})) + ")",
            excerpt(text, commands[0][1]), source))
    elif clip and commands:
        hits.append(Hit(
            "clickfix", "clickfix_clipboard_command", "HIGH", "potential",
            "ClickFix possible : le script écrit dans le presse-papiers et contient "
            "une commande système (" + ", ".join(sorted({cid for cid, _ in commands})) + ")",
            excerpt(text, commands[0][1]), source))
    elif keys and lure:
        hits.append(Hit(
            "clickfix", "clickfix_lure", "HIGH", "potential",
            "ClickFix possible : instructions au clavier (" + keys[0][0]
            + ") associées à un faux CAPTCHA",
            excerpt(text, keys[0][1]), source))
    elif clip and keys:
        hits.append(Hit(
            "clickfix", "clickfix_clipboard_keystroke", "HIGH", "potential",
            "ClickFix possible : écriture dans le presse-papiers et instructions "
            "au clavier (" + keys[0][0] + ")",
            excerpt(text, keys[0][1]), source))
    return hits


def _etherhiding_hits(text: str, sig: Signatures) -> List[Hit]:
    hits: List[Hit] = []
    low = text.lower()
    for address in re.findall(r"0x[0-9a-f]{40}", low):
        if address in sig.contracts:
            family, source = sig.contracts[address]
            m = re.search(re.escape(address), low)
            hits.append(Hit(
                "etherhiding", "etherhiding_contract", "CRITICAL", "confirmed",
                f"EtherHiding : adresse de contrat publiée comme infrastructure "
                f"malveillante ({family})", excerpt(text, m), source))
            break
    for selector in sig.selectors:
        idx = low.find(selector)
        if idx >= 0:
            m = re.search(re.escape(selector), low)
            hits.append(Hit(
                "etherhiding", "etherhiding_selector", "CRITICAL", "potential",
                "EtherHiding : sélecteur de fonction du contrat UNC5142",
                excerpt(text, m),
                "https://cloud.google.com/blog/topics/threat-intelligence/"
                "unc5142-etherhiding-distribute-malware"))
            break
    rpc = sig.rpc_call
    call = rpc["method"].search(text) if rpc["jsonrpc"].search(text) else None
    client = rpc["client"].search(text)
    host_match = None
    for _, pattern, _ in sig.rpc_hosts:
        # Les motifs d'hôte sont ancrés : on les applique aux noms d'hôte
        # présents dans le texte.
        for host in re.findall(r"https?://([a-z0-9.-]+)", low):
            if pattern.search(host):
                host_match = host
                break
        if host_match:
            break
    address = rpc["address"].search(text)
    if (call or client) and (host_match or address):
        anchor = call or client
        what = "appel JSON-RPC eth_call" if call else "client Web3"
        where = f"nœud {host_match}" if host_match else "adresse de contrat"
        hits.append(Hit(
            "etherhiding", "etherhiding_rpc", "HIGH", "potential",
            f"EtherHiding possible : {what} vers un {where} (lecture d'un contrat "
            "sur une blockchain, normal seulement pour un site qui a une fonction Web3)",
            excerpt(text, anchor),
            "https://cloud.google.com/blog/topics/threat-intelligence/"
            "unc5142-etherhiding-distribute-malware"))
    chain = sig.loader_chain
    decode = chain["decode"].search(text)
    if decode and chain["inflate"].search(text) and chain["run"].search(text):
        hits.append(Hit(
            "etherhiding", "loader_chain", "HIGH", "potential",
            "Chargeur obscurci : décodage base64 (atob), décompression puis "
            "exécution du résultat (eval ou Function)",
            excerpt(text, decode),
            "https://cloud.google.com/blog/topics/threat-intelligence/"
            "unc5142-etherhiding-distribute-malware"))
    return hits


def _campaign_hits(text: str, sig: Signatures) -> List[Hit]:
    hits = []
    for mid, pattern, family, source in sig.campaign_markers:
        m = pattern.search(text)
        if m:
            hits.append(Hit("campaign", mid, "CRITICAL", "potential",
                            f"Marqueur de campagne connue : {family}",
                            excerpt(text, m), source))
    return hits


def scan_script(text: str, sig: Optional[Signatures] = None) -> List[Hit]:
    """Constats ClickFix, EtherHiding et marqueurs de campagne d'un script."""
    if not text:
        return []
    sig = sig or load_signatures()
    text = text[:MAX_SCAN_CHARS]
    return _clickfix_hits(text, sig) + _etherhiding_hits(text, sig) + _campaign_hits(text, sig)


# ── URL de scripts ───────────────────────────────────────────────────────

def library_ids(urls: Iterable[str], sig: Optional[Signatures] = None) -> List[str]:
    """Bibliothèques blockchain ou de décodage chargées (web3, ethers, pako,
    crypto-js), d'après le chemin des URL de scripts."""
    sig = sig or load_signatures()
    found = []
    for url in urls:
        path = urlsplit(url or "").path.lower()
        for lid, pattern in sig.libraries:
            if lid not in found and pattern.search(path):
                found.append(lid)
    return found


def is_library_url(url: str, sig: Optional[Signatures] = None) -> bool:
    """True si l'URL désigne une bibliothèque blockchain connue : son contenu
    contient légitimement eth_call et JSON-RPC, il n'est donc pas analysé."""
    return bool(library_ids([url], sig))


def library_hits(urls: Iterable[str], sig: Optional[Signatures] = None) -> List[Hit]:
    """Constat sur les bibliothèques chargées : le trio du premier étage
    UNC5142 (web3, pako, crypto-js) est un indice fort ; web3 ou ethers seul
    n'est qu'un signal pour un site sans fonction Web3."""
    ids = library_ids(urls, sig)
    source = ("https://cloud.google.com/blog/topics/threat-intelligence/"
              "unc5142-etherhiding-distribute-malware")
    if {"web3", "pako", "crypto_js"} <= set(ids):
        return [Hit("etherhiding", "library_triple", "HIGH", "potential",
                    "Bibliothèques web3, pako et crypto-js chargées ensemble : trio "
                    "du premier étage EtherHiding UNC5142", ", ".join(ids), source)]
    if {"web3", "ethers"} & set(ids):
        return [Hit("etherhiding", "library_web3", "MEDIUM", "potential",
                    "Bibliothèque Web3 chargée (" + ", ".join(ids) + ") : normale "
                    "pour un site qui a une fonction Web3, suspecte sinon",
                    ", ".join(ids), source)]
    return []


def rpc_host_id(host: str, sig: Optional[Signatures] = None) -> Optional[str]:
    """Identifiant du motif si `host` est un nœud RPC ou un explorateur de
    blockchain connu."""
    sig = sig or load_signatures()
    host = (host or "").lower().rstrip(".")
    for hid, pattern, _ in sig.rpc_hosts:
        if pattern.search(host):
            return hid
    return None


def contract_family(text: str, sig: Optional[Signatures] = None) -> Optional[str]:
    """Famille de la première adresse de contrat publiée trouvée dans `text`."""
    sig = sig or load_signatures()
    for address in re.findall(r"0x[0-9a-f]{40}", (text or "").lower()):
        if address in sig.contracts:
            return sig.contracts[address][0]
    return None


# ── Scripts data: ────────────────────────────────────────────────────────

_DATA_SCRIPT_RE = re.compile(
    r"^\s*data:(?:text|application)/(?:x-)?(?:java|ecma)script(?:;[^,]*)?,", re.I)


def is_data_script(src: str) -> bool:
    return bool(_DATA_SCRIPT_RE.match(src or ""))


def decode_data_script(src: str) -> Optional[str]:
    """Contenu d'un script ``data:`` (base64 ou texte), borné, sans jamais
    l'exécuter. None si l'URL n'est pas un script data: ou ne se décode pas."""
    m = _DATA_SCRIPT_RE.match(src or "")
    if not m:
        return None
    header, payload = src[:m.end()], src[m.end():]
    if ";base64" in header.lower():
        compact = re.sub(r"\s+", "", payload)[: (MAX_DATA_SCRIPT_BYTES * 4) // 3 + 4]
        try:
            raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
        except (binascii.Error, ValueError):
            return None
        return raw[:MAX_DATA_SCRIPT_BYTES].decode("utf-8", errors="replace")
    from urllib.parse import unquote
    return unquote(payload)[:MAX_DATA_SCRIPT_BYTES]
