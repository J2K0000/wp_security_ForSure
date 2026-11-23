"""Masquage des secrets avant toute preuve, tout affichage et toute écriture.

Un secret lu sur la cible (mot de passe de base de données, clé ou sel
WordPress, jeton, clé d'API, chaîne de connexion, cookie de session, empreinte
de mot de passe, clé privée) ne doit jamais être recopié en clair dans un
rapport. On garde au plus 4 caractères (jamais plus du quart de la valeur),
puis ``***`` et la longueur : de quoi prouver la fuite sans la reproduire.
Aucune empreinte n'est ajoutée, car même tronquée elle permettrait de
confirmer hors ligne un mot de passe faible deviné.

S'applique à la source (checks d'exposition) et, en défense en profondeur,
dans les trois reporters juste avant le rendu. Le masquage est idempotent :
une valeur déjà masquée n'est pas masquée une seconde fois.
"""

import re
from typing import Any

_KEEP = 4
_MASK_MARK = "***("

# Mots qui signalent un nom de variable porteur de secret. Couvre DB_PASSWORD,
# AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY, les *_SALT, les jetons,
# clés d'API, identifiants de session et cookies d'authentification WordPress.
_SECRET_WORDS = (
    r"PASSWORD|PASSWD|PASSPHRASE|(?<![A-Za-z])PASS(?![A-Za-z])|PWD|SECRET|TOKEN"
    r"|API[_\-]?KEY|ACCESS[_\-]?KEY|PRIVATE[_\-]?KEY|_KEY|SALT|NONCE"
    r"|CREDENTIALS?|DSN|SESS(?:ION)?_?ID|wordpress_(?:logged_in|sec)_[0-9a-f]*"
)
_NAME = rf"[A-Za-z0-9_.\-]*?(?:{_SECRET_WORDS})[A-Za-z0-9_.\-]*"

# 'NOM' , 'valeur'  /  'NOM' => 'valeur'  /  "NOM": "valeur"  (define(),
# tableaux PHP, JSON, tuples SQL de wp_options). Valeur tronquée acceptée.
_QUOTED_PAIR = re.compile(
    rf"(?P<kq>['\"])(?P<name>{_NAME})(?P=kq)(?P<sep>\s*(?:,|=>|:|=)\s*)"
    r"(?:(?P<vq>['\"])(?P<val>(?:\\.|(?!(?P=vq))[^\r\n\\])*)"
    r"|(?P<uval>[A-Za-z0-9_+/=.\-]{6,}))",
    re.I)
# NOM=valeur ou NOM: valeur en début de ligne (.env, ini, YAML).
_LINE_ASSIGN = re.compile(
    rf"^(?P<pre>[ \t]*(?:export[ \t]+)?{_NAME}[ \t]*[=:][ \t]*)"
    r"(?P<val>[^\r\n]*?)[ \t]*$",
    re.I | re.M)
# nom=valeur dans une ligne (chaîne de requête, cookie).
_INLINE_ASSIGN = re.compile(
    rf"(?<![A-Za-z0-9_.\-])(?P<pre>{_NAME}=)(?P<val>[^\s'\"<>;,&]+)", re.I)
# schéma://utilisateur:motdepasse@hôte
_URL_USERINFO = re.compile(
    r"(?P<pre>\b[a-z][a-z0-9+.\-]*://[^\s:/@'\"<>]*:)(?P<val>[^\s@/'\"<>]+)(?=@)",
    re.I)
_AUTH_HEADER = re.compile(
    r"(?P<pre>\b(?:proxy-)?authorization[ \t]*:[ \t]*"
    r"(?:(?:bearer|basic|token|digest)[ \t]+)?)(?P<val>[^\s'\"<>]+)",
    re.I)
_BEARER = re.compile(r"(?P<pre>\bbearer[ \t]+)(?P<val>[A-Za-z0-9._~+/\-]+=*)", re.I)
# Formats de jetons reconnaissables sans nom de variable.
_TOKEN_FORMATS = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    r"|\bxox[abposr]-[A-Za-z0-9\-]{10,}"
    r"|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"
    r"|\bAIza[0-9A-Za-z_\-]{35}\b"
    r"|\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
# Empreintes de mots de passe (phpass WordPress, bcrypt, argon2).
_PASSWORD_HASH = re.compile(
    r"\$[PH]\$[./0-9A-Za-z]{31}"
    r"|(?:\$wp)?\$2[abxy]\$\d{2}\$[./0-9A-Za-z]{53}"
    r"|\$argon2(?:id|i|d)\$[^\s'\"<>,)]+")
_PRIVATE_KEY = re.compile(
    r"(?P<pre>-----BEGIN (?P<kind>[A-Z0-9 ]*?)PRIVATE KEY-----)(?P<val>.*?)"
    r"(?=-----END (?P=kind)PRIVATE KEY-----|\Z)",
    re.S)


def _already_masked(value: str) -> bool:
    return _MASK_MARK in value or "[REDACTED]" in value or "•••" in value


def mask_secret(value: Any) -> str:
    """Masque une valeur secrète : ``abcd***(16 car.)``.

    Au plus 4 caractères conservés, et jamais plus du quart de la valeur :
    un mot de passe court ne doit pas être presque entièrement révélé.
    Aucune empreinte n'est ajoutée : même tronquée, une empreinte permet de
    confirmer hors ligne un mot de passe faible deviné.
    """
    value = "" if value is None else str(value)
    if not value or _already_masked(value):
        return value
    keep = min(_KEEP, len(value) // 4)
    return f"{value[:keep]}***({len(value)} car.)"


def _skip(text: str, match, group: str = "val") -> bool:
    """Valeur vide, déjà masquée, ou préfixe d'un masque existant."""
    value = match.group(group)
    return (not value or _already_masked(value)
            or text.startswith("***", match.end(group)))


def _sub_value(pattern, text: str) -> str:
    def repl(m):
        if _skip(text, m):
            return m.group(0)
        return m.group("pre") + mask_secret(m.group("val"))
    return pattern.sub(repl, text)


def _sub_quoted_pair(text: str) -> str:
    def repl(m):
        group = "val" if m.group("vq") else "uval"
        if _skip(text, m, group):
            return m.group(0)
        head = text[m.start():m.start(group)]
        return head + mask_secret(m.group(group))
    return _QUOTED_PAIR.sub(repl, text)


def _sub_line_assign(text: str) -> str:
    def repl(m):
        val = m.group("val")
        if _skip(text, m):
            return m.group(0)
        tail = m.group(0)[len(m.group("pre")) + len(val):]
        quote = val[0] if val[0] in "'\"" else ""
        if quote and len(val) > 1 and val.endswith(quote):
            inner = val[1:-1]
            masked = quote + (mask_secret(inner) if inner else "") + quote
        elif quote:
            masked = quote + mask_secret(val[1:]) if len(val) > 1 else val
        else:
            masked = mask_secret(val)
        return m.group("pre") + masked + tail
    return _LINE_ASSIGN.sub(repl, text)


def _sub_whole(pattern, text: str) -> str:
    def repl(m):
        value = m.group(0)
        if _already_masked(value) or text.startswith("***", m.end()):
            return value
        return mask_secret(value)
    return pattern.sub(repl, text)


def _sub_private_key(text: str) -> str:
    def repl(m):
        body = m.group("val").strip()
        if not body or _already_masked(body):
            return m.group(0)
        return m.group("pre") + "\n" + mask_secret(body) + "\n"
    return _PRIVATE_KEY.sub(repl, text)


def redact_text(text: Any) -> Any:
    """Masque tous les secrets reconnus dans un texte (non-str : inchangé)."""
    if not isinstance(text, str) or not text:
        return text
    text = _sub_private_key(text)
    text = _sub_whole(_PASSWORD_HASH, text)
    text = _sub_quoted_pair(text)
    text = _sub_line_assign(text)
    text = _sub_value(_INLINE_ASSIGN, text)
    text = _sub_value(_URL_USERINFO, text)
    text = _sub_value(_AUTH_HEADER, text)
    text = _sub_value(_BEARER, text)
    text = _sub_whole(_TOKEN_FORMATS, text)
    return text


def redact_obj(obj: Any) -> Any:
    """Copie de ``obj`` (dict, list, tuple, str) dont chaque chaîne est masquée.

    Les clés de dictionnaire sont conservées telles quelles."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v) for v in obj)
    return obj
