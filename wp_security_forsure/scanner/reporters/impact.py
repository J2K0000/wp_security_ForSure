"""Couche IMPACT, traduit chaque constat en « accès attaquant ».

Objectif : passer d'une liste technique de findings à un narratif d'attaquant -
« voici à quelles données / quel accès un attaquant pourrait parvenir ». Deux
sorties :

  1) classify() + narrative() : par constat, sa CLASSE d'accès (du pire au
     moindre) et son narratif structuré (donnée exposée → chemin d'attaque →
     ce que ça permet ensuite) ;
  2) exposure_surface() : la synthèse « Surface d'exposition » en tête de
     rapport, qui ne retient QUE les accès PROUVÉS (confidence=confirmed,
     hors INFO) groupés par classe, le narratif solide et défendable.

La classification s'appuie d'abord sur le NOM DU CHECK (signal le plus fiable),
puis affine avec des mots-clés du message. Aucune modification des checks : tout
est dérivé au moment du rapport.
"""

import re
from typing import List, Optional, Tuple

# ── Classes d'accès attaquant, ordonnées du pire au moindre ──────────────────
# (clé, emoji, libellé, description courte de ce que l'attaquant obtient)
ACCESS_CLASSES: List[Tuple[str, str, str, str]] = [
    ("controle", "🟥", "Prise de contrôle",
     "Exécution de code, compte administrateur ou shell, l'attaquant contrôle le site."),
    ("secrets", "🟧", "Identifiants & secrets",
     "Mots de passe base de données, clés API, cookies de session, accès direct ou rebond."),
    ("pii", "🟨", "Données personnelles",
     "Emails, comptes, noms, ciblage, phishing et force brute des comptes réels."),
    ("prive", "🟦", "Contenu privé / accès interne",
     "Sauvegardes, dumps SQL, contenu en cache privé, pivot vers le réseau interne."),
    ("recon", "⬜", "Reconnaissance",
     "Versions, chemins, composants et posture, prépare une attaque ciblée."),
]
_CLASS_ORDER = [k for k, *_ in ACCESS_CLASSES]
_CLASS_META = {k: (emoji, label, blurb) for k, emoji, label, blurb in ACCESS_CLASSES}

# ── Classe par défaut selon le check (signal le plus fiable) ─────────────────
_CLASS_BY_CHECK = {
    "core_branch": "recon",
    "plugin_status": "recon",
    "rest_batch": "controle",
    "auth_bypass_state": "controle",
    "forms_upload": "controle",
    "nulled_plugins": "controle",
    "malware_detection": "controle",
    "cloaking_seo_spam": "controle",
    "visit_profiles": "controle",
    "client_injection": "controle",
    "browser_render": "controle",
    "takeover": "controle",
    "database_exposure": "secrets",
    "cookies_sessions": "secrets",
    "brute_force_login": "secrets",
    "rest_api": "recon",               # affiné : user-enum→pii, CORS→prive
    "wp_features": "recon",            # affiné : user-enum→pii, pingback→prive
    "ssrf_endpoints": "prive",
    "cache_security": "prive",
    "webhook_exposure": "prive",
    "file_exposure": "prive",          # affiné par message (secrets vs recon)
    "vulnerability_scan": "controle",  # affiné par sévérité en aval
    "third_party_scripts": "recon",    # affiné par message
    "security_headers": "recon",
    "ssl_tls": "recon",
    "email_auth": "pii",  # surface d'usurpation email / phishing
    "server_security": "recon",
    "waf_cdn": "recon",
    "multisite": "recon",
    "fingerprint": "recon",
    "high_risk_plugins": "recon",  # présence d'un plugin à risque = surface ;
                                    # l'exploitabilité réelle passe par
                                    # vulnerability_scan (affinage message).
}

# ── Affinages par mots-clés du message (priment sur le défaut du check) ──────
# Premier motif qui matche → classe. Ordre = du plus spécifique au plus général.
_CLASS_REFINE: List[Tuple[Tuple[str, ...], str]] = [
    # 1) Prise de contrôle (RCE / admin / compromission / takeover).
    (("webshell", "backdoor", "malware", "nulled", "nullé", "wp2shell",
      "exploitable", "prise de contrôle", "takeover", "nxdomain", "dangling",
      "upload"), "controle"),
    # 2) Contenu privé / accès interne (SSRF, cache, CORS, sauvegardes).
    (("pingback", "ssrf", "cache deception", "logged-in", "cors",
      "access-control-allow-origin", "backup", "sauvegarde", "dump", ".sql"),
     "prive"),
    # 3) Identifiants & secrets (config/fichiers sensibles, jetons, cookies).
    (("wp-config", ".env", ".git", "debug.log", "db_password", "auth_key",
      "set-cookie", "application password", "phpmyadmin", "adminer"), "secrets"),
    # 4) Données personnelles (énumération de comptes réels).
    (("user enum", "user list", "énumération", "author=", "email"), "pii"),
    # 5) Reconnaissance / abus de fonction (xmlrpc, surface, versions).
    # Placé APRÈS les classes fortes : « credential »/« namespace » ne doivent
    # pas surclasser un simple vecteur d'abus ou de surface.
    (("xml-rpc", "xmlrpc", "multicall", "getusersblogs", "getcomments",
      "namespace", "attack surface", "surface d'attaque", "readme", "license",
      "version", "empreinte", "fingerprint", "waf", "cdn", "media endpoint"),
     "recon"),
]

# ── Narratifs structurés par mots-clés (donnée, chemin, permet ensuite) ──────
# Le premier motif qui matche le message donne le narratif spécifique.
_NARRATIVE: List[Tuple[Tuple[str, ...], str, str, str]] = [
    (("wp2shell", "rce", "batch"),
     "Exécution de code arbitraire sur le serveur (pré-authentification).",
     "Appel non authentifié de l'API REST batch vulnérable du cœur.",
     "Contrôle total : lecture de toute la base, dépôt de backdoor, rebond interne."),
    (("upload",),
     "Dépôt de fichier arbitraire (potentiel webshell).",
     "Formulaire / endpoint d'upload sans restriction de type.",
     "Exécution de code à distance puis contrôle complet du site."),
    (("nulled", "nullé", "webshell", "backdoor", "malware", "parrot", "balada",
      "socgholish", "skimmer"),
     "Code malveillant déjà présent (compromission active).",
     "Backdoor / injection déposée lors d'une intrusion antérieure.",
     "Persistance de l'attaquant, vol de données et redirections frauduleuses."),
    (("auth bypass", "auth-bypass", "2fa", "role simulation", "privilege"),
     "Accès à un compte administrateur.",
     "Contournement d'authentification ou secret faible côté plugin.",
     "Prise de contrôle de l'admin WordPress (plugins, utilisateurs, contenu)."),
    (("takeover", "nxdomain", "dangling"),
     "Contrôle d'un (sous-)domaine ou d'une ressource de confiance.",
     "Enregistrement DNS pointant vers un service tiers réclamable.",
     "Servir du contenu malveillant sous une origine légitime (phishing, vol de session)."),
    (("wp-config", ".env", ".git", "dump", "backup", "sauvegarde", "database",
      "adminer", "phpmyadmin"),
     "Identifiants base de données et secrets du site.",
     "Fichier de configuration / sauvegarde téléchargeable sans authentification.",
     "Accès direct à la base et compromission complète du site."),
    (("debug.log", "set-cookie", "session"),
     "Cookies de session / secrets journalisés.",
     "Fichier debug.log exposé publiquement.",
     "Vol de session administrateur (account takeover) sans mot de passe."),
    (("application password",),
     "Jeton d'accès API complet contournant la double authentification.",
     "Endpoint des mots de passe applicatifs exposé.",
     "Accès programmatique complet au site sans 2FA."),
    (("user enum", "énumération", "user list", "author="),
     "Liste des comptes réels (identifiants, parfois emails).",
     "Endpoint REST /wp/v2/users ou énumération par auteur, sans authentification.",
     "Force brute ciblée des comptes et spear-phishing des administrateurs."),
    (("pingback",),
     "Accès au réseau interne / métadonnées cloud via le serveur.",
     "XML-RPC pingback.ping détourné (SSRF).",
     "Scan interne, lecture de métadonnées cloud, amplification DDoS."),
    (("ssrf",),
     "Requêtes émises depuis le serveur vers des cibles internes.",
     "Endpoint passant une URL utilisateur à un client HTTP sans allowlist.",
     "Accès à des services internes, métadonnées cloud, pivot réseau."),
    (("multicall", "xml-rpc", "xmlrpc"),
     "Amplification de force brute et surface d'abus.",
     "xmlrpc.php actif (system.multicall) sans authentification.",
     "Test de milliers de mots de passe par requête, amplification."),
    (("cache deception", "cache", "logged-in"),
     "Contenu dynamique / privé servi depuis un cache public.",
     "Cache mal isolé ou déception de cache par URL d'apparence statique.",
     "Fuite de réponses privées (données de compte, contenu authentifié)."),
    (("cors", "access-control-allow-origin", "origin"),
     "Lecture de données authentifiées par un site tiers.",
     "Politique CORS permissive (réflexion d'origine, credentials autorisés).",
     "Vol de session ou de données via un site contrôlé par l'attaquant."),
    (("directory listing", "exposed", "exposé", "disclosure"),
     "Fichiers et ressources listés / téléchargeables.",
     "Répertoire ou fichier sensible accessible sans authentification.",
     "Cartographie du site et récupération de ressources sensibles."),
    (("tls 1.0", "tls 1.1", "cipher", "certificate", "certificat", "mixed content", "hsts"),
     "Interception du trafic (données en transit).",
     "Chiffrement faible/obsolète ou absence de HSTS (position réseau requise).",
     "Déchiffrement / altération du trafic, vol de session (MITM)."),
    (("csp", "content-security-policy", "x-frame", "clickjacking", "x-content-type",
      "security header"),
     "Absence de barrière contre XSS / clickjacking.",
     "En-têtes de sécurité manquants ou trop permissifs.",
     "Amplifie l'impact d'une faille XSS/clickjacking (vol de session)."),
    (("webhook",),
     "Réception d'événements sans validation de signature (à auditer).",
     "Endpoint récepteur de webhook exposé (validation non vérifiable à distance).",
     "Actions forgées possibles si la signature n'est pas vérifiée côté serveur."),
    (("bibliothèque js", "prototype pollution", "vulnérable"),
     "Faille connue dans une bibliothèque front chargée.",
     "Version vulnérable servie par le thème / plugin / CDN.",
     "XSS ou prototype pollution selon la lib (vol de session, exécution JS)."),
]

# ── Narratif générique par classe (repli quand aucun motif ne matche) ────────
_CLASS_NARRATIVE = {
    "controle": (
        "Contrôle du site (exécution de code ou compte administrateur).",
        "Exploitation de la faille identifiée.",
        "Prise de contrôle complète : vol de toutes les données, défacement, rebond."),
    "secrets": (
        "Identifiants ou secrets (base de données, clés, session).",
        "Lecture directe de la ressource exposée.",
        "Accès authentifié, rebond vers d'autres services, compromission."),
    "pii": (
        "Données personnelles (emails, comptes).",
        "Lecture d'un endpoint public.",
        "Phishing ciblé et force brute des comptes réels."),
    "prive": (
        "Contenu privé ou accès au réseau interne.",
        "Requête non authentifiée.",
        "Fuite de données confidentielles ou pivot interne."),
    "recon": (
        "Informations techniques (versions, chemins, composants).",
        "Observation passive du site.",
        "Prépare une attaque ciblée sur une faille connue."),
}


def classify(check_name: Optional[str], message: Optional[str],
             finding: Optional[dict] = None) -> str:
    """Classe d'accès d'un constat.

    Priorité : access_class explicite du finding > affinage par message >
    défaut du check > 'recon'.
    """
    if finding and finding.get("access_class") in _CLASS_ORDER:
        return finding["access_class"]
    m = (message or "").lower()
    for keys, cls in _CLASS_REFINE:
        if any(k in m for k in keys):
            return cls
    return _CLASS_BY_CHECK.get(check_name or "", "recon")


def narrative(check_name: Optional[str], message: Optional[str],
              finding: Optional[dict] = None) -> dict:
    """Narratif structuré : {classe, emoji, label, data, path, enables}.

    Si le finding porte un narratif `impact` à la source, il prime.
    """
    cls = classify(check_name, message, finding)
    if finding and isinstance(finding.get("impact"), dict):
        imp = finding["impact"]
        emoji, label, _ = _CLASS_META[cls]
        return {"classe": cls, "emoji": emoji, "label": label,
                "data": imp.get("data"), "path": imp.get("path"),
                "enables": imp.get("enables")}
    m = (message or "").lower()
    data = path = enables = None
    for keys, d, p, e in _NARRATIVE:
        if any(k in m for k in keys):
            data, path, enables = d, p, e
            break
    if data is None:
        data, path, enables = _CLASS_NARRATIVE.get(cls, _CLASS_NARRATIVE["recon"])
    emoji, label, _ = _CLASS_META[cls]
    return {"classe": cls, "emoji": emoji, "label": label,
            "data": data, "path": path, "enables": enables}


# ── Extraction d'un exemple concret « ce qu'un attaquant récolte » ──────────
# But : montrer au client les VRAIES données récupérables sur son site (comptes,
# emails, secrets…) pour rendre l'impact tangible. Toujours CAVIARDÉ.
_EMAIL_RE = re.compile(r'([A-Za-z0-9])[A-Za-z0-9._%+\-]*(@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})')
_SECRET_RE = re.compile(
    r'(?i)\b(pass(?:word)?|secret|api[_-]?key|token|auth[_-]?key|db_password|'
    r'authorization|bearer)\b\s*[:=]?\s*\S+')
_EMOJI_RE = re.compile(
    '[\U0001F000-\U0001FAFF☀-➿⬀-⯿←-⇿️]')
# Lignes de « cadrage » du check (pas de la donnée récoltée) à écarter.
_META_LINE = re.compile(
    r'^\s*(impact|response|recommendation|reco|référence|reference|detail|détail|'
    r'interpretation|fault code|matched indicators|remédiation|note|snippet|'
    r'http\s+\d|content-type)\b', re.I)


def redact(text: str) -> str:
    """Caviarde emails (garde 1re lettre + domaine) et secrets évidents."""
    text = _EMAIL_RE.sub(lambda m: m.group(1) + '•••' + m.group(2), text)
    text = _SECRET_RE.sub(lambda m: m.group(1) + ' •••', text)
    return text


def harvest_example(evidence: Optional[str], limit: int = 190) -> Optional[str]:
    """Extrait un exemple concret et CAVIARDÉ de ce qu'un attaquant récolte.

    Nettoie l'évidence brute du check (emojis, lignes de cadrage, XML), garde les
    lignes porteuses de données, caviarde, tronque. Renvoie None si rien d'utile.
    """
    if not evidence:
        return None
    ev = _EMOJI_RE.sub('', str(evidence))
    lines = [ln.strip() for ln in ev.splitlines() if ln.strip()]
    keep = [ln for ln in lines
            if not _META_LINE.match(ln) and '<?xml' not in ln and not ln.startswith('<')]
    text = ' '.join(keep) if keep else ' '.join(lines)
    text = re.sub(r'\s+', ' ', redact(text)).strip()
    if len(text) < 8:
        return None
    return text[:limit] + ('…' if len(text) > limit else '')


def exposure_surface(results) -> List[dict]:
    """Synthèse « Surface d'exposition » : accès PROUVÉS groupés par classe.

    Ne retient que les findings confidence=confirmed et de sévérité non-INFO -
    le narratif solide et défendable en rapport client. Renvoie une liste de
    blocs {key, emoji, label, blurb, findings:[(check_name, finding)...]} dans
    l'ordre des classes (pire → moindre), classes vides omises.
    """
    buckets = {k: [] for k in _CLASS_ORDER}
    for r in results:
        check_name = getattr(r, "check_name", "")
        for f in getattr(r, "findings", []) or []:
            if f.get("severity") == "INFO":
                continue
            if f.get("confidence", "confirmed") != "confirmed":
                continue
            cls = classify(check_name, f.get("message", ""), f)
            buckets[cls].append((check_name, f))
    out = []
    for key in _CLASS_ORDER:
        if not buckets[key]:
            continue
        emoji, label, blurb = _CLASS_META[key]
        out.append({"key": key, "emoji": emoji, "label": label,
                    "blurb": blurb, "findings": buckets[key]})
    return out
