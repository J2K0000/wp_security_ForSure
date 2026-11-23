"""HTML Reporter, Rapport client formaté en HTML.

Structure orientée client :
  1. Cadre de l'analyse (périmètre + méthodologie)
  2. Synthèse / bilan (verdict + compteurs + risques majeurs)
  3. Vulnérabilités détectées, groupées par sévérité, avec IMPACT métier
  4. Contrôles conformes & observations (repliés, en bas)
"""

import html
from datetime import datetime, timezone
from . import BaseReporter
from .guidance import (RECOMMENDATIONS_TITLE, audit_limits_block, incident_block,
                       recommendations_block)
from .impact import exposure_surface, narrative, harvest_example
from ..access_tiers import AUTHORIZED_WARNING, SKIPPED_LABEL, access_level
from ..status import (ERROR_LABEL, audit_is_complete, error_results,
                      incomplete_label, ok_results, skipped_results)
from ..vulndb import freshness


_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEV_LABEL = {
    "CRITICAL": "Critiques", "HIGH": "Élevées",
    "MEDIUM": "Moyennes", "LOW": "Faibles",
}
_SEV_FR = {"CRITICAL": "Critique", "HIGH": "Élevée", "MEDIUM": "Moyenne",
           "LOW": "Faible", "INFO": "Info"}

# Icônes inline (style Lucide : stroke currentColor, viewBox 24×24), jamais d'emoji.
_ICON = {
    "clipboard": '<rect x="8" y="2" width="8" height="4" rx="1"/><path d="M9 4H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-3"/>',
    "gauge": '<path d="M12 13l4-4"/><path d="M4.6 17a8 8 0 1 1 14.8 0"/>',
    "target": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
    "check": '<circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
    "alert": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    "unlock": '<rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
    "arrow": '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>',
}


def _svg(name, cls="ic"):
    return f'<svg class="{cls}" viewBox="0 0 24 24">{_ICON.get(name, "")}</svg>'


def _sev_pill(sev):
    return (f'<span class="pill {sev}"><span class="dot"></span>'
            f'<span>{_SEV_FR.get(sev, sev)}</span></span>')


def _chip(key, label):
    return (f'<span class="chip {key}"><span class="dot"></span>'
            f'{html.escape(str(label))}</span>')


def _sec(icon, eyebrow, title):
    # eyebrow/title sont des littéraux de code (jamais de l'entrée utilisateur).
    return (f'\n  <div class="section"><span class="eyebrow">{_svg(icon)} '
            f'{eyebrow}</span><h2>{title}</h2></div>')


# Traduction « langage clair » des classes d'accès pour le verdict dirigeant.
_CLASS_PLAIN = {
    "controle": "la prise de contrôle complète du site (accès administrateur)",
    "secrets": "des identifiants et secrets techniques (accès base de données)",
    "pii": "des données personnelles de vos utilisateurs (emails, comptes)",
    "prive": "des contenus privés ou un accès à votre infrastructure",
    "recon": "des informations techniques facilitant une attaque ciblée",
}


def _join_fr(items):
    """Énumération française : « a, b et c »."""
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " et " + items[-1]


# ── Rattachement à la taxonomie CWE (référentiel de menaces WordPress) ───────
_CWE_MAP = [
    (("user enumeration", "user list", "énumération", "author=", "application password",
      "cors", "access-control-allow-origin", "bypass", "rest endpoint", "permission_callback",
      "sans authentification", "without authentication"),
     "CWE-284, Contrôle d'accès défaillant"),
    (("xss", "cross-site scripting", "réfléchi", "reflected"), "CWE-79, Cross-Site Scripting"),
    (("sql", "injection sql"), "CWE-89, Injection SQL"),
    (("upload", "put method", "http put"), "CWE-434, Téléversement de fichier dangereux"),
    (("object injection", "unserialize", "désérialis"), "CWE-502, Désérialisation non sécurisée"),
    (("nonce", "csrf"), "CWE-352, Cross-Site Request Forgery"),
    (("webshell", "backdoor", "malware", "parrot", "balada", "socgholish", "skimmer",
      "cloaking", "seo spam", "suspicious", "malicious"),
     "Malware / compromission (post-intrusion)"),
    (("hsts", "clickjacking", "x-frame", "frame-ancestors", "x-content-type", "csp",
      "content-security-policy", "security header"),
     "CWE-693, Défaut de mécanisme de protection"),
    (("tls 1.0", "tls 1.1", "cipher", "certificate", "certificat", "mixed content"),
     "CWE-326/327, Chiffrement faible/obsolète"),
    (("exposed", "exposé", "wp-config", "dump", ".env", "directory listing", "disclosure",
      "divulgation", "phpmyadmin", "adminer"),
     "CWE-200, Exposition d'informations sensibles"),
    (("xml-rpc", "xmlrpc", "pingback", "multicall"),
     "CWE-799/406, Abus de fonction / contrôle de fréquence"),
]


def _cwe(message: str) -> str:
    m = (message or "").lower()
    for keys, label in _CWE_MAP:
        if any(k in m for k in keys):
            return label
    return ""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport d'audit de sécurité WordPress : {target} · wp_security_ForSure</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --brand-50:#ecfeff; --brand-100:#cffafe; --brand-200:#a5f3fc; --brand-500:#06b6d4;
    --brand-600:#0891b2; --brand-700:#155e75; --brand-800:#164e63;
    --accent-600:#0369a1; --accent-700:#075985;
    --ink-900:#0f172a; --ink-800:#1e293b; --ink-700:#334155; --ink-600:#475569;
    --ink-500:#64748b; --ink-400:#94a3b8; --ink-300:#cbd5e1; --ink-200:#e2e8f0;
    --ink-100:#f1f5f9; --ink-50:#f8fafc; --canvas:#fafafa;
    --sev-critical:#dc2626; --sev-high:#ea580c; --sev-medium:#ca8a04; --sev-low:#0f766e;
    --radius-card:1rem;
    --shadow-soft:0 1px 2px rgb(15 23 42 / .04), 0 8px 24px -12px rgb(15 23 42 / .12);
    --shadow-lift:0 2px 4px rgb(15 23 42 / .05), 0 18px 40px -16px rgb(15 23 42 / .18);
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Inter',ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
          background:var(--canvas); color:var(--ink-800); line-height:1.6;
          font-feature-settings:'cv02','cv03','cv04','cv11'; -webkit-font-smoothing:antialiased; }}
  h1,h2,h3,h4 {{ font-family:'IBM Plex Sans','Inter',ui-sans-serif,system-ui,sans-serif;
                 color:var(--ink-900); letter-spacing:-0.02em; }}
  .container {{ max-width:960px; margin:0 auto; padding:24px 20px 8px; }}
  svg.ic {{ width:1em; height:1em; stroke:currentColor; fill:none;
            stroke-width:2; stroke-linecap:round; stroke-linejoin:round;
            vertical-align:-0.125em; flex:none; }}

  /* En-tête de marque */
  header {{ background:#fff; border-bottom:1px solid var(--ink-200); }}
  header .container {{ display:flex; align-items:center; justify-content:space-between;
                       gap:16px; padding-block:20px; }}
  .brand {{ display:flex; align-items:center; gap:12px; }}
  .brand .mark {{ width:40px; height:40px; border-radius:12px; background:var(--ink-900);
                  color:#fff; display:inline-flex; align-items:center; justify-content:center; }}
  .brand .mark svg.ic {{ width:22px; height:22px; color:var(--brand-400); }}
  .brand .name {{ font-family:'IBM Plex Sans'; font-weight:700; font-size:1.05rem;
                  color:var(--ink-900); line-height:1.15; }}
  .brand .sub {{ font-size:.78rem; color:var(--ink-500); }}
  header .meta {{ text-align:right; font-size:.78rem; color:var(--ink-500); line-height:1.5; }}
  header .meta strong {{ color:var(--ink-800); font-weight:600; }}

  /* Titres de section : eyebrow brand + titre display */
  .section {{ margin:34px 0 14px; }}
  .section .eyebrow {{ display:inline-flex; align-items:center; gap:7px;
                       font-size:.72rem; font-weight:700; letter-spacing:.06em;
                       text-transform:uppercase; color:var(--brand-600); }}
  .section h2 {{ font-size:1.4rem; font-weight:700; margin-top:4px; }}

  .card {{ background:#fff; border:1px solid var(--ink-200); border-radius:var(--radius-card);
           padding:20px 24px; box-shadow:var(--shadow-soft); margin-bottom:14px; color:var(--ink-700); }}
  .card p + p {{ margin-top:9px; }}
  .card strong {{ color:var(--ink-900); }}
  .card a {{ color:var(--brand-700); text-decoration:underline; text-underline-offset:2px; }}

  /* Verdict */
  .verdict {{ display:flex; gap:12px; align-items:flex-start; font-weight:600;
              padding:16px 18px; border-radius:var(--radius-card); margin-bottom:16px;
              border:1px solid; box-shadow:var(--shadow-soft); }}
  .verdict svg.ic {{ width:22px; height:22px; margin-top:1px; }}
  .verdict.crit {{ background:#fef2f2; color:#991b1b; border-color:#fecaca; }}
  .verdict.high {{ background:#fff7ed; color:#9a3412; border-color:#fed7aa; }}
  .verdict.med  {{ background:#fefce8; color:#854d0e; border-color:#fde68a; }}
  .verdict.ok   {{ background:var(--brand-50); color:var(--brand-800); border-color:var(--brand-200); }}
  .verdict.incomplete {{ background:var(--ink-100); color:var(--ink-800); border-color:var(--ink-300); }}
  .card.errors {{ border-left:3px solid var(--ink-500); }}
  .card.errors ul {{ margin:8px 0 0 18px; }}
  .card.errors li {{ margin:4px 0; font-size:.9rem; color:var(--ink-700); }}
  .verdict .level {{ font-family:'IBM Plex Sans'; font-size:1.1rem; font-weight:700; margin-bottom:4px; }}
  .verdict p {{ font-weight:400; font-size:.96rem; line-height:1.55; }}
  ul.prio {{ list-style:none; margin:2px 0 0; }}
  ul.prio li {{ display:flex; gap:9px; align-items:flex-start; margin:9px 0;
                font-size:.92rem; color:var(--ink-700); line-height:1.5; }}
  ul.prio li .pill {{ margin-top:1px; flex:none; }}
  ul.prio li strong {{ color:var(--ink-900); }}

  /* Compteurs */
  .summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
              gap:12px; margin:16px 0; }}
  .stat {{ background:#fff; border:1px solid var(--ink-200); padding:16px; border-radius:14px;
           text-align:center; box-shadow:var(--shadow-soft); }}
  .stat .number {{ font-family:'IBM Plex Sans'; font-size:1.9rem; font-weight:700; }}
  .stat .label {{ font-size:.76rem; color:var(--ink-500); margin-top:4px; }}
  .critical {{ color:var(--sev-critical); }} .high {{ color:var(--sev-high); }}
  .medium {{ color:var(--sev-medium); }} .low {{ color:var(--sev-low); }}

  /* Pills de sévérité (calquées sur SeverityBadge du site) */
  .pill {{ display:inline-flex; align-items:center; gap:6px; border-radius:999px;
           padding:3px 10px; font-size:.72rem; font-weight:600; white-space:nowrap;
           box-shadow:inset 0 0 0 1px currentColor; }}
  .pill .dot {{ width:6px; height:6px; border-radius:999px; background:currentColor; opacity:.7; }}
  .pill span {{ color:var(--_t); }}
  .pill.CRITICAL {{ color:#fecaca; background:#fef2f2; --_t:#b91c1c; }}
  .pill.HIGH {{ color:#fed7aa; background:#fff7ed; --_t:#c2410c; }}
  .pill.MEDIUM {{ color:#fde68a; background:#fefce8; --_t:#a16207; }}
  .pill.LOW {{ color:var(--brand-200); background:var(--brand-50); --_t:var(--brand-700); }}
  .pill.INFO {{ color:var(--ink-200); background:var(--ink-50); --_t:var(--ink-600); }}
  .pill .dot {{ background:var(--_t); }}

  /* Chips (classe d'accès, CWE, à vérifier) */
  .chip {{ display:inline-flex; align-items:center; gap:6px; border-radius:999px;
           padding:2px 9px; font-size:.7rem; font-weight:600; }}
  .chip .dot {{ width:6px; height:6px; border-radius:999px; background:currentColor; }}
  .chip.controle {{ background:#fef2f2; color:#b91c1c; }}
  .chip.secrets  {{ background:#fff7ed; color:#c2410c; }}
  .chip.pii      {{ background:#fefce8; color:#a16207; }}
  .chip.prive    {{ background:#f0f9ff; color:var(--accent-700); }}
  .chip.recon    {{ background:var(--ink-100); color:var(--ink-600); }}
  .cwe {{ font-size:.7rem; color:var(--brand-700); background:var(--brand-50);
          box-shadow:inset 0 0 0 1px var(--brand-200); padding:2px 8px; border-radius:999px;
          font-weight:600; }}
  .to-verify {{ font-size:.7rem; color:#a16207; background:#fefce8; padding:2px 8px;
                border-radius:999px; font-weight:600; }}

  /* Constats */
  .finding {{ background:#fff; border:1px solid var(--ink-200); border-left:4px solid var(--ink-300);
              border-radius:14px; padding:15px 18px; margin-bottom:11px; box-shadow:var(--shadow-soft); }}
  .finding.CRITICAL {{ border-left-color:var(--sev-critical); }}
  .finding.HIGH {{ border-left-color:var(--sev-high); }}
  .finding.MEDIUM {{ border-left-color:var(--sev-medium); }}
  .finding.LOW {{ border-left-color:var(--sev-low); }}
  .finding .top {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }}
  .finding .src {{ font-size:.74rem; color:var(--ink-400); }}
  .finding .msg {{ font-weight:600; color:var(--ink-900); margin:8px 0 2px; }}
  .narr {{ margin-top:8px; padding-left:12px; border-left:2px solid var(--ink-200);
           color:var(--ink-600); font-size:.9rem; line-height:1.55; }}
  .narr b {{ color:var(--ink-900); font-weight:600; }}
  .evidence {{ font-family:ui-monospace,'SFMono-Regular',Menlo,Consolas,monospace;
               font-size:.78rem; background:var(--ink-900); color:var(--ink-200);
               padding:9px 12px; border-radius:10px; margin-top:9px;
               word-break:break-word; white-space:pre-wrap; max-height:150px; overflow:auto; }}

  /* Surface d'exposition */
  .surface .cls {{ display:flex; align-items:center; gap:9px; margin:18px 0 3px; }}
  .surface .cls h3 {{ font-size:1.02rem; font-weight:700; }}
  .surface .blurb {{ color:var(--ink-500); font-size:.86rem; margin-bottom:8px; }}
  .surface .item {{ margin:7px 0; padding:10px 14px; border:1px solid var(--ink-200);
                    border-left:3px solid var(--ink-300); background:#fff; border-radius:0 12px 12px 0; }}
  .surface .item .d {{ font-weight:600; color:var(--ink-900); }}
  .surface .item .flow {{ color:var(--ink-600); font-size:.86rem; margin-top:3px; }}
  .surface .item .ex {{ margin-top:7px; font-size:.84rem; color:var(--ink-700);
                        background:#fff7ed; border:1px solid #fed7aa; border-radius:8px;
                        padding:6px 9px; }}
  .surface .item .ex b {{ color:#9a3412; }}
  .surface .item .ex code {{ font-family:ui-monospace,Menlo,Consolas,monospace;
                             color:var(--ink-900); word-break:break-word; }}
  .evidence-label {{ font-size:.72rem; font-weight:600; color:var(--ink-500);
                     text-transform:uppercase; letter-spacing:.04em; margin:10px 0 3px;
                     display:flex; align-items:center; gap:5px; }}
  .evidence-label svg.ic {{ width:13px; height:13px; }}

  details.conformes {{ background:#fff; border:1px solid var(--ink-200); border-radius:var(--radius-card);
                       padding:6px 20px; box-shadow:var(--shadow-soft); }}
  details.conformes summary {{ cursor:pointer; font-weight:600; color:var(--ink-900); padding:12px 0; }}
  details.conformes ul {{ margin:4px 0 10px; padding-left:4px; list-style:none; }}
  details.conformes li {{ display:flex; align-items:flex-start; gap:7px; margin:4px 0;
                          color:var(--ink-600); font-size:.9rem; }}
  details.conformes li svg.ic {{ color:var(--sev-low); width:15px; height:15px; margin-top:3px; }}

  /* Textes de conduite (reporters/guidance.py) */
  .card.incident {{ border-left:4px solid var(--sev-critical); }}
  .card.incident.annex {{ border-left-color:var(--ink-300); }}
  .card ol.steps {{ margin:8px 0 0 22px; }}
  .card ol.steps li {{ margin:5px 0; }}
  .card ul.plain {{ margin:8px 0 0 18px; }}
  .card ul.plain li {{ margin:5px 0; }}
  .card code {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.86em; }}

  footer {{ max-width:960px; margin:0 auto; padding:26px 20px 34px; color:var(--ink-400);
            font-size:.8rem; border-top:1px solid var(--ink-200); margin-top:24px; }}

  @media print {{
    body {{ background:#fff; }}
    header, .card, .stat, .finding, .surface .item, details.conformes {{ box-shadow:none; }}
    .finding, .surface .item {{ break-inside:avoid; }}
    a {{ color:var(--ink-800); text-decoration:none; }}
    @page {{ margin:1.4cm; }}
  }}
</style>
</head>
<body>
<header>
  <div class="container">
    <div class="brand">
      <span class="mark"><svg class="ic" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>
      <div>
        <div class="name">wp_security_ForSure</div>
        <div class="sub">Rapport d'audit de sécurité WordPress</div>
      </div>
    </div>
    <div class="meta">
      <div><strong>Cible</strong> · {target}</div>
      <div>{date} · wp_security_ForSure v0.1.0</div>
    </div>
  </div>
</header>
<div class="container">
{verdict_html}
{incident_html}
{surface_html}
{vulns_html}
{methodo_html}
{guidance_html}
{conformes_html}
</div>
<footer>
  <p>Généré par wp_security_ForSure, audit de sécurité WordPress passif et en lecture seule.
     « À vérifier » = détection heuristique nécessitant une validation manuelle.</p>
</footer>
</body>
</html>"""


def _incident_card(block: dict) -> str:
    """Carte de réponse à incident : indices, étapes ordonnées, avertissement."""
    indicators = "".join(
        f"<li>{_sev_pill(i['severity'])} {html.escape(str(i['message']))} "
        f"<span class='src'>({html.escape(str(i['check']))})</span></li>"
        for i in block["indicators"][:8])
    steps = "".join(f"<li>{html.escape(s)}</li>" for s in block["steps"])
    cls = "card incident" + ("" if block["highlighted"] else " annex")
    return (f"<div class='{cls}'><p><strong>{html.escape(block['lead'])}</strong></p>"
            + (f"<ul class='plain'>{indicators}</ul>" if indicators else "")
            + f"<ol class='steps'>{steps}</ol>"
            f"<p><strong>{html.escape(block['warning'])}</strong></p></div>")


def _guidance_annex(incident: dict, incident_card: str) -> str:
    """Annexes communes : recommandation 2FA, réponse à incident quand elle
    n'est pas en tête, « Ce que cet audit ne peut pas voir »."""
    recs = "".join(
        f"<div class='card'><p><strong>{html.escape(r['title'])}</strong></p>"
        f"<p>{html.escape(r['text'])}</p></div>" for r in recommendations_block())
    out = _sec("shield", RECOMMENDATIONS_TITLE, "Comptes administrateurs") + recs
    if not incident["highlighted"]:
        out += _sec("alert", "Annexe", html.escape(incident["title"])) + incident_card
    limits = audit_limits_block()
    items = "".join(f"<li>{html.escape(i)}</li>" for i in limits["items"])
    out += (_sec("clipboard", "Annexe", html.escape(limits["title"]))
            + f"<div class='card'><p>{html.escape(limits['lead'])}</p>"
            f"<ul class='plain'>{items}</ul></div>")
    return out


class HTMLReporter(BaseReporter):
    """Rapport client au format HTML."""

    def _confirmed(self, sev):
        return [(r.title, r.check_name, f) for r in ok_results(self.results)
                for f in r.findings
                if f["severity"] == sev and f.get("confidence", "confirmed") == "confirmed"]

    def generate(self) -> str:
        # ── Classement des findings ──
        # Un contrôle en erreur (exception, cible injoignable) n'est jamais
        # « conforme » : il est listé à part et rend l'audit incomplet.
        done = ok_results(self.results)
        errors = error_results(self.results)
        skipped = skipped_results(self.results)
        access = access_level(self.config)
        incomplete = not audit_is_complete(self.results)
        issues = []           # (check_title, finding) severity != INFO
        info_findings = []    # severity == INFO
        conformes = []        # checks sans aucun finding non-INFO
        sev_counts = {s: 0 for s in _SEV_ORDER}

        for r in done:
            non_info = [f for f in r.findings if f["severity"] != "INFO"]
            for f in r.findings:
                if f["severity"] == "INFO":
                    info_findings.append((r.title, f))
                else:
                    issues.append((r.title, r.check_name, f))
                    sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
            if not non_info:
                conformes.append(r.title)

        crit_conf = self._confirmed("CRITICAL")
        high_conf = self._confirmed("HIGH")

        # ── Fraîcheur des données de vulnérabilités (annexe) ──
        ds = freshness.from_results(self.results)
        sources_html = (
            "<p><strong>Données de vulnérabilités :</strong> "
            f"CVE {html.escape(ds['cve']['label'])}. "
            f"{html.escape(ds['epss']['label'])}. "
            f"{html.escape(ds['kev']['label'])}.</p>")

        # ── Annexe : méthodologie & périmètre (repoussée après les constats) ──
        methodo_html = f"""
  {_sec("clipboard", "Annexe", "Méthodologie & périmètre")}
  <div class="card">
    <p><strong>Cible auditée :</strong> {html.escape(str(self.target))}</p>
    <p><strong>Périmètre :</strong> {len(self.results)} familles de contrôles -
       empreinte (plugins/thèmes/core), vulnérabilités connues (CVE), configuration
       serveur & en-têtes HTTP, exposition de fichiers, REST API / XML-RPC,
       authentification, TLS/SSL, cache et scripts tiers.</p>
    <p><strong>Mode :</strong> audit <em>passif et en lecture seule</em> : aucune
       écriture ni modification de la cible.</p>
    <p><strong>Niveau d'accès :</strong> {html.escape(access['label'])}</p>
    {sources_html}
    <p><strong>Lecture :</strong> chaque constat porte une <strong>sévérité</strong>
       (Critique → Basse), un <strong>impact métier</strong> et, le cas échéant, sa
       catégorie <strong>CWE</strong> (taxonomie standard des failles). La mention
       <span class="to-verify">à vérifier</span> signale une détection heuristique
       à confirmer manuellement (par opposition à un constat déterministe).</p>
    <p><strong>Périmètre &amp; limites :</strong> cet audit est <em>externe</em>
       (boîte noire, sans accès au serveur). Il détecte l'exposition, les
       vulnérabilités connues (CVE) et les signes de compromission observables du
       dehors. Il ne remplace pas un contrôle d'<strong>intégrité des fichiers</strong>
       côté serveur (WP-CLI : <code>wp core verify-checksums</code>,
       <code>wp plugin verify-checksums</code>), indispensable car les malwares
       récents s'injectent dans des fichiers légitimes. Les deux approches sont
       complémentaires.</p>
  </div>"""

        # ── Surface calculée tôt : elle alimente le verdict en langage clair ──
        surface = exposure_surface(done)

        # ── 1) Verdict pour le dirigeant (langage clair, en ouverture) ──
        if crit_conf:
            level, vclass, vicon = "Critique", "crit", "alert"
        elif high_conf:
            level, vclass, vicon = "Élevé", "high", "alert"
        elif sev_counts.get("MEDIUM"):
            level, vclass, vicon = "Modéré", "med", "alert"
        elif incomplete:
            # Jamais le verdict le plus favorable sur un audit incomplet.
            level, vclass, vicon = "Non établi (audit incomplet)", "incomplete", "alert"
        else:
            level, vclass, vicon = "Maîtrisé", "ok", "check"

        # Ce que ça signifie concrètement, dérivé des accès PROUVÉS (surface).
        present = [b["key"] for b in surface]
        if present:
            meaning = ("Concrètement, un attaquant pourrait accéder à "
                       + _join_fr([_CLASS_PLAIN[k] for k in present if k in _CLASS_PLAIN])
                       + ".")
        else:
            meaning = ("Aucun accès attaquant n'a pu être prouvé sur le périmètre "
                       "externe (des points à confirmer figurent plus bas).")

        if crit_conf:
            lead = (f"{len(crit_conf)} faille(s) critique(s) confirmée(s), "
                    f"exploitable(s) à distance sans identifiants. {meaning} "
                    "La correction est ciblée et rapide, aucune refonte nécessaire.")
        elif high_conf:
            lead = (f"{len(high_conf)} constat(s) de gravité élevée confirmé(s). "
                    f"{meaning} À corriger rapidement, sans urgence de rupture.")
        elif sev_counts.get("MEDIUM"):
            lead = ("Aucune faille critique. Des durcissements sont recommandés pour "
                    f"réduire la surface d'attaque. {meaning}")
        elif incomplete:
            lead = ("Aucun constat sur les contrôles réalisés, mais l'audit est "
                    "incomplet : l'absence de constat ne prouve pas l'absence de "
                    "faille. Relancer l'audit une fois la cause des erreurs corrigée.")
        else:
            lead = f"Aucun problème majeur détecté sur le périmètre externe. {meaning}"
        if incomplete and (crit_conf or high_conf or sev_counts.get("MEDIUM")):
            lead += (" Audit incomplet : d'autres failles peuvent exister sur les "
                     "contrôles non réalisés.")

        errors_html = ""
        if incomplete:
            err_items = "".join(
                f"<li><strong>{html.escape(str(r.title))}</strong> : {ERROR_LABEL}"
                + (" : " + html.escape(str(r.findings[0].get("message", "")))
                   if r.findings else "")
                + "</li>"
                for r in errors)
            errors_html = (
                "<div class='card errors'><p><strong>"
                + html.escape(incomplete_label(self.results)) + "</strong></p>"
                + (f"<ul>{err_items}</ul>" if err_items else "") + "</div>")

        skipped_html = ""
        if skipped:
            items = "".join(
                f"<li><strong>{html.escape(str(r.title))}</strong> : "
                f"{html.escape(SKIPPED_LABEL)}</li>" for r in skipped)
            skipped_html = (
                f"<div class='card'><p><strong>{len(skipped)} contrôle(s) non "
                "réalisé(s), ni échec ni conformité :</strong></p>"
                f"<ul>{items}</ul></div>")
        authorized_html = (
            f"<div class='card errors'><p><strong>{html.escape(AUTHORIZED_WARNING)}"
            "</strong></p></div>" if access["authorized"] else "")
        errors_stat = (f'<div class="stat"><div class="number">{len(errors)}</div>'
                       '<div class="label">Non réalisés (erreur)</div></div>'
                       if errors else "")
        top = (crit_conf + high_conf)[:8]
        top_html = ""
        if top:
            items, seen = "", set()
            for title, check_name, f in top:
                n = narrative(check_name, f.get("message", ""), f)
                # Langage clair : impact métier (donnée exposée → conséquence),
                # pas le message technique brut (réservé à la section Constats).
                # Dédup par message métier : deux constats de même impact ne
                # répètent pas la même ligne dans le résumé dirigeant.
                key = (n["data"], n["enables"])
                if key in seen:
                    continue
                seen.add(key)
                items += (f"<li>{_sev_pill(f['severity'])}<span>"
                          f"<strong>{html.escape(n['data'])}</strong>, "
                          f"{html.escape(n['enables'])}</span></li>")
            top_html = ("<div class='card'><p><strong>À traiter en priorité :</strong>"
                        f"</p><ul class='prio'>{items}</ul></div>")

        verdict_html = f"""
  {_sec("gauge", "Pour le dirigeant", "Verdict")}
  {authorized_html}
  <div class="verdict {vclass}">{_svg(vicon)}<div><div class="level">Niveau de risque : {level}</div><p>{lead}</p></div></div>
  <div class="summary">
    <div class="stat"><div class="number critical">{sev_counts['CRITICAL']}</div><div class="label">Critiques</div></div>
    <div class="stat"><div class="number high">{sev_counts['HIGH']}</div><div class="label">Élevées</div></div>
    <div class="stat"><div class="number medium">{sev_counts['MEDIUM']}</div><div class="label">Moyennes</div></div>
    <div class="stat"><div class="number low">{sev_counts['LOW']}</div><div class="label">Faibles</div></div>
    <div class="stat"><div class="number" style="color:var(--brand-600)">{len(conformes)}</div><div class="label">Contrôles OK</div></div>
    {errors_stat}
  </div>
  {errors_html}
  {skipped_html}
  {top_html}"""

        # ── 2) Surface d'exposition (accès PROUVÉS, groupés par classe) ──
        if surface:
            blocks = ""
            for b in surface:
                items = ""
                for check_name, f in b["findings"]:
                    n = narrative(check_name, f.get("message", ""), f)
                    # Exemple concret : « récolte » de données réservée aux classes
                    # qui exposent vraiment des données (pii/secrets) ; sinon c'est
                    # une preuve. Rien pour la reconnaissance (versions/namespaces).
                    ex = (harvest_example(f.get("evidence", ""))
                          if b["key"] != "recon" else None)
                    if ex:
                        ex_label = ("Ce qu'un attaquant récolte"
                                    if b["key"] in ("pii", "secrets") else "Extrait réel")
                        ex_html = (f"<div class='ex'><b>{ex_label} :</b> "
                                   f"<code>{html.escape(ex)}</code></div>")
                    else:
                        ex_html = ""
                    items += (
                        "<div class='item'><div class='d'>"
                        + html.escape(str(f.get("message", "")))
                        + "</div><div class='flow'>" + _svg("unlock") + " "
                        + html.escape(n["data"]) + " &nbsp;·&nbsp; " + _svg("arrow")
                        + " " + html.escape(n["path"]) + " &nbsp;·&nbsp; " + _svg("alert")
                        + " " + html.escape(n["enables"]) + "</div>" + ex_html + "</div>")
                blocks += (
                    f"<div class='cls'>{_chip(b['key'], b['label'])}</div>"
                    f"<div class='blurb'>{html.escape(b['blurb'])}</div>{items}")
            surface_html = (
                _sec("target", "Vue attaquant",
                     "Surface d'exposition, ce qu'un attaquant peut atteindre")
                + "<div class='card'><p>Accès <strong>prouvés</strong> (constats "
                "confirmés), classés du plus grave au moindre. Les détections "
                "heuristiques « à vérifier » ne figurent pas ici.</p></div>"
                f"<div class='surface'>{blocks}</div>")
        else:
            surface_html = (
                _sec("target", "Vue attaquant", "Surface d'exposition")
                + "<div class='card'><p>Aucun accès attaquant <strong>prouvé</strong> "
                "n'a été obtenu sur le périmètre externe (aucun constat confirmé de "
                "sévérité non-INFO).</p>"
                "<p style='margin-top:9px'>Pour situer l'enjeu : sur un site vulnérable, "
                "un attaquant récolterait typiquement la liste des comptes et les emails "
                "du personnel, les identifiants de la base de données (fichier de "
                "configuration exposé) ou le contenu des sauvegardes. "
                "<strong>Sur votre site, aucun de ces accès n'a pu être obtenu</strong>, "
                "voir néanmoins les points d'attention et détections à vérifier plus "
                "bas.</p>"
                + ("<p style='margin-top:9px'><strong>Audit incomplet :</strong> des "
                   "contrôles n'ont pas pu être réalisés ; ce constat ne vaut que pour "
                   "les contrôles effectués.</p>" if incomplete else "")
                + "</div>")

        # ── 3) Vulnérabilités détectées (par sévérité) ──
        vulns_html = _sec("shield", "Constats", "Vulnérabilités & points d'attention")
        if not issues and incomplete:
            vulns_html += ("<div class='card'>Aucune vulnérabilité détectée sur les "
                           "contrôles réalisés (audit incomplet).</div>")
        elif not issues:
            vulns_html += ("<div class='card'>Aucune vulnérabilité détectée, "
                           "seuls des contrôles conformes et des observations.</div>")
        else:
            by_sev = {s: [] for s in _SEV_ORDER}
            for title, check_name, f in issues:
                by_sev[f["severity"]].append((title, check_name, f))
            for sev in _SEV_ORDER:
                group = by_sev[sev]
                if not group:
                    continue
                vulns_html += (f'\n  <h3 style="margin:22px 0 9px;color:var(--ink-700);'
                               f'font-size:1rem">{_SEV_LABEL[sev]} · {len(group)}</h3>')
                for title, check_name, f in group:
                    conf = f.get("confidence", "confirmed")
                    verify = ("<span class='to-verify'>à vérifier</span>"
                              if conf != "confirmed" else "")
                    msg = html.escape(str(f.get("message", "")))
                    n = narrative(check_name, f.get("message", ""), f)
                    cls_badge = _chip(n["classe"], n["label"])
                    cwe = _cwe(f.get("message", ""))
                    evidence = html.escape(str(f.get("evidence", "")))[:400]
                    url = html.escape(str(f.get("url", "")))
                    vulns_html += f"""
  <div class="finding {sev}">
    <div class="top">
      {_sev_pill(sev)}
      {cls_badge}
      {verify}
      {"<span class='cwe'>" + html.escape(cwe) + "</span>" if cwe else ""}
      <span class="src">- {html.escape(str(title))}</span>
    </div>
    <div class="msg">{msg}</div>
    <div class="narr"><b>{_svg("unlock")} Donnée / accès :</b> {html.escape(n['data'])}<br>
      <b>{_svg("arrow")} Chemin d'attaque :</b> {html.escape(n['path'])}<br>
      <b>{_svg("alert")} Permet ensuite :</b> {html.escape(n['enables'])}</div>
    {"<div class='evidence-label'>" + _svg("clipboard") + " Preuve technique</div><div class='evidence'>" + evidence + "</div>" if evidence else ""}
    {"<div class='src'>" + url + "</div>" if url else ""}
  </div>"""

        # ── 4) Contrôles conformes & observations (repliés) ──
        _check = _svg("check")
        conformes_items = "".join(
            f"<li>{_check} {html.escape(str(t))}</li>" for t in conformes)
        info_items = ""
        for title, f in info_findings[:40]:
            info_items += (f"<li>{html.escape(str(title))}, "
                           f"{html.escape(str(f.get('message','')))}</li>")
        conformes_html = f"""
  {_sec("check", "Contrôles OK", "Contrôles conformes & observations")}
  <details class="conformes">
    <summary>{len(conformes)} contrôle(s) sans anomalie + {len(info_findings)} observation(s), cliquer pour dérouler</summary>
    <p style="margin-top:8px"><strong>Contrôles conformes</strong> (aucun problème détecté) :</p>
    <ul>{conformes_items or '<li>-</li>'}</ul>
    <p style="margin-top:8px"><strong>Observations informatives</strong> :</p>
    <ul>{info_items or '<li>-</li>'}</ul>
  </details>"""

        # ── Textes de conduite communs (reporters/guidance.py) ──
        incident = incident_block(self.results)
        incident_card = _incident_card(incident)
        incident_html = (_sec("alert", "Urgence", html.escape(incident["title"]))
                         + incident_card) if incident["highlighted"] else ""
        guidance_html = _guidance_annex(incident, incident_card)

        return HTML_TEMPLATE.format(
            target=html.escape(str(self.target)),
            date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            verdict_html=verdict_html,
            surface_html=surface_html,
            vulns_html=vulns_html,
            methodo_html=methodo_html,
            conformes_html=conformes_html,
            incident_html=incident_html,
            guidance_html=guidance_html,
        )
