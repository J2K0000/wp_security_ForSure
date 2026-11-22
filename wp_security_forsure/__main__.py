"""wp_security_ForSure: passive WordPress security audit

Usage:
  python3 -m wp_security_forsure audit https://cible.com
  python3 -m wp_security_forsure audit https://cible.com --checks ssl_tls,security_headers
  python3 -m wp_security_forsure audit https://cible.com --output rapport.html   # format déduit de l'extension
  python3 -m wp_security_forsure audit https://cible.com --authorized   # autorisation écrite du propriétaire
  python3 -m wp_security_forsure list                      # Lister les checks disponibles
  python3 -m wp_security_forsure vulncache --info          # Etat du cache CVE
  python3 -m wp_security_forsure vulncache --clear         # Vider le cache CVE
  python3 -m wp_security_forsure refresh-epss              # Télécharge le snapshot EPSS (réseau)

Codes de sortie : voir EXIT_CODES_HELP (affiché par --help).
"""

import argparse
import io
import sys
from datetime import datetime, timezone
from pathlib import Path
import yaml

# Console Windows : forcer UTF-8 pour les emojis/accents des rapports.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

from . import __version__
from .scanner.engine import PRIORITY_LABELS, ScanEngine, UnknownCheckError, check_catalog
from .scanner.reporters import get_reporter
from .scanner.status import audit_is_complete
from .scanner.vulndb.cache import epss_path, vulncache_path

EXIT_OK = 0
EXIT_CRITICAL = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3

EXIT_CODES_HELP = """\
Codes de sortie :
  0  audit complet, aucun constat CRITICAL confirmé
  1  au moins un constat CRITICAL confirmé (l'emporte sur le code 3)
  2  erreur d'usage : argument invalide, check inconnu, configuration illisible
  3  audit incomplet : cible injoignable ou au moins un contrôle en erreur

Format du rapport : --format, sinon déduit de l'extension de --output
(.html, .json ; toute autre extension : texte du rapport terminal).
Cache CVE et snapshot EPSS : dossier de cache utilisateur, modifiable par la
variable d'environnement WP_SECURITY_FORSURE_CACHE_DIR."""

_FORMAT_BY_EXTENSION = {".html": "html", ".htm": "html", ".json": "json"}

AUTHORIZED_HELP = (
    "Réservée à l'audit d'un site dont on a l'autorisation écrite du "
    "propriétaire. Active la recherche de chemins non liés (niveau 2 : "
    "sauvegardes, .env, .git/, listings de répertoires, readme.txt "
    "d'extensions devinés...). Le scanner reste en lecture seule.")


def load_config():
    cfg_path = Path(__file__).parent / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def list_checks():
    """Liste générée depuis le registre du moteur (nom, titre, description,
    priorité) : tout check découvert y figure, sans liste à maintenir."""
    catalog = check_catalog()
    print(f"{len(catalog)} checks disponibles, par priorité :")
    current = object()
    for check in catalog:
        prio = check["priority"]
        if prio != current:
            current = prio
            label = PRIORITY_LABELS.get(prio)
            if label:
                heading = f"Priorité {prio} : {label}"
            else:
                heading = f"Priorité {prio}" if prio else "Priorité non définie"
            print(f"\n{heading}")
        print(f"  {check['name']:<20} {check['title']}")
        if check["description"]:
            print(f"  {'':<20} {check['description']}")
    return EXIT_OK


def refresh_epss(dest, url="https://epss.cyentia.com/epss_scores-current.csv.gz",
                 opener=None):
    """Télécharge et décompresse le snapshot EPSS vers `dest` (CSV).

    `opener(url, timeout)` renvoie un flux binaire (défaut urllib). Seule sortie
    réseau du projet ; explicitement opt-in via la commande refresh-epss.
    """
    import gzip
    if opener is None:
        import urllib.request
        opener = lambda u, timeout=60: urllib.request.urlopen(u, timeout=timeout)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with opener(url, timeout=60) as resp:
        data = resp.read()
    csv_bytes = gzip.decompress(data)
    dest.write_bytes(csv_bytes)
    return dest


def _has_confirmed_critical(results) -> bool:
    """True s'il existe au moins un finding CRITICAL de confiance 'confirmed'."""
    return any(
        f.get("severity") == "CRITICAL" and f.get("confidence", "confirmed") == "confirmed"
        for r in results
        for f in r.findings
    )


def exit_code_for(results) -> int:
    """Code de sortie d'un audit (voir EXIT_CODES_HELP).

    Un CRITICAL « potential » (heuristique, à valider humainement) ne fait
    pas échouer. Un CRITICAL confirmé l'emporte sur l'audit incomplet."""
    if _has_confirmed_critical(results):
        return EXIT_CRITICAL
    if not audit_is_complete(results):
        return EXIT_INCOMPLETE
    return EXIT_OK


def resolve_format(fmt, output) -> str:
    """--format explicite, sinon déduit de l'extension de --output."""
    if fmt:
        return fmt
    if output:
        return _FORMAT_BY_EXTENSION.get(Path(output).suffix.lower(), "terminal")
    return "terminal"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp-security-forsure",
        description="wp_security_ForSure : audit de sécurité WordPress passif et en lecture seule",
        epilog=EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("action", nargs="?", default="audit",
                        choices=["audit", "list", "vulncache", "refresh-epss"],
                        help="Action à exécuter")
    parser.add_argument("target", nargs="?",
                        help="URL cible (ex: https://cible.com)")
    parser.add_argument("--checks", "-c",
                        help="Checks spécifiques, séparés par des virgules "
                             "(noms donnés par la commande list)")
    parser.add_argument("--output", "-o",
                        help="Fichier de sortie (rapport)")
    parser.add_argument("--format", "-f", choices=["terminal", "json", "html"],
                        default=None,
                        help="Format de sortie (par défaut : déduit de l'extension "
                             "de --output, sinon terminal)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Timeout HTTP (secondes)")
    parser.add_argument("--config",
                        help="Chemin vers config personnalisée")
    parser.add_argument("--authorized", action="store_true", default=False,
                        help=AUTHORIZED_HELP)
    parser.add_argument("--clear", action="store_true", help="vulncache : vider le cache")
    parser.add_argument("--info", action="store_true", help="vulncache : afficher l'état du cache")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.action == "list":
        return list_checks()

    if args.action == "vulncache":
        from .scanner.vulndb.cache import VulnCache
        path = vulncache_path()
        cache = VulnCache(str(path))
        if args.clear:
            cache.clear()
            print(f"Cache CVE vidé : {path}")
        else:
            info = cache.info()
            print(f"Cache CVE : {path}")
            print(f"Entrées en cache : {info['entries']}")
            if info.get("oldest"):
                oldest = datetime.fromtimestamp(info["oldest"], timezone.utc)
                print(f"Fiche la plus ancienne : {oldest.date().isoformat()}")
        return EXIT_OK

    if args.action == "refresh-epss":
        path = refresh_epss(epss_path())
        print(f"EPSS snapshot écrit : {path}")
        return EXIT_OK

    if not args.target:
        parser.error("L'URL cible est requise pour l'action 'audit'")

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = f"https://{target}"

    # Chargement config
    config = load_config()
    if args.config:
        try:
            with open(args.config, encoding="utf-8") as f:
                custom = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as e:
            parser.error(f"configuration illisible ({args.config}) : {e}")
        if not isinstance(custom, dict):
            parser.error(f"configuration invalide ({args.config}) : "
                         "un dictionnaire YAML est attendu")
        config.update(custom)
    config["timeout"] = args.timeout
    # Niveau 2 : option CLI, ou clé `authorized` de la configuration.
    config["authorized"] = bool(args.authorized or config.get("authorized"))

    # Checks demandés ou tous. Un nom inconnu est une erreur d'usage (code 2).
    checks_list = None
    if args.checks is not None:
        checks_list = [c.strip() for c in args.checks.split(",") if c.strip()]
        if not checks_list:
            parser.error("--checks : aucun nom de check fourni (voir la commande list)")
    try:
        engine = ScanEngine(target, config, checks_list)
    except UnknownCheckError as e:
        parser.error(f"{e} (voir la commande list pour les noms disponibles)")

    # Lancement du scan
    results = engine.run_all()

    # Output : format explicite, sinon déduit de l'extension du fichier.
    fmt = resolve_format(args.format, args.output)
    reporter = get_reporter(fmt, results, target, config)
    if fmt == "terminal" and args.output:
        output = reporter.generate(stream=io.StringIO())
    elif fmt == "terminal":
        reporter.generate()   # affiché directement par Rich
        output = None
    else:
        output = reporter.generate()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Rapport sauvegardé : {args.output}")
    elif output is not None:
        print(output)

    return exit_code_for(results)


if __name__ == "__main__":
    sys.exit(main())
