"""forms_upload, Détection des vulnérabilités liées aux formulaires et uploads.

Couvre :
  1) Upload endpoint detection (lecture de wp-json/wp/v2/media). Les
     gestionnaires d'upload des extensions (fichiers PHP sous
     wp-content/plugins/) ne sont plus demandés : un GET les exécuterait
     (constat INFO « non évaluable de l'extérieur »).
  2) Contact Form 7 detection + version (readme.txt deviné : niveau 2,
     option --authorized)
  3) Gravity Forms detection
  4) Elementor form detection
  5) WPForms detection
  6) Comment form nonce test
  7) Login form autocomplete analysis
  8) Registration form detection (passif : lecture du formulaire, jamais de
     création de compte)
  9) Lost password form reachability (passif : jamais de vraie demande de
     réinitialisation envoyée)

Toutes les sondes sont STRICTEMENT PASSIVES (GET/HEAD uniquement) : aucun
check de ce module ne crée de fichier, de compte, ni ne déclenche un email sur
la cible. Retirés car impossibles sans requête active : les actions d'upload
admin-ajax.php (POST), le POST anonyme sur l'API media et le test de XSS
réfléchi de la recherche (charge d'attaque). Ils sont signalés par un constat
INFO « non évaluable passivement ».
"""

import re
from typing import List, Optional
from urllib.parse import urlparse, urljoin

from .base import BaseCheck, CheckResult

class FormsUploadCheck(BaseCheck):
    """Vérifie la sécurité des formulaires et des endpoints d'upload."""

    name = "forms_upload"
    title = "Formulaires & Upload"
    description = (
        "Détection des vulnérabilités liées aux formulaires (login, commentaire, "
        "recherche, inscription, mot de passe perdu) et aux endpoints d'upload "
        "(admin-ajax, REST API, plugins)."
    )
    severity = "HIGH"
    access_tier = 1  # mixte : readme.txt d'extensions sous --authorized
    depends_on: List[str] = []

    # --- Constantes ---

    # Gestionnaires d'upload connus : documentés dans le constat INFO, jamais
    # demandés (fichiers PHP sous wp-content/plugins/, un GET les exécute).
    PLUGIN_UPLOAD_PATHS = [
        # Contact Form 7
        "wp-content/plugins/contact-form-7/modules/file.php",
        "wp-content/plugins/cf7-conditional-fields/scripts/upload.php",
        # Gravity Forms
        "wp-content/plugins/gravityforms/includes/upload.php",
        "wp-content/plugins/gravityforms/upload.php",
        # Elementor Pro
        "wp-content/plugins/elementor-pro/assets/lib/file-upload/file-upload.php",
        # WPForms
        "wp-content/plugins/wpforms/pro/includes/fields/class-file-upload.php",
        "wp-content/plugins/wpforms-lite/pro/includes/fields/class-file-upload.php",
        # Fluent Forms
        "wp-content/plugins/fluentform/app/Services/Integrations/FileUpload.php",
        # Forminator
        "wp-content/plugins/forminator/library/fields/upload.php",
        # WooCommerce
        "wp-content/plugins/woocommerce/includes/class-wc-upload.php",
        # WP File Upload
        "wp-content/plugins/wp-file-upload/wp-file-upload.php",
        # User Submitted Posts
        "wp-content/plugins/user-submitted-posts/inc/upload.php",
    ]

    PLUGIN_DETECTION = [
        {
            "name": "Contact Form 7",
            "paths": [
                "wp-content/plugins/contact-form-7/readme.txt",
            ],
            "version_from": "wp-content/plugins/contact-form-7/readme.txt",
        },
        {
            "name": "Gravity Forms",
            "paths": [
                "wp-content/plugins/gravityforms/readme.txt",
            ],
            "version_from": "wp-content/plugins/gravityforms/readme.txt",
        },
        {
            "name": "Elementor (free)",
            "paths": [
                "wp-content/plugins/elementor/readme.txt",
            ],
            "version_from": "wp-content/plugins/elementor/readme.txt",
        },
        {
            "name": "Elementor Pro",
            "paths": [
                "wp-content/plugins/elementor-pro/readme.txt",
            ],
            "version_from": "wp-content/plugins/elementor-pro/readme.txt",
        },
        {
            "name": "WPForms",
            "paths": [
                "wp-content/plugins/wpforms/readme.txt",
                "wp-content/plugins/wpforms-lite/readme.txt",
            ],
            "version_from": "wp-content/plugins/wpforms/readme.txt",
        },
    ]

    # --- Méthodes privées ---

    def _extract_version_from_readme(self, path: str) -> Optional[str]:
        """Tente d'extraire la version depuis un fichier readme.txt."""
        try:
            resp = self.http_get(path)
            if resp.status_code == 200:
                # Stable tag: X.Y.Z  or  Version: X.Y.Z
                m = re.search(
                    r"(?:stable\s*tag|version)[:\s]*([\d.]+)",
                    resp.text,
                    re.IGNORECASE,
                )
                if m:
                    return m.group(1)
        except Exception:
            pass
        return None

    def _check_plugin_upload_paths(self) -> List[dict]:
        """Gestionnaires d'upload des extensions : sonde retirée.

        Ce sont des fichiers PHP sous wp-content/plugins/ : un HEAD ou un GET
        les exécuterait côté serveur. Constat INFO « non évaluable »."""
        return [{
            "message": (
                "Gestionnaires d'upload des extensions de formulaire "
                f"({len(self.PLUGIN_UPLOAD_PATHS)} fichiers PHP sous "
                "wp-content/plugins/) : non évaluable de l'extérieur sans "
                "exécuter le fichier ; à vérifier en mode authentifié"
            ),
            "severity": "INFO",
            "evidence": (
                "Fichiers non demandés : " + ", ".join(self.PLUGIN_UPLOAD_PATHS)
                + ". Un GET sur un fichier PHP l'exécute côté serveur : le "
                "scanner ne l'envoie à aucun niveau d'accès."
            ),
            "url": f"{self.target}/",
            "confidence": "potential",
        }]

    def _check_media_endpoint(self) -> List[dict]:
        """Teste l'accès en lecture à wp-json/wp/v2/media (GET seul, passif).

        L'acceptation d'un upload anonyme ne se vérifie qu'avec un POST : ce
        sous-contrôle est non évaluable passivement (voir _not_assessable).
        """
        findings = []
        media_url = "wp-json/wp/v2/media"

        try:
            resp = self.http_get(media_url)
            if resp.status_code == 200:
                findings.append({
                    "message": (
                        "Endpoint media REST API accessible en lecture "
                        "(wp-json/wp/v2/media)"
                    ),
                    "severity": "INFO",
                    "evidence": (
                        f"HTTP {resp.status_code} : accès public aux médias."
                    ),
                    "url": f"{self.target}/{media_url}",
                })
        except Exception:
            pass

        return findings

    def _detect_plugins(self) -> List[dict]:
        """Détecte les plugins de formulaire et leurs versions.

        readme.txt devinés (niveau 2) : seulement avec --authorized."""
        findings = []
        if not self.config.get("authorized"):
            return [{
                "message": (
                    "Non réalisé sans --authorized (recherche de chemins non "
                    "liés) : détection par readme.txt des extensions de "
                    "formulaire (" + ", ".join(
                        p["name"] for p in self.PLUGIN_DETECTION) + ")"
                ),
                "severity": "INFO",
                "evidence": (
                    "Ces sondes visent des chemins devinés et non liés (niveau "
                    "2), réservés à l'audit d'un site dont le propriétaire a "
                    "donné son autorisation écrite (option --authorized)."
                ),
                "url": f"{self.target}/",
                "confidence": "potential",
            }]
        for plugin in self.PLUGIN_DETECTION:
            name = plugin["name"]
            detected = False
            version = None

            # Vérifier les chemins d'existence
            for path in plugin["paths"]:
                try:
                    resp = self.http_head(path)
                    if resp.status_code == 200:
                        detected = True
                        break
                except Exception:
                    pass

            if detected:
                base = plugin.get("version_from", "")
                if base:
                    version = self._extract_version_from_readme(base)

                msg = f"{name} détecté"
                if version:
                    msg += f" (version {version})"
                findings.append({
                    "message": msg,
                    "severity": "MEDIUM",
                    "evidence": f"Plugin présent. Version : {version or 'inconnue'}.",
                    "url": f"{self.target}/wp-content/plugins/{name.lower().replace(' ', '-')}/",
                })
        return findings

    def _check_comment_nonce(self) -> List[dict]:
        """Vérifie si le formulaire de commentaire possède un nonce."""
        findings = []
        try:
            resp = self.http_get("")
            page = resp.text if resp.text else ""

            # Chercher des indicateurs de nonce dans le formulaire de commentaire
            nonce_indicators = [
                "wp_comment_nonce",
                "_wp_unfiltered_html_comment",
                "akismet_nonce",
                "comment_nonce",
                "_wpnonce",
            ]
            found_nonce = False
            for indicator in nonce_indicators:
                if indicator in page:
                    found_nonce = True
                    break

            # Vérifier aussi wp-comments-post.php
            has_comment_form = (
                "wp-comments-post.php" in page
                or "commentform" in page.lower()
                or "id=\"commentform\"" in page
                or "id=\"respond\"" in page
            )

            if has_comment_form and not found_nonce:
                findings.append({
                    "message": (
                        "Formulaire de commentaire sans nonce (comportement WordPress "
                        "natif pour les visiteurs anonymes)"
                    ),
                    "severity": "LOW",
                    "evidence": (
                        "Le formulaire de commentaire WordPress n'a pas de nonce pour "
                        "un visiteur anonyme (par design ; l'anti-spam repose sur "
                        "Akismet/modération). Pas une vulnérabilité propre au site."
                    ),
                    "url": f"{self.target}/",
                    "confidence": "potential",
                })
            elif has_comment_form:
                findings.append({
                    "message": "Formulaire de commentaire protégé par nonce",
                    "severity": "INFO",
                    "evidence": "Nonce présent dans le formulaire de commentaire.",
                    "url": f"{self.target}/",
                })
        except Exception:
            pass

        return findings

    def _not_assessable(self) -> List[dict]:
        """Constat INFO : sous-contrôles retirés car impossibles sans sonde
        active (le scanner n'émet que GET, HEAD et OPTIONS)."""
        return [{
            "message": (
                "Sous-contrôles formulaires non évaluables passivement : actions "
                "d'upload admin-ajax.php, upload anonyme via l'API media, XSS "
                "réfléchi de la recherche"
            ),
            "severity": "INFO",
            "evidence": (
                "Ces vérifications exigent un POST ou l'envoi d'une charge "
                "d'attaque, que le scanner n'émet jamais (lecture seule). À "
                "vérifier manuellement, dans un cadre autorisé."
            ),
            "url": f"{self.target}/",
        }]

    def _check_login_autocomplete(self) -> List[dict]:
        """Analyse les attributs autocomplete du formulaire de login."""
        findings = []
        login_urls = ["wp-login.php", "wp-admin/"]

        for url_path in login_urls:
            try:
                resp = self.http_get(url_path)
                if resp.status_code != 200:
                    continue
                page = resp.text

                # Chercher les champs de type password
                password_inputs = re.findall(
                    r'<input[^>]*type=[\"\']password[\"\'][^>]*>', page, re.IGNORECASE
                )

                if not password_inputs:
                    continue

                for inp in password_inputs:
                    # Vérifier autocomplete
                    ac_match = re.search(r'autocomplete=[\"\']([^\"\']*)[\"\']', inp)
                    if ac_match:
                        ac_value = ac_match.group(1).lower()
                        if ac_value == "off":
                            findings.append({
                                "message": (
                                    f"Champ mot de passe avec autocomplete=\"off\" "
                                    f"sur {url_path}"
                                ),
                                "severity": "LOW",
                                "evidence": (
                                    "autocomplete=\"off\" bloque les gestionnaires "
                                    "de mots de passe, ce qui pousse les utilisateurs "
                                    "à utiliser des mots de passe faibles ou à les "
                                    "réutiliser. Préférer autocomplete=\"new-password\"."
                                ),
                                "url": f"{self.target}/{url_path}",
                            })
                        elif ac_value == "new-password":
                            # Bonne pratique moderne
                            pass
                        else:
                            findings.append({
                                "message": (
                                    f"Attribut autocomplete=\"...{ac_value}...\" "
                                    f"sur champ mot de passe ({url_path})"
                                ),
                                "severity": "INFO",
                                "evidence": f"autocomplete=\"{ac_value}\"",
                                "url": f"{self.target}/{url_path}",
                            })
                    else:
                        findings.append({
                            "message": (
                                f"Champ mot de passe sans attribut autocomplete "
                                f"sur {url_path}"
                            ),
                            "severity": "LOW",
                            "evidence": (
                                "L'attribut autocomplete est absent. Ajouter "
                                "autocomplete=\"new-password\" pour les champs "
                                "mot de passe."
                            ),
                            "url": f"{self.target}/{url_path}",
                        })

            except Exception:
                pass

        return findings

    def _check_registration(self) -> List[dict]:
        """Détecte si l'inscription est ouverte, STRICTEMENT PASSIF.

        Aucun compte n'est jamais créé : ni GET ni POST ne sont envoyés vers
        l'endpoint REST d'inscription au-delà d'une lecture de son existence.
        La détection « inscription ouverte » repose uniquement sur la
        lecture (GET) du formulaire natif wp-login.php?action=register.
        """
        findings = []

        # 1) Existence (lecture seule) de l'endpoint REST, jamais de POST.
        # NB : WP core enregistre TOUJOURS cette route (elle répond 403 quand
        # l'inscription est fermée), sa seule existence n'est donc PAS une
        # preuve d'inscription ouverte, juste un indice à confirmer.
        rest_register = "wp-json/wp/v2/users/register"
        try:
            resp = self.http_get(rest_register)
            if resp.status_code != 404:
                findings.append({
                    "message": (
                        "Route REST d'inscription présente, inscription "
                        "ouverte à confirmer (wp-json/wp/v2/users/register)"
                    ),
                    "severity": "MEDIUM",
                    "evidence": (
                        f"HTTP {resp.status_code}, WordPress core enregistre "
                        "toujours cette route (elle répond aussi 403 quand "
                        "l'inscription est fermée) ; sa seule présence "
                        "n'établit pas que l'inscription est ouverte."
                    ),
                    "url": f"{self.target}/{rest_register}",
                    "confidence": "potential",
                })
        except Exception:
            pass

        # 2) Formulaire natif wp-login.php?action=register, lecture seule,
        # la seule présence du formulaire suffit à établir que l'inscription
        # est ouverte (déterministe -> confirmed).
        reg_page = "wp-login.php?action=register"
        try:
            resp = self.http_get(reg_page)
            if resp.status_code == 200:
                page = resp.text or ""
                has_form = (
                    "id=\"registerform\"" in page
                    or "user_login" in page
                    or "user_email" in page
                    or "action=register" in page
                )
                if has_form:
                    findings.append({
                        "message": (
                            "Inscription ouverte (wp-login.php?action=register)"
                        ),
                        "severity": "MEDIUM",
                        "evidence": (
                            "Le formulaire d'inscription standard WordPress "
                            "est accessible et rendu (aucune tentative de "
                            "création de compte n'a été effectuée)."
                        ),
                        "url": f"{self.target}/{reg_page}",
                        "confidence": "confirmed",
                    })
        except Exception:
            pass

        return findings

    def _check_lostpassword_enumeration(self) -> List[dict]:
        """Note l'accessibilité du formulaire mot de passe perdu -
        STRICTEMENT PASSIF.

        L'ancienne version POSTait une vraie demande de réinitialisation
        pour « admin », ce qui déclenche un email réel côté cible : c'est
        une mutation interdite. On se contente désormais d'un GET pour
        constater que le formulaire natif WordPress est joignable, sans
        jamais soumettre de user_login.
        """
        findings = []
        lost_pw_url = "wp-login.php?action=lostpassword"

        try:
            resp = self.http_get(lost_pw_url)
            if resp.status_code == 200:
                page = resp.text or ""
                has_form = (
                    "id=\"lostpasswordform\"" in page
                    or "user_login" in page
                    or "action=lostpassword" in page
                )
                if has_form:
                    findings.append({
                        "message": (
                            "Formulaire mot de passe perdu accessible "
                            "(wp-login.php?action=lostpassword)"
                        ),
                        "severity": "INFO",
                        "evidence": (
                            "Le formulaire standard WordPress de "
                            "réinitialisation de mot de passe est joignable. "
                            "Aucune demande réelle n'a été envoyée "
                            "(détection passive uniquement, pas de test "
                            "d'énumération actif)."
                        ),
                        "url": f"{self.target}/{lost_pw_url}",
                    })
        except Exception:
            pass

        return findings

    # --- Méthode principale ---

    def run(self) -> CheckResult:
        """Exécute tous les sous-checks et retourne le résultat consolidé."""
        self._result.check_name = self.name
        self._result.title = self.title
        self._result.description = self.description

        all_findings = []

        # 1) Plugin upload paths
        all_findings.extend(self._check_plugin_upload_paths())

        # 2) REST API media endpoint (lecture seule)
        all_findings.extend(self._check_media_endpoint())

        # 3) Plugin detection (CF7, Gravity, Elementor, WPForms)
        all_findings.extend(self._detect_plugins())

        # 4) Comment form nonce test
        all_findings.extend(self._check_comment_nonce())

        # 5) Login autocomplete analysis
        all_findings.extend(self._check_login_autocomplete())

        # 6) Registration detection
        all_findings.extend(self._check_registration())

        # 7) Lost password user enumeration
        all_findings.extend(self._check_lostpassword_enumeration())

        # 8) Sous-contrôles retirés (actifs) : constat INFO
        all_findings.extend(self._not_assessable())

        # Ajouter tous les findings au résultat
        for f in all_findings:
            self._result.add_finding(
                message=f["message"],
                severity=f.get("severity", "INFO"),
                evidence=f.get("evidence", ""),
                url=f.get("url", ""),
                confidence=f.get("confidence", "confirmed"),
                access_class=f.get("access_class"),
                impact=f.get("impact"),
            )

        return self._result
