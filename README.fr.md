# wp_security_ForSure

Un audit de sécurité externe des sites WordPress qui ne peut pas modifier le site qu'il audite.
Il n'envoie que des requêtes de lecture ordinaires, celles d'un navigateur ou d'un client WordPress,
et cartographie ce qu'un attaquant extérieur peut apprendre : versions et composants exposés,
vulnérabilités connues, fichiers qui fuient, configuration risquée, scripts injectés.

[English version](README.md) · Statut : alpha (0.1.0) · Licence : Apache-2.0

## Pourquoi un scanner de plus

La plupart des scanners WordPress mêlent la reconnaissance et l'attaque : ils soumettent des
formulaires, essaient des mots de passe, envoient des chaînes d'injection ou devinent des milliers
de chemins. C'est normal dans un test d'intrusion sous contrat signé. Partout ailleurs, c'est un
problème. En France, cela peut relever de l'article 323-1 du Code pénal.

Cet outil prend le parti inverse et l'impose dans le code, pas dans la documentation :

| Garantie | Comment elle est imposée |
|---|---|
| Lecture seule | Le client HTTP refuse toute méthode autre que `GET`, `HEAD` et `OPTIONS` (`PassivityViolation`). Aucun formulaire soumis, aucune tentative de connexion, aucun fichier envoyé. |
| Aucune charge d'attaque | `tests/test_passivity.py` exécute le moteur complet contre un site simulé, enregistre chaque requête et échoue sur toute autre méthode ou sur des charges comme `<script`, `' OR '`, `../` ou des adresses internes. Il tourne en CI à chaque modification. |
| Rien n'est exécuté sur la cible | Les fichiers `.php` devinés sous `wp-content/` (uploads, mu-plugins, drop-ins) et les noms de webshells présumés ne sont jamais demandés : un `GET` les exécuterait. `wp-cron.php` et les diagnostics Site Health ne sont jamais appelés. |
| Accès gradué | Par défaut, l'outil ne demande que la page d'accueil, ce qu'elle référence et les points d'entrée publics standard de WordPress (index de l'API REST, flux, `xmlrpc.php` en `GET`, `wp-login.php`, sitemaps). Deviner des chemins non liés (sauvegardes, `.env`, `.git/`, slugs de plugins) demande `--authorized`, à n'utiliser qu'avec l'autorisation écrite du propriétaire. Sans elle, ces parties sont rapportées « non réalisées ». |
| La cible ne peut pas retourner le scanner contre vous | Chaque requête sortante est résolue puis refusée si elle vise une adresse privée, de bouclage, de lien local ou réservée. Les redirections sont suivies à la main, 5 sauts au plus, seulement vers l'hôte de la cible et sa variante `www.`. Chaque audit a un budget de requêtes. |
| Les secrets ne sortent pas dans les rapports | Un mot de passe, une clé ou un sel trouvé dans un fichier exposé est masqué à la source, puis à nouveau avant l'écriture de tout rapport. |
| Trafic identifiable | Les requêtes portent un User-Agent qui nomme l'outil et renvoie à ce dépôt. Deux exceptions documentées, parce que les injections se cachent des outils : les profils de visite se présentent comme un navigateur (et le contrôle du cloaking comme Googlebot), sur l'accueil et au plus deux pages qu'il lie. |
| La passe navigateur suit les mêmes règles | `--render` est désactivé par défaut. Dans Chromium, seules `GET`, `HEAD` et `OPTIONS` partent ; les autres méthodes, les nœuds RPC de blockchain, la navigation vers un autre site, les WebSocket, les téléchargements et les adresses privées sont bloqués et notés. Le presse-papiers est intercepté, jamais écrit. Le bac à sable de Chromium est obligatoire : sans lui, la passe ne démarre pas. |
| Les erreurs ne sont pas cachées | Un contrôle qui échoue est rapporté « non réalisé », le verdict dit que l'audit est incomplet, et le code de sortie vaut `3`. |

## Installation

Python 3.10 ou plus récent.

```bash
pip install "git+https://github.com/J2K0000/wp_security_ForSure"
```

La passe navigateur facultative demande Playwright et Chromium :

```bash
pip install "wp-security-forsure[render] @ git+https://github.com/J2K0000/wp_security_ForSure"
python -m playwright install chromium
```

Un paquet PyPI (`wp-security-forsure`) suivra.

## Utilisation

```bash
wp-security-forsure list
wp-security-forsure audit https://exemple.fr
wp-security-forsure audit https://exemple.fr --output rapport.html
wp-security-forsure audit https://exemple.fr --checks fingerprint,vulnerability_scan --format json
wp-security-forsure audit https://exemple.fr --authorized   # seulement avec l'autorisation écrite du propriétaire
wp-security-forsure audit https://exemple.fr --render       # exécute aussi les pages dans un Chromium isolé
wp-security-forsure refresh-kev    # télécharge le catalogue CISA KEV (réseau, à la demande seulement)
wp-security-forsure refresh-epss   # télécharge les scores EPSS (réseau, à la demande seulement)
```

Rapports en texte terminal, en JSON ou en page HTML autonome, rédigés en français.
Chaque rapport se termine par ce que l'audit ne peut pas voir, des conseils de durcissement des comptes
(double authentification sur chaque administrateur) et une procédure de réponse à incident, remontée en
tête quand un constat indique une compromission. En JSON : `audit_limits`, `recommendations` et
`incident_response`. Les identifiants relevés sont masqués (`ju***`) sauf s'ils sont eux-mêmes le constat
(`admin`, `test`...) ; `mask_usernames: false` dans la configuration les affiche.

| Code de sortie | Sens |
|---|---|
| 0 | Audit complet, aucun constat critique confirmé |
| 1 | Au moins un constat critique confirmé (l'emporte sur 3) |
| 2 | Erreur d'usage : argument invalide, check inconnu, configuration illisible |
| 3 | Audit incomplet : cible injoignable, ou au moins un contrôle en erreur |

Chaque constat porte un niveau de confiance. `confirmed` signifie que la preuve est déterministe ;
`potential` qu'elle est à vérifier à la main. L'outil ne transforme jamais une hypothèse en certitude.

## Ce qui est contrôlé

`wp-security-forsure list` affiche le catalogue à jour avec ses descriptions. Les contrôles sont
regroupés selon ce qu'un attaquant y gagne :

- Injections côté navigateur : l'accueil et jusqu'à deux pages qu'il lie, demandés sous huit profils de
  visite (clic depuis Google, mobile, autre langue, deux visites directes, cookie de connexion WordPress
  invalide, seconde visite, Googlebot). Les scripts, iframes et redirections que seuls certains profils
  reçoivent sont signalés ; un écart ne compte que si la page ne varie pas déjà entre deux visites
  directes. Les scripts servis aux visiteurs (en ligne, URL `data:` décodées, fichiers `.js` du site,
  quelques scripts tiers inconnus) sont comparés aux signatures publiées de ClickFix et d'EtherHiding,
  listées avec leurs sources dans `wp_security_forsure/signatures/injection_signatures.yaml`. Avec `--render`,
  les pages s'exécutent dans Chromium : écritures dans le presse-papiers, appels de blockchain,
  redirections JavaScript et superpositions de faux CAPTCHA sont notés, et la case d'un faux CAPTCHA
  est cliquée une fois pour révéler la commande qu'il copie.
- Prise de contrôle et intrusion : empreinte des composants et versions, CVE connues (relevées en critique
  quand elles figurent au catalogue CISA des vulnérabilités activement exploitées), version du cœur marquée
  insecure par wordpress.org ou en retard sur sa branche, plugins fermés sur wordpress.org ou sans mise à
  jour depuis 2 ans (seuil propre à l'outil), outils de maintenance laissés en production (remise à zéro de
  base, gestionnaires de fichiers, consoles SQL), noms de comptes à risque (`admin`, `test`, le nom du
  site), exposition
  de l'API REST batch (wp2shell), routes REST de plugins qui acceptent une URL, plugins nullés, surface
  d'attaque des plugins courants, exposition de la connexion et énumération d'utilisateurs, fonctions
  WordPress (XML-RPC, oEmbed, mots de passe d'application), fichiers et dumps exposés, traces de code
  injecté, cloaking et spam SEO, commentaires ouverts sur un article, et avec `--authorized` un
  `.user.ini` lisible dont `auto_prepend_file` désigne un fichier inconnu.
- Exposition de données : contenus et utilisateurs de l'API REST, cookies et sessions, scripts
  tiers, configuration TLS, authentification des e-mails (SPF, DKIM, DMARC), récepteurs de webhooks.
- Durcissement : en-têtes de sécurité, configuration serveur, détection de WAF et de CDN (un CAPTCHA
  seul n'est pas lu comme un WAF : un faux passerait pour une protection), prise de
  contrôle de sous-domaine, plugins de cache, multisite.

## Ce qu'il ne voit pas

Un audit en boîte noire et en lecture seule a des limites. Le rapport les dit au lieu d'afficher
« propre ».

- **Un site déjà compromis.** Une porte dérobée dans le `functions.php` d'un thème, un mu-plugin, un
  drop-in, la base de données ou une tâche planifiée est invisible de l'extérieur. Répondre à « suis-je
  déjà piraté ? » demande un accès serveur : `wp core verify-checksums`, `wp plugin verify-checksums`,
  revue de `wp-content/mu-plugins/`, des drop-ins, des administrateurs et des options.
- **Une partie des injections servies à certains visiteurs seulement.** Les profils de visite
  couvrent le Referer, l'appareil, la langue, le cookie de connexion et la seconde visite. Ils ne
  déclenchent ni le cloaking qui vérifie l'adresse IP de Googlebot, ni le ciblage par pays ou par
  adresse IP du visiteur : toutes les visites partent de votre adresse. Sans `--render`, les
  conditions évaluées en JavaScript (localStorage, détection d'automatisation) ne sont pas vues.
- **Les versions masquées.** Quand un site cache tous ses signaux de version, l'appariement des CVE ne
  peut pas s'appuyer dessus. Aucune version trouvée ne prouve aucune faille.
- **Tout ce qui est derrière une authentification**, ainsi que les rapports Sécurité et Actions
  manuelles de Google Search Console, qui n'ont pas d'API. Vérifiez-les dans votre propriété.
- **Les sauvegardes.** On ne voit pas de l'extérieur si une copie existe hors du serveur et si elle a
  déjà été restaurée. On voit en revanche les fichiers de sauvegarde exposés.

## Trafic réseau

En plus de la cible, un audit contacte :

| Hôte | Pourquoi | Quand |
|---|---|---|
| `www.wpvulnerability.net` | Vulnérabilités connues de chaque composant détecté | Pour chaque composant absent du cache local ou en cache depuis plus de 7 jours |
| `api.wordpress.org` | Statut des versions du cœur (`stable-check`, `version-check`) | À chaque audit, cache de 24 heures |
| `api.wordpress.org` | Fiche du plugin : fermé, abandonné, copie nullée | Pour chaque plugin détecté, cache de 7 jours |
| Hôtes référencés par la page d'accueil | Services tiers abandonnés (contrôle de prise de contrôle) | À chaque audit (DNS et `GET`, mêmes gardes) |
| Hôtes de scripts tiers | Contenu d'au plus 10 scripts inconnus cités par les pages auditées (services très répandus et bibliothèques blockchain exclus) | À chaque audit |
| Hôtes que les pages chargent (scripts, polices, iframes) | Ce que charge le navigateur d'un visiteur, dans Chromium, en `GET` seulement | Seulement avec `--render` (`render_third_party: false` les bloque) |
| Votre résolveur DNS | Enregistrements SPF, DKIM et DMARC | À chaque audit |
| `crt.sh` | Énumération des sous-domaines | Seulement avec `takeover_enum: true` dans la configuration |
| Fichier de données EPSS | Scores de prédiction d'exploitation | Seulement avec `wp-security-forsure refresh-epss` |
| `www.cisa.gov` | Catalogue des vulnérabilités activement exploitées (KEV) | Seulement avec `wp-security-forsure refresh-kev` |

Le cache CVE, les instantanés EPSS et KEV et le cache wordpress.org sont dans votre dossier de cache utilisateur
(`%LOCALAPPDATA%\wp_security_forsure` sous Windows, `~/.cache/wp_security_forsure` ailleurs), ou dans
`WP_SECURITY_FORSURE_CACHE_DIR` si la variable est définie. Les rapports indiquent la provenance de
leurs données de vulnérabilités et leur âge.

## Usage responsable

À lancer sur des sites qui vous appartiennent ou que vous êtes mandaté pour auditer. Lisez
[docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md) avant d'utiliser `--authorized` ou `--render`. Les identifiants et
adresses e-mail trouvés pendant un audit sont des données personnelles : gardez les rapports privés et
supprimez-les à la fin de la mission.

## Sources de données

- Vulnérabilités : [WPVulnerability](https://www.wpvulnerability.net/), interrogé à l'exécution.
- Prédiction d'exploitation : [EPSS de FIRST](https://www.first.org/epss/), téléchargé à la demande.
- Exploitation active : [catalogue KEV de la CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), téléchargé à la demande.
- Statut du cœur et des plugins : l'[API publique de WordPress.org](https://api.wordpress.org/).
- Signatures d'injection : indicateurs publiés par Microsoft Threat Intelligence, Google Threat
  Intelligence, Trend Micro et Rapid7, chaque entrée avec son lien dans
  `wp_security_forsure/signatures/injection_signatures.yaml`.

## Feuille de route

- Un mode authentifié en lecture seule pour l'intégrité (sommes de contrôle, drop-ins, mu-plugins,
  administrateurs).
- Sortie SARIF et `diff` entre deux rapports.
- Un instantané WPVulnerability hors ligne, et des listes de plugins surveillés alimentées par les CVE.

## Contribuer

Voir [CONTRIBUTING.md](CONTRIBUTING.md). Les vulnérabilités de l'outil se signalent en privé, comme
indiqué dans [SECURITY.md](SECURITY.md).

## Licence

Apache License 2.0. Voir [LICENSE](LICENSE) et [NOTICE](NOTICE).
WordPress est une marque de la WordPress Foundation. Ce projet n'est ni affilié à elle ni approuvé par elle.
