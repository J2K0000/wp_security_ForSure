# Responsible use

wp_security_ForSure is built for site owners, the people they mandate (agencies, freelancers,
auditors) and security researchers acting in good faith. This page says what the tool does to a
target, what stays your responsibility, and where the legal lines are. It is not legal advice.

## What the tool does to a target

- It only sends `GET`, `HEAD` and `OPTIONS` requests. It never submits a form, never tries a
  password, never uploads a file, never sends an injection or traversal string.
- It never requests a guessed `.php` file under `wp-content/` or a presumed web shell, because a `GET`
  would execute it on the server, and it never calls `wp-cron.php` or a Site Health diagnostic.
- By default (level 0 and 1) it only requests the home page, the resources that page references, and
  the standard public endpoints any WordPress client uses.
- With `--authorized` (level 2) it also checks whether well-known unlinked paths exist: backups,
  environment and configuration files, `.git/`, debug logs, plugin and theme slugs. It is still
  read-only, but guessing paths is reconnaissance that a site owner did not invite.
- Each audit has a request budget, and requests carry a user agent that names the tool and links to
  this repository, so the site owner can identify the traffic. Visitor profiles are the exception:
  about 25 requests on the home page and at most two pages it links present a browser, one of them
  with an invalid WordPress login cookie, because injections hide from tools and from logged-in
  users. The cookie opens no session.

## The browser pass (`--render`)

- It runs the site's JavaScript, including malicious code if the site is infected, inside Chromium's
  sandbox. Run it from a disposable virtual machine or container with no credentials and no mounted
  folders, not from your everyday workstation.
- Inside the browser the same rules apply: only `GET`, `HEAD` and `OPTIONS` leave; other methods,
  blockchain RPC nodes and explorers, navigation to another site, WebSockets, downloads, pop-ups and
  private addresses are blocked and recorded. Writes to the clipboard are captured and cancelled.
- It loads third-party hosts the page asks for, as a visitor's browser would, unless you set
  `render_third_party: false`.
- It hides `navigator.webdriver` and the "HeadlessChrome" user agent, because ClearFake serves a clean
  page to automated browsers. This evades the malware's checks, not the site's protections.
- When a page shows a fake CAPTCHA, it clicks the verification box once, to see what the page puts on
  the clipboard. It never clicks anything else.

## Your responsibility

- **Authorisation.** Audit sites you own or are mandated to audit, and keep the mandate in writing.
  Use `--authorized` only when that mandate covers it. In France, accessing or remaining in a system
  without right is an offence (Penal Code, article 323-1), and so is providing a tool designed for
  such offences "without legitimate reason" (article 323-3-1). Read-only requests reduce the risk.
  They do not replace an authorisation.
- **Personal data.** Usernames and email addresses that a site exposes are personal data under the
  GDPR. You decide what the report keeps, where it is stored, who receives it and when it is deleted.
  Keep reports private.
- **Disclosure.** If you find a vulnerability on a site you do not own, contact its owner. In France,
  you can also report it in good faith to ANSSI, which protects the reporter's identity (Defence Code,
  article L. 2321-4). Report vulnerabilities in WordPress, plugins or themes to their vendor or to a
  WordPress CNA (Wordfence, Patchstack, WPScan).
- **Results.** Findings marked `potential` need manual confirmation. A clean report is not a
  guarantee: read the "what it does not see" section of the README.

## What the project will not accept

Contributions that add active probes (form submission, authentication attempts, uploads, injection
payloads, cache poisoning, exploitation of a vulnerability) are declined. This tool maps the external
exposure of a site; penetration testing belongs to other tools and to signed engagements.

---

# Usage responsable (résumé en français)

- L'outil n'envoie que des requêtes `GET`, `HEAD` et `OPTIONS`, ne demande jamais un `.php` deviné sous
  `wp-content/` ni un webshell présumé, et n'appelle jamais `wp-cron.php` ni un diagnostic Site Health.
- Par défaut, il ne demande que la page d'accueil, ses ressources et les points d'entrée publics de
  WordPress. `--authorized` ajoute la recherche de chemins non liés, à réserver à un audit sous mandat
  écrit.
- Les profils de visite se présentent comme un navigateur, sur l'accueil et au plus deux pages qu'il
  lie, dont un avec un cookie de connexion WordPress invalide, qui n'ouvre aucune session.
- `--render` exécute le JavaScript du site, code malveillant compris, dans le bac à sable de Chromium :
  à lancer depuis une machine virtuelle ou un conteneur jetable. Seules les lectures partent ; appels
  de blockchain, navigation vers un autre site, WebSocket et téléchargements sont bloqués, le
  presse-papiers est intercepté. Seule la case d'un faux CAPTCHA est cliquée, une fois.
- Auditer sans droit un système relève de l'article 323-1 du Code pénal ; mettre à disposition un outil
  conçu pour cela « sans motif légitime » relève de l'article 323-3-1. La lecture seule réduit le risque,
  elle ne remplace pas une autorisation.
- Les identifiants et e-mails relevés sont des données personnelles (RGPD) : gardez les rapports privés
  et supprimez-les à la fin de la mission.
- Une faille trouvée sur un site tiers se signale à son propriétaire, et peut l'être de bonne foi à
  l'ANSSI (article L. 2321-4 du Code de la défense).
- Ce texte n'est pas un conseil juridique.
