# Legal & Ethics, WordPress Security Audit Reference Document

> **Purpose**: This document provides the legal and ethical framework governing all WordPress security audits performed by [Your Company/Your Name]. It must be reviewed, acknowledged, and signed by the client *before* any scanning or testing begins.
>
> **Version**: 1.0 | **Last Updated**: 2026-07-16
>
> **⚠️ Disclaimer**: This document is for informational purposes and does not constitute legal advice. Consult a qualified attorney in your jurisdiction before finalizing contracts, consent forms, or disclosure policies.

---

## Table of Contents

1. [Authorization Requirements](#1-authorization-requirements)
2. [GDPR Implications](#2-gdpr-implications)
3. [French Law, Loi Godfrain & Code Pénal](#3-french-law--loi-godfrain--code-pénal)
4. [Responsible Disclosure Policy Template](#4-responsible-disclosure-policy-template)
5. [Limitation of Liability, Disclaimer](#5-limitation-of-liability--disclaimer)
6. [Data Handling Policy](#6-data-handling-policy)
7. [Scope Definition](#7-scope-definition)
8. [Sample Consent Form (French)](#8-sample-consent-form-french)
9. [Ethical Boundaries](#9-ethical-boundaries)
10. [Insurance Considerations](#10-insurance-considerations)

---

## 1. Authorization Requirements

### 1.1 Principle

**No scanning, probing, or testing of any WordPress site shall commence without explicit, informed, written consent from the site owner or their legally authorized representative.**

Unauthorized security testing, even with benign intent, can constitute a criminal offense under multiple legal frameworks (see Section 3). Written authorization is the single most important legal safeguard for both the auditor and the client.

### 1.2 Minimum Authorization Checklist

Before any scan begins, the auditor must obtain:

| Item | Description | Status |
|------|-------------|--------|
| ✅ Signed consent form | Client name, site URL(s), testing dates, scope, authorized tester identity | ☐ |
| ✅ Scope document | Agreed list of URLs, subdomains, IPs, and excluded systems | ☐ |
| ✅ Contact details | Emergency contact (phone + email) for the client during testing | ☐ |
| ✅ Third-party notice | Written acknowledgment from client that they own or have permission from the hosting provider to test | ☐ |
| ✅ Insurance confirmation | Client informed of auditor's insurance coverage (see Section 10) | ☐ |

### 1.3 Authorization Validity Period

- A single consent form is valid for **one audit engagement only** (one scan cycle + one report cycle).
- Recurring audits (e.g., monthly) require either a **renewed form per engagement** or a **standing annual authorization** with explicit termination conditions.
- Authorization can be revoked at any time by the client in writing. Upon revocation, all testing must cease immediately and any collected data must be purged within 72 hours.

### 1.4 When Authorization Is Not Sufficient

Even with written consent, the auditor must **never**:

- Test sites they do not have express permission to test, even if "asked" by a third party.
- Allow the consent form to authorize activity outside the defined scope.
- Assume hosting provider consent is implied, the client must confirm this separately.

---

## 2. GDPR Implications

### 2.1 Personal Data in Scan Artifacts

WordPress security scans may inadvertently capture personal data. Common examples:

| Artifact Type | Potential Personal Data |
|---------------|------------------------|
| Database dumps | User emails, IP addresses, hashed passwords, names, metadata |
| HTTP responses | Session cookies, CSRF tokens, personal info in form fields, API payloads |
| Logs | Visitor IP addresses, timestamps (geolocation), user-agent strings |
| Upload directory listing | User-uploaded files (may contain personal images, documents) |

### 2.2 Legal Basis for Processing

Under GDPR Article 6, the audit's legal basis is **Legitimate Interest** (Article 6(1)(f)), the processing is necessary for the security of the data controller's system. However, the auditor must:

1. **Minimize data collection**: Only capture data strictly necessary for the audit.
2. **Inform the data controller** (client) of the types of personal data that may be processed.
3. **Provide a Data Processing Agreement (DPA)** if the auditor is considered a "processor" under GDPR.

### 2.3 Data Retention Policy for Scan Artifacts

| Data Type | Retention Period | Rationale |
|-----------|-----------------|-----------|
| Raw scan output (logs, screenshots) | 90 days after report delivery | Allows re-verification if client disputes findings |
| Final audit report | 2 years (or as agreed in contract) | Legal/insurance record retention |
| Client PII (name, email, billing) | Duration of client relationship + 3 years (tax compliance) | Accounting and legal obligations |
| Database extracts (sanitized) | 7 days after report delivery; auto-purged | Minimization principle |
| Cookies/tokens captured | Deleted immediately after analysis | High sensitivity, not retained |
| IP addresses in scan logs | 30 days, then anonymized | Operational security monitoring |

**Auto-purge mechanism**: All scan artifacts on auditor systems must be subject to automated deletion policies. Manual extension requires written client approval.

### 2.4 Data Subject Rights

If a data subject (e.g., a WordPress user whose email was captured in a scan) exercises their GDPR rights (access, erasure, rectification), the auditor must:

1. **Acknowledge within 72 hours**.
2. **Verify the requestor's identity** before taking action.
3. **Coordinate with the client** (data controller), the client owns the relationship with the data subject.
4. **Document the request and response** per Article 5(2) accountability principle.

### 2.5 Cross-Border Transfers

If scan data crosses EU borders (e.g., auditor is EU-based, client is non-EU), ensure:

- Standard Contractual Clauses (SCCs) are in place.
- Adequacy decisions apply where relevant.
- Data is stored within the EU or a recognized adequate jurisdiction when possible.

---

## 3. French Law, Loi Godfrain & Code Pénal

### 3.1 Overview

In France, unauthorized access to, or maintenance within, an automated data processing system is a criminal offense under the **Loi Godfrain** (Law 88-19 of 5 January 1988), now codified in **Articles 323-1 to 323-7 of the French Code Pénal**.

> ⚠️ **Critical**: Even with a signed consent form, if the consent does not explicitly and clearly authorize the specific testing actions, the auditor may still be committing an offense. French courts interpret these articles broadly.

### 3.2 Key Articles

#### Article 323-1, Unauthorized Access & Maintenance

> *Le fait d'accéder ou de se maintenir, frauduleusement, dans tout ou partie d'un système de traitement automatisé de données est puni de deux ans d'emprisonnement et de 60 000 € d'amende.*
>
> *Lorsqu'il en est résulté soit la suppression ou la modification de données contenues dans le système, soit une altération du fonctionnement de ce système, la peine est de trois ans d'emprisonnement et de 100 000 € d'amende.*

- **Up to 2 years imprisonment + €60,000 fine** for accessing a system without authorization.
- **Up to 3 years imprisonment + €100,000 fine** if data is altered or system functioning is impaired.

#### Article 323-2, Obstruction

> *Le fait d'entraver ou de fausser le fonctionnement d'un système de traitement automatisé de données est puni de cinq ans d'emprisonnement et de 150 000 € d'amende.*

- **Up to 5 years imprisonment + €150,000 fine** for hindering or falsifying the operation of a system.
- This covers DoS testing, rate-limiting bypasses, and any action that degrades system performance.

#### Article 323-3, Data Introduction, Deletion, or Modification

> *Le fait d'introduire frauduleusement des données dans un système de traitement automatisé ou de supprimer ou de modifier frauduleusement les données qu'il contient est puni de cinq ans d'emprisonnement et de 150 000 € d'amende.*

- **Up to 5 years imprisonment + €150,000 fine** for fraudulent data introduction, deletion, or modification.
- This covers any form of data modification, even with "good intentions" like fixing insecure configurations.

#### Article 323-3-1, Extraction of Data

> *Le fait, sans motif légitime, d'extraire, de détenir, de reproduire, de transmettre, de supprimer ou de modifier frauduleusement les données d'un système de traitement automatisé est puni de sept ans d'emprisonnement et de 300 000 € d'amende.*

- **Up to 7 years imprisonment + €300,000 fine** for extracting, holding, reproducing, or transmitting data without legitimate reason.

#### Article 323-4, Organized Group

> *Les infractions prévues aux articles 323-1 à 323-3-1, lorsqu'elles sont commises en bande organisée, sont punies de dix ans d'emprisonnement et de 500 000 € d'amende.*

- **Up to 10 years imprisonment + €500,000 fine** when committed by an organized group.

#### Article 323-4-1, Attempt

> *La tentative des infractions prévues à la présente section est punie des mêmes peines.*

- **Attempt is punishable with the same penalties** as the completed offense.

#### Article 323-5, Phishing/Counterfeiting

> *Le fait, sans motif légitime, d'importer, de détenir, d'offrir, de céder ou de mettre à disposition un équipement, un instrument, un programme informatique ou des données conçus ou spécialement adaptés pour commettre les infractions prévues par la présente section est puni des peines prévues respectivement pour ces infractions.*

- Covers possession or distribution of hacking tools, penalized at the same level as the intended offense.

#### Article 323-6, Penalties for Legal Entities

> *Les personnes morales déclarées pénalement responsables (...) sont punies d'une amende (...) et des peines prévues à l'article 131-39.*

- Companies can be held criminally liable with fines up to 5× the individual amounts.

#### Article 323-7, Disqualification

> *Les personnes physiques encourent également les peines complémentaires d'interdiction, pour une durée de cinq ans au plus, d'exercer une fonction publique ou d'exercer l'activité professionnelle ou sociale à l'occasion de laquelle l'infraction a été commise.*

- **Up to 5-year ban** from practicing the profession in which the offense was committed.

### 3.3 Practical Implications for Auditors

1. **Written consent is mandatory, but not sufficient**, the consent must be specific, informed, and narrowly scoped.
2. **Do not access a system before the consent period begins** or after it ends.
3. **Do not modify any data** unless explicitly authorized and documented (e.g., creating a test user with a password you control, then deleting it).
4. **Do not exfiltrate data** without a clearly defined and agreed-upon purpose.
5. **Keep detailed logs of all actions** taken during the audit to demonstrate good faith and compliance with scope.
6. **French law applies even if the auditor is outside France**, the offense occurs where the system is located (territoriality principle).

### 3.4 Lawful Justification

The only lawful justification for security testing under French law is **consent** from the system owner. The elements for valid consent are:

- **Free**: No coercion or pressure.
- **Specific**: Exact scope, methods, dates.
- **Informed**: Client understands what will happen.
- **Unambiguous**: Clear affirmative action (signature).
- **Revocable**: Client can withdraw at any time.

> **Note**: There is no "security researcher exception" in French law comparable to the US DMCA exemptions. Good faith is not a defense.

---

## 4. Responsible Disclosure Policy Template

### 4.1 Policy Statement

Use the following template as the basis for your responsible disclosure commitments. Modify as needed for your practice.

---

```
# Responsible Disclosure Policy

## Commitment
[Your Company/Your Name] is committed to the responsible disclosure of security
vulnerabilities discovered during WordPress security audits. We believe that
coordinated disclosure protects users, builds trust, and improves security for
everyone.

## Disclosure Process

### 1. Internal Notification
As soon as a vulnerability is confirmed during an audit, we notify the client
within 24 hours via the agreed emergency contact. A preliminary risk assessment
(severity, impacted systems, potential exploitation vectors) accompanies this
notification.

### 2. Client Remediation Period
We grant the client a remediation period appropriate to the severity of the
vulnerability:

| Severity       | Remediation Period |
|----------------|--------------------|
| Critical       | 48 hours           |
| High           | 7 days             |
| Medium         | 30 days            |
| Low            | 90 days            |

The remediation period begins when the client acknowledges receipt of the
preliminary finding. If the client requests an extension, we evaluate on a
case-by-case basis.

### 3. Verification
After the client reports that a fix has been applied, we re-test the
vulnerability (within the original audit scope) to confirm remediation.

### 4. Public Disclosure (if applicable)

We will NOT publicly disclose a vulnerability without the client's written
consent, UNLESS:

a) The client fails to remediate within the agreed period AND fails to
   request/obtain an extension, AND
b) The vulnerability poses a credible risk to third parties (e.g., a widely
   used plugin or theme), AND
c) We have made at least three good-faith attempts to contact the client
   over a 30-day period.

When public disclosure is necessary, we will:

- Publish only enough technical detail for defenders to assess risk.
- Withhold proof-of-concept code that would enable exploitation.
- Credit the client if they wish.
- Coordinate disclosure with the WordPress plugin/theme maintainers if
  applicable.

### 5. Communication
All disclosure-related communication must be:
- Encrypted (GPG-encrypted email preferred)
- Directed to the client's authorized security contact
- Documented and retained per our Data Handling Policy (Section 6)

## Exceptions
We will NOT disclose vulnerabilities that:
- The client is actively remediating within the agreed period.
- The client has demonstrated a good-faith effort to fix but needs additional
  time.
- The vulnerability has been reported to us by a third party who wishes to
  remain anonymous.

## Safe Harbor
[Your Company/Your Name] will not take legal action against clients for
sharing our vulnerability findings within their own organization for the
purpose of remediation. We expect the same in return when we act in good
faith and within the scope of the signed consent form.

---

*Version 1.0, Last updated: [Date]*
```

### 4.2 Key Principles of Responsible Disclosure

| Principle | Description |
|-----------|-------------|
| **Coordinated** | Work *with* the client, not against them |
| **Timely** | Notify immediately for critical/high; allow reasonable remediation |
| **Minimal** | Disclose only what is necessary for remediation |
| **Documented** | Every step of the disclosure process is recorded |
| **Good faith** | Act in the interest of security, not publicity or profit |

### 4.3 When NOT to Disclose Publicly

- The client remediates within the agreed period.
- The vulnerability is in a client-specific custom plugin (not shared code).
- Disclosure would expose the client to legal liability beyond the vulnerability itself.
- The client specifically contracts for non-disclosure (NDA in place).

---

## 5. Limitation of Liability, Disclaimer

### 5.1 Sample Disclaimer for Audit Reports

Include the following disclaimer in every audit report and proposal:

---

```
## Disclaimer & Limitation of Liability

### No Guarantee of Complete Security
[Your Company/Your Name] ("Auditor") has performed a security assessment of
the WordPress site(s) identified in this report using industry-standard
tools and methodologies. However:

- **No security assessment can identify all vulnerabilities.** New
  vulnerabilities are discovered daily, and this assessment reflects only
  the state of the target at the time of testing.
- **Tool limitations**: Automated scanners may produce false positives or
  miss vulnerabilities that a manual tester would identify, and vice versa.
- **Evolving threat landscape**: Vulnerabilities, exploits, and attack
  vectors that did not exist at the time of testing may emerge afterward.

### Scope Limitation
This assessment is limited to the scope defined in the signed Consent Form
and Scope Document. Systems, applications, and networks outside that scope
were not tested and may contain vulnerabilities.

### No Liability for Operational Impact
The Auditor has taken reasonable precautions to avoid disrupting the
Client's operations. However, the Auditor shall not be liable for:

a) Downtime or service interruptions resulting from testing activities,
   including but not limited to rate limiting, WAF blocks, or server
   resource exhaustion caused by scan traffic.
b) Data loss or corruption, except where caused by the Auditor's gross
   negligence or willful misconduct.
c) Third-party actions taken based on this report.

### Limitation of Damages
To the maximum extent permitted by applicable law, the Auditor's total
liability arising out of or related to this assessment shall not exceed
the total fees paid by the Client for this specific engagement. In no
event shall the Auditor be liable for consequential, indirect, incidental,
or special damages.

### Client Responsibility
The Client acknowledges that:

1. Remediation of identified vulnerabilities is the Client's
   responsibility.
2. The Client retains full control over their systems at all times.
3. The Client should retain backups and verify system integrity after any
   remediation actions.
4. The Client is responsible for compliance with applicable laws and
   regulations (GDPR, French Code Pénal, etc.) regarding the findings
   in this report.

### Indemnification
The Client agrees to indemnify and hold harmless the Auditor from and
against any claims, damages, or losses arising from:

- The Client's failure to remediate identified vulnerabilities.
- The Client's use of the report for purposes not intended by the Auditor.
- Third-party claims related to the Client's systems that pre-date or are
  unrelated to the Auditor's assessment.

### Governing Law
This agreement and any disputes arising from it shall be governed by the
laws of [Jurisdiction, e.g., France], without regard to its conflict of
law provisions.

---

*This disclaimer is incorporated by reference into the audit engagement
contract and the signed consent form.*
```

### 5.2 When Liability Protection May Fail

Liability disclaimers are not a substitute for good practice. They may be rendered invalid if:

- The auditor acts with **gross negligence or willful misconduct**.
- The disclaimer is found to be **unconscionable or contrary to public policy**.
- The auditor **exceeds the agreed scope** without authorization.
- The auditor **modifies data, exfiltrates data, or causes damage** without explicit permission.
- The auditor **fails to maintain professional liability insurance** as contractually represented.

---

## 6. Data Handling Policy

### 6.1 What We Store

During a WordPress security audit, the following data categories may be stored:

| Category | Examples | Storage Required? |
|----------|----------|-------------------|
| Client identification | Name, company, email, phone, billing address | Yes, contractual |
| Target system metadata | URLs, IPs, server headers, CMS version | Yes, audit results |
| Scan artifacts | Raw tool output, screenshots, logs | Yes, evidence (temporary) |
| Vulnerability evidence | Payload examples, request/response pairs | Yes, report support |
| Personal data (incidental) | User emails in DB dumps, visitor IPs in logs | Minimized, temporary |
| Client system credentials | SSH keys, API tokens, admin passwords | Never stored in plaintext |
| Payment information | Credit card details | Never stored, processed via PCI-compliant processor |

### 6.2 How Long We Store Data

See [Section 2.3, Data Retention Policy](#23-data-retention-policy-for-scan-artifacts) for the full retention schedule.

Summary:
- **Raw scan data**: 90 days
- **Final report**: 2 years (or per contract)
- **Client PII**: Duration of relationship + 3 years
- **High-sensitivity artifacts** (passwords, tokens, cookies): Deleted immediately after use

### 6.3 Who Has Access

| Role | Access Level | Rationale |
|------|-------------|-----------|
| Lead Auditor | Full access to all data | Required to perform and document the audit |
| Auditor (team member) | Full access for assigned engagement | Required for testing and reporting |
| Administrator (technical) | Infrastructure access only (no report content) | Server maintenance, backups |
| Client | Only their own audit data | Contractual right |
| Third-party subcontractors | None, unless explicitly authorized by client | Requires addendum to consent form |
| Insurance auditor (audit of us) | Access to file metadata, not scan content | Proof of professional practice |
| Law enforcement | Only with valid legal process (warrant, subpoena) | Legal obligation |

### 6.4 Data Storage Security

All stored data is protected by:

1. **Encryption at rest**: AES-256 for stored scan artifacts and reports.
2. **Encryption in transit**: TLS 1.3 for all data transfers.
3. **Access controls**: Role-based access with individual credentials; no shared accounts.
4. **Audit logging**: All access to scan data is logged (who, when, what).
5. **Physical security**: Servers in SSAE-16/SOC-2-compliant data centers.
6. **Backup encryption**: Backups are encrypted with the same standards.
7. **Secure deletion**: Data is wiped using approved methods (DoD 5220.22-M for SSDs, degaussing for HDDs).

### 6.5 Data Breach Notification

In the event of a data breach involving client scan data or personal data:

1. **Internal detection within 24 hours**, the breach must be identified.
2. **Client notification within 48 hours** of detection.
3. **Regulator notification** (CNIL or relevant DPA) within 72 hours, if GDPR applies.
4. **Remediation plan** provided within 7 days.
5. **Post-incident review** and process improvement within 30 days.

### 6.6 Data Processing Agreement (DPA)

> A full DPA should be executed between the auditor and client. The DPA template is outside the scope of this reference document but must include:
>
> - Subject matter and duration of processing
> - Nature and purpose of processing
> - Types of personal data processed
> - Categories of data subjects
> - Obligations and rights of the data controller (client)
> - Sub-processing authorization requirements
> - Technical and organizational security measures

---

## 7. Scope Definition

### 7.1 Why Scope Definition Matters

A poorly defined scope is the #1 source of legal exposure for security auditors. When scope is ambiguous:

- The auditor may inadvertently test systems they are not authorized to test.
- The client may claim the auditor "exceeded authority."
- Liability for any damage (even accidental) is harder to allocate.
- Criminal liability under French law increases if systems outside scope are accessed.

### 7.2 Scope Definition Checklist

| Parameter | What to Define | Example |
|-----------|---------------|---------|
| **Target URLs** | Exact URL patterns | `https://example.com`, `https://www.example.com`, NOT `*.example.com` |
| **Subdomains** | Explicit list | `blog.example.com`, `shop.example.com`, or state "all subdomains of example.com" |
| **IP ranges** | If applicable | `192.0.2.0/24` |
| **Environments** | Production / Staging / Dev | "Production only, staging and dev are excluded" |
| **Testing methods** | Allowed techniques | Automated scan only / Automated + manual / No credential testing / With credentials |
| **Testing intensity** | Rate limits, concurrency | "Max 10 requests/second per host" |
| **Excluded systems** | Explicitly named | "Payment processor (Stripe), CDN (Cloudflare), SMTP (SendGrid)" |
| **Excluded tests** | Prohibited test types | "No SQL injection, no DoS tests, no file upload tests" |
| **Testing window** | Date + time range | "2026-08-01 00:00 UTC to 2026-08-07 23:59 UTC" |
| **Emergency stop** | Who can halt tests | "Client can halt at any time via emergency contact" |
| **Post-audit actions** | What happens to test data | "All test accounts deleted, all test content removed within 48 hours" |

### 7.3 Sample Scope Definition Clause

```
## Scope of Work (SOW)

### In Scope
- Primary domain: https://client-example.com
- Subdomains: https://blog.client-example.com, https://shop.client-example.com
- Authentication: Auditor will be provided with an Administrator-level test
  account (created for this purpose only)
- Testing methods: Automated scanning (WPScan, Nikto, Nuclei) + manual
  verification
- Testing window: 2026-08-01 00:00 UTC to 2026-08-07 23:59 UTC

### Out of Scope
- Any system not listed above
- Third-party hosted services (payment gateways, analytics, email providers)
- Denial of Service (DoS) or Distributed Denial of Service (DDoS) testing
- Social engineering attacks (phishing, pretexting)
- Physical security assessment
- Source code review (unless separately contracted)
- Load or stress testing
- Production data modification

### Scope Change Procedure
Any request to expand the scope must be:
1. Made in writing by the Client
2. Acknowledged in writing by the Auditor
3. Documented as an addendum to this SOW

No scope expansion is effective until written confirmation is received
from both parties.
```

### 7.4 Common Scope Pitfalls

| Pitfall | Risk | Mitigation |
|---------|------|------------|
| "All subdomains" without enumeration | Wildcard DNS may lead to unintended targets | Enumerate subdomains first, then list explicitly |
| Including cloud assets without checking shared hosting | Testing a shared IP may hit other tenants | Use DNS names, not IPs; test via host header |
| Including third-party plugins | Testing a plugin on client site affects the plugin vendor's servers | Verify plugin vendor terms; test in isolated environment if needed |
| No time-bound scope | Testing continues indefinitely | Always set exact start/end dates |
| Verbal scope changes | "I said you could test that too" disputes | All scope changes in writing only |

---

## 8. Sample Consent Form (French)

### 8.1 Formulaire d'Autorisation de Test de Sécurité

Utilisez ce formulaire pour chaque engagement d'audit. Il doit être signé avant le début des tests.

---

```
**FORMULAIRE D'AUTORISATION DE TEST DE SÉCURITÉ**
**SÉCURITÉ WORDPRESS, AUTORISATION EXPRESSE**

---

**Entre les soussignés :**

**Le Client :**
Nom de l'entreprise : __________________________________________________
Nom du représentant légal : ____________________________________________
Fonction : _____________________________________________________________
Adresse : ______________________________________________________________
Email : _______________________________________________________________
Téléphone : ___________________________________________________________

**Et**

**L'Auditeur :**
Nom de l'entreprise / du prestataire : __________________________________
Nom de l'auditeur responsable : ________________________________________
Email : _______________________________________________________________
Téléphone : ___________________________________________________________

---

**Article 1, Objet**

Le présent formulaire a pour objet d'autoriser expressément et par écrit
l'Auditeur à réaliser des tests de sécurité sur le(s) site(s) WordPress
appartenant au Client, ci-après désigné(s) comme la ou les « Cible(s) ».

**Article 2, Cible(s) autorisée(s)**

Le Client autorise les tests sur les sites, URLs et systèmes suivants
(ci-après le « Périmètre Autorisé ») :

1. __________________________________________________________________
2. __________________________________________________________________
3. __________________________________________________________________

(Ajouter des lignes si nécessaire. Tout système non listé ci-dessus est
EXCLU du périmètre.)

**Article 3, Méthodes de test autorisées**

Cochez les cases applicables :

☐ Scan automatisé (outils de sécurité standard, WPScan, Nikto, Nuclei)
☐ Vérification manuelle des vulnérabilités identifiées
☐ Tests avec identifiants de connexion (compte administrateur fourni par le Client)
☐ Tests sans identification (test en utilisateur non connecté)
☐ Tests d'intrusion (exploitation contrôlée de vulnérabilités, SANS modification de données de production)

☐ AUTRE : _____________________________________________________________

Les méthodes suivantes sont EXCLUES (sauf accord écrit séparé) :
- Tests d'attaque par déni de service (DoS/DDoS)
- Ingénierie sociale (phishing, pretexting)
- Modification de données de production
- Extraction massive de données

**Article 4, Période d'autorisation**

Les tests sont autorisés du : ____/____/________ au : ____/____/________
Heure de début : ______________ (UTC)  Heure de fin : ______________ (UTC)

**Article 5, Contact d'urgence**

En cas d'incident pendant les tests, le Client désigne la personne suivante
comme contact d'urgence :

Nom : _______________________________________
Téléphone : _________________________________
Email : _____________________________________

L'Auditeur s'engage à contacter ce contact immédiatement en cas de :
- Découverte d'une vulnérabilité critique
- Impact opérationnel inattendu des tests
- Demande d'interruption des tests par le Client

**Article 6, Responsabilités**

Le Client déclare et garantit :
a) Qu'il est le propriétaire légitime ou l'exploitant autorisé de la/des
   Cible(s) listée(s) à l'Article 2.
b) Qu'il a obtenu toutes les autorisations nécessaires des tiers
   (hébergeur, prestataires techniques) pour la réalisation des tests.
c) Qu'il a sauvegardé l'intégralité des données de la/des Cible(s) avant
   le début des tests.

L'Auditeur s'engage à :
a) Limiter ses actions au Périmètre Autorisé et aux méthodes autorisées.
b) Ne pas consulter, copier, modifier ou supprimer de données de production
   sauf autorisation expresse et écrite.
c) Ne pas divulguer les informations découvertes à des tiers, sauf dans le
   cadre du rapport d'audit remis au Client ou si requis par la loi.
d) Détruire ou restituer toutes les données collectées dans les délais
   prévus au contrat.

**Article 7, Loi applicable**

Le présent formulaire est régi par le droit français. Tout litige relèvera
de la compétence des tribunaux français.

**Article 8, Révocation**

Le Client peut révoquer la présente autorisation à tout moment par
notification écrite (email suffit). En cas de révocation, l'Auditeur
cessera immédiatement les tests et détruira les données collectées dans
un délai de 72 heures.

---

**Fait à :** ___________________________ **Le :** ____/____/________

**Pour le Client :**
Nom : __________________________________
Signature : ____________________________
_(Précédée de la mention « Lu et approuvé, Bon pour autorisation de test »)_

**Pour l'Auditeur :**
Nom : __________________________________
Signature : ____________________________

---

*Document à conserver pendant toute la durée de la relation contractuelle
et 3 ans après la fin de celle-ci, conformément à la politique de
conservation des données.*
```

### 8.2 Instructions d'Utilisation

1. **Remplir toutes les sections**, ne laissez pas de blancs. Si une section ne s'applique pas, barrez-la ou écrivez "N/A".
2. **Signature obligatoire**, une signature électronique (DocuSign, Yousign) est acceptable si elle permet l'identification du signataire.
3. **Remettre au Client avant les tests**, le Client doit recevoir le formulaire au moins 48h avant le début des tests pour révision.
4. **Conserver le document original**, pendant toute la durée de la relation contractuelle + 3 ans.
5. **Envoyer une copie au Client**, pour ses propres dossiers.

### 8.3 Checklist Pré-Test (Français)

Avant de lancer le premier scan, vérifiez :

- [ ] Formulaire d'autorisation signé et daté
- [ ] Périmètre clairement défini et accepté
- [ ] Contact d'urgence confirmé
- [ ] Client informé des horaires précis de test
- [ ] Client a confirmé que les sauvegardes sont à jour
- [ ] Client informé des risques résiduels (possible blocage temporaire par le WAF, saturation de logs)
- [ ] Accès VPN ou identifiants reçus (si nécessaire)
- [ ] Assurance responsabilité professionnelle vérifiée (à jour, couverture suffisante)

---

## 9. Ethical Boundaries

### 9.1 Core Ethical Principles

Every WordPress security audit must be governed by the following inviolable ethical principles:

| # | Principle | Description |
|---|-----------|-------------|
| 1 | **Do no harm** | The audit must not cause unnecessary damage to the client's systems, data, or reputation |
| 2 | **Stay in scope** | Never test beyond what was agreed in writing |
| 3 | **Minimize access** | Access only what is necessary to confirm a vulnerability |
| 4 | **Protect data** | Treat all client data as confidential, even data you weren't "supposed" to find |
| 5 | **Be transparent** | Document what you did, what you found, and what you accessed |
| 6 | **Stay competent** | Do not perform tests you are not qualified to perform safely |
| 7 | **Put security first** | If you find a critical vulnerability during a non-critical test, report it immediately |

### 9.2 Absolute Prohibitions

The following actions are **never** permitted, regardless of what the consent form says, unless explicitly, narrowly, and separately authorized in writing:

#### ❌ No Data Exfiltration

- **Do not** download database dumps, user lists, or full site backups unless this is explicitly part of the agreed methodology.
- **Do not** copy production data to your local machine "for analysis", analyze in place where possible.
- **If you must capture** specific data as evidence (e.g., a screenshot of exposed API keys), minimize the data captured and delete it as soon as it is documented.

#### ❌ No Denial of Service Without Explicit Permission

- **Do not** run any test that could degrade or interrupt system availability.
- **Avoid** aggressive scan settings (high concurrency, low timeouts).
- **If DoS testing is required** (e.g., rate limiting assessment), it must be:
  1. Explicitly listed in scope.
  2. Performed against a **staging environment** whenever possible.
  3. Time-boxed to specific, short windows.
  4. Monitored in real-time by the client.

#### ❌ No Production Data Modification

- **Do not** create, modify, or delete any content on a production site, including:
  - User accounts
  - Posts, pages, or media
  - Plugin/theme settings
  - Database records
  - Configuration files
- **Exception**: Creating a dedicated, isolated test user account with a strong, unique password may be permitted if:
  1. Explicitly authorized in writing.
  2. The account is deleted immediately after testing.
  3. The account has the minimum privileges necessary.

#### ❌ No Privilege Escalation Without Permission

- **Do not** attempt to escalate from test account to administrator unless explicitly authorized.
- **Do not** use found credentials to access systems outside the authorized scope.

#### ❌ No Installation of Backdoors or Persistent Access

- **Never** install webshells, backdoors, or any form of persistent access, even temporarily.
- **Never** leave test files, scripts, or configurations on the target system.

### 9.3 Gray Areas, Require Explicit Clarification

| Scenario | Guidance |
|----------|----------|
| Exploiting SQLi to prove impact | Use `SELECT SLEEP(1)` for time-based, or `SELECT 1` for UNION-based. **Do not** use `INTO OUTFILE` or `LOAD_FILE`. |
| Uploading a test file | Only if scope explicitly allows file upload testing. Use a benign `.txt` file with a clear name. Delete immediately. |
| Using client credentials for authenticated scanning | Only if account was created for testing or client explicitly provides a dedicated account. Never use admin's personal account. |
| Testing a live e-commerce site | Clone to staging first. If staging is not available, test only read-only methods, avoid checkout/payment flows entirely. |
| Scanning from a cloud VPS | Ensure the VPS IP is not blacklisted/firewalled by the client before scanning. Use a dedicated IP per client. |

### 9.4 Decision Tree: "Should I Do This?"

```
Is the action in scope?
├── YES → Is it explicitly authorized?
│   ├── YES → Does it modify production data?
│   │   ├── YES → ❌ STOP. Get separate written authorization.
│   │   └── NO → Does it risk availability?
│   │       ├── YES → ❌ STOP. Ensure risk is communicated and authorized.
│   │       └── NO → ✅ Proceed with caution. Document everything.
│   └── NO → Could it be considered implicit?
│       ├── YES → ❌ STOP. Get explicit authorization. Nothing is "implicit."
│       └── NO → ❌ STOP. Out of scope.
└── NO → ❌ STOP. Out of scope. Do not proceed.
```

---

## 10. Insurance Considerations

### 10.1 Why Insurance Matters

Professional liability insurance (often called "Errors and Omissions" or E&O insurance for cyber services) protects both the auditor and the client. Without it:

- A single claim could bankrupt a small practice.
- Clients may refuse to engage an uninsured auditor.
- The auditor may be personally liable for damages caused by their testing.

### 10.2 Types of Insurance for Cyber Audit Services

| Type | What It Covers | Recommended Minimum |
|------|----------------|---------------------|
| **Professional Liability (E&O)** | Claims of negligence, failure to detect vulnerabilities, errors in reports | €1,000,000 per claim |
| **Cyber Liability** | Data breach response, notification costs, regulatory fines, data restoration | €1,000,000 per claim |
| **General Liability** | Bodily injury or property damage (less relevant for remote audits, but often required for office/onsite) | €500,000 |
| **Errors & Omissions + Cyber combined** | Many insurers offer a combined policy for tech professionals | €1,000,000–€2,000,000 |
| **Umbrella/Excess** | Additional coverage above primary policy limits | €1,000,000+ |

### 10.3 Coverage Checklist

When purchasing or renewing insurance, verify your policy covers:

- [ ] **Penetration testing and vulnerability assessment**, explicitly named as a covered activity.
- [ ] **Both automated and manual testing**, some policies exclude "hacking tools."
- [ ] **Third-party claims**, claims made by your client's clients or partners.
- [ ] **Regulatory defense costs**, GDPR, CNIL, or other data protection authority investigations.
- [ ] **Breach response costs**, notification, credit monitoring, PR.
- [ ] **Business interruption**, if your testing accidentally causes downtime.
- [ ] **Worldwide coverage**, if you audit international clients.
- [ ] **Subcontractor coverage**, if you engage other auditors.
- [ ] **Prior acts coverage**, covers claims arising from work done before the policy was in force (if switching insurers).
- [ ] **No "hacking" exclusion**, some policies exclude unauthorized computer access *unless* performed under written contract. Read the fine print.

### 10.4 What Insurance Typically EXCLUDES

| Exclusion | Implication |
|-----------|-------------|
| **Intentional illegal acts** | If you exceed scope and access systems without authorization, your insurance won't cover the resulting claims. |
| **Criminal fines** | No insurance covers fines imposed by criminal courts (Article 323-1 fines, for example). |
| **Punitive damages** | Many jurisdictions don't allow insurance for punitive damages (they are meant to punish, not compensate). |
| **Known prior vulnerabilities** | If you knew about a vulnerability before testing and failed to remediate it, claims arising from it may be excluded. |
| **War/cyberwar** | State-sponsored attacks or actions during armed conflict. |

### 10.5 Questions to Ask Your Insurer

1. Does my policy explicitly cover "penetration testing" and "vulnerability assessment" as described activities?
2. Are automated security scanning tools covered, or is there a "hacking tools" exclusion?
3. Does the policy cover regulatory investigations (CNIL, GDPR authorities)?
4. Is there a sub-limit for breach response costs?
5. Does the policy require me to notify the insurer before accepting a high-risk engagement?
6. Are subcontractors covered, or do they need their own policy?
7. Does the policy cover me if I accidentally cause a production outage?
8. What is the retroactive date? (Coverage may not apply to work done before this date.)
9. Is coverage "claims-made" or "occurrence-based"? (Most professional liability is claims-made.)
10. What are the policy's exclusions for "unauthorized access", and does a valid consent form satisfy them?

### 10.6 Client Communication About Insurance

Include this in your engagement letter or proposal:

```
## Insurance Disclosure

[Your Company/Your Name] maintains the following insurance coverage:

- Professional Liability (Errors & Omissions): €[amount] per claim / €[amount] aggregate
- Cyber Liability: €[amount] per claim / €[amount] aggregate
- General Liability: €[amount] per occurrence

A certificate of insurance is available upon request. Coverage is provided by
[Insurer Name], policy number [XXXXXX], effective [date] through [date].

This insurance covers the professional security assessment services described
in this engagement. It does NOT cover:
- Criminal fines or penalties
- Damage resulting from actions outside the agreed scope
- Pre-existing vulnerabilities unknown to either party
```

### 10.7 Insurance for French-Based Auditors

French auditors should also consider:

- **Assurance Responsabilité Civile Professionnelle (RC Pro)**, mandatory for many regulated professions; strongly recommended for security auditors.
- **Assurance Responsabilité Civile Exploitation**, covers premises liability (if clients visit your office).
- **Assurance Protection Juridique**, legal defense costs for disputes.
- **Cyber-risques assurance**, increasingly available from French insurers (AXA, Groupama, Generali, Hiscox France).

> **French tax note**: Insurance premiums for professional liability are generally tax-deductible as business expenses. Consult your accountant.

---

## Appendices

### Appendix A: Pre-Engagement Checklist

- [ ] Client identity verified (company registration, legal representative)
- [ ] Signed consent form (French or English, per client preference)
- [ ] Scope document finalized and signed
- [ ] Emergency contact confirmed and tested
- [ ] Client confirms backups exist and are verified
- [ ] Testing window agreed and communicated
- [ ] Insurance certificate shared with client (or available on request)
- [ ] DPA signed (if GDPR applies)
- [ ] NDA signed (if required)
- [ ] Data retention schedule communicated to client
- [ ] Client aware of responsible disclosure policy
- [ ] Audit tools updated and tested in isolated environment

### Appendix B: Post-Engagement Checklist

- [ ] All test data purged per retention policy (or returned to client)
- [ ] All test accounts deleted from client systems
- [ ] All test files/scripts removed from client systems
- [ ] Report delivered (encrypted, per client preference)
- [ ] Client acknowledged receipt of report
- [ ] Responsible disclosure timeline initiated (if applicable)
- [ ] Consent form archived per retention policy
- [ ] Insurance carrier notified of engagement completion (if required)

### Appendix C: Key Legal References

| Reference | Description |
|-----------|-------------|
| Code Pénal, Articles 323-1 à 323-7 | Loi Godfrain, Accès frauduleux aux STAD |
| GDPR, Regulation (EU) 2016/679 | Protection des données personnelles |
| Loi n° 78-17 du 6 janvier 1978 | Loi Informatique et Libertés (France) |
| CNIL, Guide de la sécurité des données | Recommandations CNIL pour les audits |
| ANSSI, Guide d'audit de sécurité | Méthodologie ANSSI |
| ENISA, Vulnerability Disclosure | European guidelines on coordinated disclosure |
| OWASP, Testing Guide | Industry standard for web app testing methodology |

---

> **Document History**
>
> | Version | Date | Author | Changes |
> |---------|------|--------|---------|
> | 1.0 | 2026-07-16 | [Your Name] | Initial creation |
>
> **Review and update**: This document should be reviewed annually and after any significant change in applicable law (GDPR updates, Code Pénal amendments, insurance market changes).
>
> ---
>
> *End of Document, Proceed with audit only after legal and ethical framework is acknowledged by all parties.*
