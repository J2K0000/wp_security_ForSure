# WordPress Vulnerability Prioritization Model

> **Converts raw security findings into client-ready priorities**
> Revision: 1.0 | Classification: Internal Methodology

---

## Table of Contents

1. [Scoring Factors](#1-scoring-factors)
2. [Weighted Formula](#2-weighted-formula)
3. [Priority Levels & SLAs](#3-priority-levels--slas)
4. [Example Scoring for Common Findings](#4-example-scoring-for-common-findings)
5. [Client Presentation, Executive Summary](#5-client-presentation--executive-summary)
6. [Overall Site Risk Score](#6-overall-site-risk-score)
7. [Implementation Script (Python)](#7-implementation-script-python)
8. [Implementation Script (Bash)](#8-implementation-script-bash)

---

## 1. Scoring Factors

Each finding is scored across **6 weighted dimensions**. The combination produces a final **Prioritization Score (P)** between 0 and 10.

### 1.1 CVSS Base Score (NVD)

The industry-standard vulnerability severity rating from the National Vulnerability Database (NVD), calculated per CVSS v3.1.

| CVSS Range | Label | Factor Value |
|---|---|---|
| 0.0 | None | 0 |
| 0.1–3.9 | Low | 1 |
| 4.0–6.9 | Medium | 3 |
| 7.0–8.9 | High | 6 |
| 9.0–10.0 | Critical | 10 |

> **Note:** Many WordPress-specific findings (exposed debug.log, nulled plugins) do not have a CVE. In those cases, use the **Projected CVSS** column in the finding template.

### 1.2 EPSS Score (Exploit Prediction Scoring System)

Provided by [FIRST.org](https://www.first.org/epss/api). Represents the **probability that a CVE will be exploited in the wild** within the next 30 days.

| EPSS Probability | Percentile (approx.) | Factor Value |
|---|---|---|
| < 0.001 (0.1%) | Bottom 50% | 0 |
| 0.001 – 0.01 (0.1%–1%) | 50th–80th | 1 |
| 0.01 – 0.10 (1%–10%) | 80th–95th | 3 |
| 0.10 – 0.50 (10%–50%) | 95th–99th | 6 |
| > 0.50 (50%+) | Top 1% | 10 |

> **API query:** `curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-XXXXX" | jq '.data[0].epss'`

### 1.3 Exploit Availability

Measures whether a working exploit exists and how accessible it is.

| Level | Description | Factor Value |
|---|---|---|
| None | No known exploit | 0 |
| Proof of Concept | Academic or theoretical PoC, limited disclosure | 2 |
| Private Exploit | Weaponised exploit exists but not public (dark web, closed channels) | 5 |
| Public PoC | Public PoC available (GitHub, Exploit-DB, Metasploit) | 7 |
| Weaponised / Wormable | Mass-exploitable (botnets, automated scanners, active campaigns) | 10 |

### 1.4 Business Impact

WordPress-specific business consequences. This is the **client-facing** weight, what matters to their bottom line.

| Impact Type | Severity | Factor Value |
|---|---|---|
| **SEO Blacklist**, Google flags site as compromised, search traffic drops to 0 | Catastrophic | 10 |
| **Data Loss**, Customer PII, payment data, credentials exfiltrated | Catastrophic | 10 |
| **Compliance Violation**, GDPR/CNIL/RGPD fine risk, breach notification required | High | 8 |
| **Reputation Damage**, Defacement, spam distribution, brand damage | High | 7 |
| **Financial Loss**, E-commerce cart abandonment, ad revenue loss | Medium | 5 |
| **Operational Disruption**, Site inaccessible, admin lockout | Medium | 4 |
| **Functional Degradation**, Reduced performance, broken features | Low | 2 |
| **Informational Only**, No direct business impact | Negligible | 0 |

Select the **highest applicable** impact. If multiple impacts apply, use the top one.

### 1.5 Remediation Difficulty

How hard and risky the fix is. This tempers the priority, a critical vulnerability that takes 30 minutes to patch escalates; one requiring a full rebuild might shift toward medium-term planning.

| Difficulty | Description | Factor Weight (divisor) |
|---|---|---|
| Trivial | Toggle a setting, delete a file, update a plugin, 5 min | 1.0 |
| Easy | One-click update, configuration change, 15 min | 0.9 |
| Moderate | Plugin replacement, theme switch, 1–2 hours | 0.7 |
| Complex | Core upgrade with compatibility testing, server config change, 4–8 hours | 0.5 |
| Very Complex | Full migration, architecture change, multi-team coordination, days | 0.3 |

The factor **divides** (not multiplies) the raw score, easy fixes are prioritized higher, hard fixes are tempered.

### 1.6 Asset Criticality

What part of the site the finding affects.

| Asset Type | Weight |
|---|---|
| E-commerce / payment pages | 1.5 |
| Login / admin / wp-admin | 1.3 |
| Customer account area (dashboard, orders) | 1.2 |
| Public-facing content pages | 1.0 |
| Staging / dev / non-production | 0.5 |

---

## 2. Weighted Formula

### 2.1 Finding Priority Score (P)

```
P = ( (CVSS × 0.30) + (EPSS × 0.15) + (EXPLOIT × 0.25) + (IMPACT × 0.20) ) × DIFFICULTY × CRITICALITY

Where:
  CVSS     = factor value from CVSS table (0–10)
  EPSS     = factor value from EPSS table (0–10)
  EXPLOIT  = factor value from exploit availability table (0–10)
  IMPACT   = factor value from business impact table (0–10)
  DIFFICULTY = remediation difficulty divisor (0.3–1.0)
  CRITICALITY = asset criticality multiplier (0.5–1.5)
```

**Weights rationale:**
- **CVSS (30%)**, Ground truth for known CVEs, but incomplete for WordPress-specific findings
- **Exploit Availability (25%)**, Strongest predictor of actual risk; a PoC doubles urgency
- **Business Impact (20%)**, Client-centric; SEO blacklist and data loss overrule technical severity
- **EPSS (15%)**, Probabilistic signal for CVEs; lower weight because not all findings have a CVE
- Remediation Difficulty (10% implicit via divisor), Tempering factor, not primary driver

### 2.2 Priority Level Mapping

| P Score Range | Priority | SLA | Color |
|---|---|---|---|
| 7.0 – 10.0 | **Critical** | Fix within 24 hours | 🔴 Red |
| 4.5 – 6.9 | **High** | Fix within 72 hours | 🟠 Orange |
| 2.0 – 4.4 | **Medium** | Fix within 2 weeks | 🟡 Yellow |
| 0.5 – 1.9 | **Low** | Monitor and re-assess quarterly | 🔵 Blue |
| < 0.5 | **Info** | Documented for awareness only | ⚪ Grey |

### 2.3 Tiebreaker Rules

When two findings have identical P scores:

1. Higher exploit availability wins (weaponised > PoC > none)
2. Higher business impact wins (data loss > reputation > operational)
3. Easier remediation wins (trivial > complex)
4. If still tied: oldest finding first (FIFO)

---

## 3. Priority Levels & SLAs

### Critical, 🔴 Fix within 24 hours

**Characteristics:**
- Remote code execution (RCE) or SQL injection with public exploit
- Active exploitation in the wild (EPSS > 0.10 or CISA KEV listed)
- Data breach confirmed or imminent (PII exposure, credential dump)
- Site blacklisted by Google Safe Browsing
- Compromised admin access (backdoor, nulled plugin with C2)
- Compliance deadline already breached

**Client communication:** Phone call + email within 2 hours of detection.

### High, 🟠 Fix within 72 hours

**Characteristics:**
- Authenticated RCE or privilege escalation with PoC
- Sensitive data exposure (debug.log, wp-config backup readable)
- Vulnerable plugin/theme with known exploit (no active campaign)
- XSS with session hijacking potential on admin pages
- Outdated core software with known vulnerabilities

**Client communication:** Email with criticality banner + Slack/WhatsApp.

### Medium, 🟡 Fix within 2 weeks

**Characteristics:**
- Unauthenticated reflected XSS (low-value target)
- Missing security headers (X-Frame-Options, Content-Type)
- Weak password policy or exposed user enumeration
- Outdated plugin with no known exploit
- Missing SSL/TLS configuration issues
- Directory listing enabled on non-sensitive directories

**Client communication:** Included in weekly report digest.

### Low, 🔵 Monitor quarterly

**Characteristics:**
- Missing HSTS header (no active threat)
- Readme.html readable (information disclosure, low risk)
- Exposed wp-json user routes (partial info leak)
- PHP version outdated but site functional
- MySQL version slightly behind
- Recommended but non-critical hardening gaps

**Client communication:** Noted in quarterly review only.

### Info, ⚪ Documented for awareness

**Characteristics:**
- Best-practice recommendations (CDN, image optimization alongside security)
- Deprecated PHP functions warning
- Coding standard violations (no direct security impact)
- Future-proofing recommendations (PHP 8.x readiness)

**Client communication:** Appendix in full report, no action item.

---

## 4. Example Scoring for Common Findings

Below are worked examples using the model. Each finding is scored end-to-end.

### 4.1 Exposed `debug.log` (WordPress Debug Log)

| Factor | Value | Detail |
|---|---|---|
| CVSS | 5.9 (Medium) → factor: 3 | Information disclosure via debug log (CWE-532) |
| EPSS | N/A (no CVE for general debug log exposure) → 0 | n/a |
| Exploit | Public PoC → 7 | Automated scanners (WPScan, Nuclei) detect this trivially |
| Impact | SEO Blacklist possible (8) + Data Loss (10) → **10** | Logs may contain API keys, session tokens, emails |
| Difficulty | Trivial → 1.0 | Delete file or disable WP_DEBUG in wp-config.php |
| Criticality | Public → 1.0 | Affects entire site |
| **P Score** | **(3×0.30 + 0×0.15 + 7×0.25 + 10×0.20) × 1.0 × 1.0** = **(0.9 + 0 + 1.75 + 2.0) × 1.0** = **4.65** | |
| **Priority** | **🟠 High** | |

**Rationale:** P score 4.65 sits in High range. Impact weight (10) and exploit availability (7) drive the score. Even without a CVE, the business risk of exposed credentials makes this a 72h fix. If the log contains actual credentials found during audit, escalate to **Critical**.

### 4.2 Outdated PHP Version (e.g. PHP 7.4, End-of-Life)

| Factor | Value | Detail |
|---|---|---|
| CVSS | 8.8 (High) → factor: 6 | Multiple CVEs in EOL PHP (average severity) |
| EPSS | 0.15 (15th percentile) → 6 | Active exploits for PHP 7.4 RCEs |
| Exploit | Weaponised → 10 | Mass-scanning for EOL PHP versions; Metasploit modules exist |
| Impact | Compliance + Reputation → 8 | PCI DSS non-compliance; reputational if breached |
| Difficulty | Moderate → 0.7 | PHP upgrade may need compatibility testing |
| Criticality | Public → 1.0 | Entire site affected |
| **P Score** | **(6×0.30 + 6×0.15 + 10×0.25 + 8×0.20) × 0.7 × 1.0** = **(1.8 + 0.9 + 2.5 + 1.6) × 0.7** = **6.8 × 0.7** = **4.76** | |
| **Priority** | **🟠 High** (borderline Critical) | |

**Rationale:** Raw score of 6.8 would be Critical, but remediation difficulty (0.7) tempers to 4.76. **If the site runs an e-commerce platform** with payment data (Criticality 1.5), adjusted P = 5.88 × 1.5 / 0.7 = **7.14 → 🔴 Critical**. EOL PHP on a storefront = Critical.

### 4.3 Missing HSTS Header

| Factor | Value | Detail |
|---|---|---|
| CVSS | 3.7 (Low) → factor: 1 | CWE-319: Cleartext transmission |
| EPSS | N/A → 0 | n/a |
| Exploit | None → 0 | Requires MITM; no automated exploit chain |
| Impact | Operational/Func. → 2 | SSL stripping possible but unlikely |
| Difficulty | Trivial → 1.0 | Add header in .htaccess or server config |
| Criticality | Public → 1.0 | n/a |
| **P Score** | **(1×0.30 + 0×0.15 + 0×0.25 + 2×0.20) × 1.0 × 1.0** = **(0.3 + 0 + 0 + 0.4) × 1.0** = **0.70** | |
| **Priority** | **🔵 Low** | |

**Rationale:** Low CVSS, no exploit, minimal business impact. Monitor quarterly unless combined with other SSL/TLS issues.

### 4.4 Nulled / Pirated Elementor Pro

| Factor | Value | Detail |
|---|---|---|
| CVSS | 9.8 (Critical, projected) → factor: 10 | Known backdoors in nulled plugins; arbitrary code execution |
| EPSS | 0.35 (top 1%) → 6 | Active botnet scanning for nulled plugin shells |
| Exploit | Weaponised → 10 | Automated mass-exploitation, C2 callbacks |
| Impact | Data Loss + SEO Blacklist → 10 | Complete site compromise, cryptominers, SEO spam |
| Difficulty | Moderate → 0.7 | Replace plugin with legitimate license, clean up infections |
| Criticality | Public → 1.0 | n/a |
| **P Score** | **(10×0.30 + 6×0.15 + 10×0.25 + 10×0.20) × 0.7 × 1.0** = **(3.0 + 0.9 + 2.5 + 2.0) × 0.7** = **8.4 × 0.7** = **5.88** | |
| **Priority** | **🔴 Critical** (see escalation) | |

**Escalation rule:** Any finding involving **intentional malicious code** (nulled plugins, backdoors, webshells) is automatically **Critical regardless of P score**. The P score is recorded for reporting; the finding is escalated to the highest SLA. This is a **mandatory override**.

### 4.5 `readme.html` Readable

| Factor | Value | Detail |
|---|---|---|
| CVSS | 2.1 (Low, CVE not required) → factor: 1 | Information disclosure (WordPress version leak) |
| EPSS | N/A → 0 | n/a |
| Exploit | Proof of Concept → 2 | Version disclosure enables targeted attacks |
| Impact | Informational → 0 | Combined with other findings only |
| Difficulty | Trivial → 1.0 | Delete file or restrict via .htaccess |
| Criticality | Public → 1.0 | n/a |
| **P Score** | **(1×0.30 + 0×0.15 + 2×0.25 + 0×0.20) × 1.0 × 1.0** = **(0.3 + 0 + 0.5 + 0) × 1.0** = **0.80** | |
| **Priority** | **🔵 Low** | |

**Rationale:** Low severity, no direct exploit chain, no business impact. Document and address during next hardening pass.

### 4.6 Summary Table of Examples

| Finding | CVSS (F) | EPSS (F) | Exploit (F) | Impact (F) | Difficulty | Crit. | P Score | Priority |
|---|---|---|---|---|---|---|---|---|
| Exposed `debug.log` | 3 | 0 | 7 | 10 | 1.0 | 1.0 | 4.65 | 🟠 High |
| Outdated PHP (EOL) | 6 | 6 | 10 | 8 | 0.7 | 1.0 | 4.76 | 🟠 High |
| Missing HSTS | 1 | 0 | 0 | 2 | 1.0 | 1.0 | 0.70 | 🔵 Low |
| Nulled Elementor Pro | 10 | 6 | 10 | 10 | 0.7 | 1.0 | **5.88\*** | 🔴 Critical |
| `readme.html` readable | 1 | 0 | 2 | 0 | 1.0 | 1.0 | 0.80 | 🔵 Low |

> **\* Nulled/backdoor findings override to Critical via mandatory escalation rule.**

---

## 5. Client Presentation, Executive Summary

### 5.1 Executive Summary Format

Present to the client in a **single-page dashboard format** (or 2-page maximum). The goal: they understand what's urgent, what can wait, and the business risk, in 60 seconds.

```markdown
# 🛡️ WordPress Security Audit, Executive Summary

**Client:** [Client Name]
**Date:** [Audit Date]
**Audit ID:** WP-[YEAR]-[XXXX]
**Overall Site Risk Score:** 47% (Moderate) ← [see section 6]

---

## 🔴 Critical, Immediate Action Required (≤ 24h)

| # | Finding | Business Risk | Est. Fix Time |
|---|---|---|---|
| 1 | Nulled Elementor Pro plugin active | Complete site takeover, SEO spam, blacklisting | Replace + clean: 4h |
| 2 | Outdated PHP 7.4 on e-commerce pages | PCI non-compliance, RCE risk, data breach | 2–4h with testing |

## 🟠 High, Action Required This Week (≤ 72h)

| # | Finding | Business Risk | Est. Fix Time |
|---|---|---|---|
| 3 | Debug log exposed at /wp-content/debug.log | Credential disclosure, API key leakage | 5 min |
| 4 | 14 plugins with known vulnerabilities | Cumulative exploit risk | 1–2h bulk update |

## 🟡 Medium, Schedule Within 2 Weeks

| # | Finding | Business Risk | Est. Fix Time |
|---|---|---|---|
| 5 | Missing security headers (X-Frame-Options) | Clickjacking risk (low likelihood) | 15 min |
| 6 | User enumeration via wp-json | Aids brute-force targeting | 10 min |

## 🔵 Low / ⚪ Info, Next Quarterly Review

| # | Finding | Notes |
|---|---|---|
| 7 | Readme.html readable | Version info disclosure, low-risk |
| 8 | Missing HSTS header | SSL stripping risk, requires HTTPS first |
| 9 | PHP 8.2 upgrade recommended | Future-proofing, performance |

---

## Key Recommendations (Top 3)

1. **Immediately** remove the nulled Elementor Pro and install a legitimate license
2. **Upgrade PHP** to 8.1+ (target your storefront first)
3. **Set up automated plugin update monitoring** to prevent future accumulation

---

*Full technical details in Appendix A. Remediation steps in Appendix B.*
```

### 5.2 Visual Priority Matrix

Present as a **2×2 matrix** (Impact vs Urgency) for the client slide deck:

```
                    HIGH IMPACT
                        │
      Low Urgency       │    High Urgency
      ┌─────────────────┼─────────────────┐
      │                 │                 │
      │  🔵 Low         │  🔴 Critical    │
      │  (Monitor)      │  (Fix now)      │
      │                 │                 │
      ├─────────────────┼─────────────────┤
      │                 │                 │
      │  ⚪ Info        │  🟡 Medium      │
      │  (Acknowledge)  │  (Schedule)     │
      │                 │                 │
      └─────────────────┼─────────────────┘
                        │
                    LOW IMPACT
                  ← URGENCY →
```

> **X-axis:** Urgency (how soon will this be exploited?) → driven by EPSS + exploit availability
> **Y-axis:** Impact (how bad is it?) → driven by business impact score

### 5.3 Per-Finding Client Presentation Format

Each finding in the client report should include a **priority badge** and **risk justification**:

```markdown
### [PRIORITY BADGE] Finding Title

| Field | Value |
|---|---|
| **Priority** | 🟠 High, Fix within 72h |
| **P Score** | 4.65 / 10.0 |
| **CVSS** | 5.9 (Medium) |
| **EPSS** | N/A |
| **Business Risk** | Credential disclosure, SEO blacklisting |
| **Location** | /wp-content/debug.log |
| **Fix Time** | ~5 minutes |

**Why this priority:** Debug logs expose sensitive data (API keys, session tokens, passwords).
Automated scanners detect this instantly. If credentials are present, this becomes Critical.

**Remediation:**
1. Delete /wp-content/debug.log
2. Add `define('WP_DEBUG', false);` to wp-config.php
3. Restrict debug file location or use a logging plugin
```

---

## 6. Overall Site Risk Score

A **percentage-based score** (0% = perfect security, 100% = fully compromised) that gives the client a single metric to track improvement over time.

### 6.1 Formula

```
Site Risk Score (%) = min(100, (Sum of all finding P scores / Max possible score) × 100)

Where:
  Sum of all finding P scores = Σ P_i for findings i = 1 to N
  Max possible score = N × 10 (each finding maxes at P = 10.0)
```

### 6.2 Tiered Classification

| Site Risk Score | Classification | Meaning |
|---|---|---|
| 0% – 15% | ✅ Excellent | Minor hardening opportunities; low risk posture |
| 16% – 35% | 🟢 Good | Some findings but manageable; standard security posture |
| 36% – 55% | 🟡 Moderate | Notable risk; remediation plan recommended within 30 days |
| 56% – 75% | 🟠 Elevated | Significant risk; urgent remediation required |
| 76% – 100% | 🔴 Critical | Site likely compromised or easily compromiseable |

### 6.3 Worked Example

A site with 10 findings:

| # | Finding | P Score |
|---|---|---|
| 1 | Nulled Elementor Pro | 5.88 |
| 2 | Exposed debug.log | 4.65 |
| 3 | Outdated PHP 7.4 | 4.76 |
| 4 | Weak password policy | 3.20 |
| 5 | Missing security headers | 2.10 |
| 6 | User enumeration | 2.40 |
| 7 | Exposed wp-config.php backup | 4.80 |
| 8 | Directory listing enabled | 1.90 |
| 9 | Readme.html readable | 0.80 |
| 10 | Missing HSTS | 0.70 |

**Sum of P scores:** 5.88 + 4.65 + 4.76 + 3.20 + 2.10 + 2.40 + 4.80 + 1.90 + 0.80 + 0.70 = **31.19**

**Max possible:** 10 × 10 = 100

**Site Risk Score:** 31.19 / 100 × 100 = **31.19% → 🟢 Good**

### 6.4 Weighted Variant (Optional)

For more granularity, weight findings by category:

```
Weighted Risk Score = (Σ (P_i × W_c)) / (N × 10) × 100

Where W_c is the category weight:
  Category               | Weight
  ───────────────────────┼───────
  Code Execution Risk    | 2.0
  Data Exposure         | 1.5
  Authentication        | 1.2
  Configuration         | 1.0
  Information Disclosure| 0.8
  Best Practice         | 0.5
```

### 6.5 Risk Score Trend

Track over time for the client. Each audit should show:

```markdown
## Site Risk Score History

| Audit Date | Score | Classification | Findings (C/H/M/L) | Trend |
|---|---|---|---|---|
| 2026-07-16 | 31% | 🟢 Good | 0 / 3 / 4 / 3 |, (baseline) |
| 2026-10-16 | n/a | n/a |, /, /, /, | Next audit |
```

---

## 7. Implementation Script (Python)

```python
#!/usr/bin/env python3
"""
WordPress Vulnerability Prioritization Model
Converts raw findings into scored, priority-ranked outputs.
"""

import json
import sys
from typing import Dict, List, Optional


# ─── Factor Value Tables ───────────────────────────────────────────────

CVSS_MAP = [
    (0.0, 0.0, 0),
    (0.1, 3.9, 1),
    (4.0, 6.9, 3),
    (7.0, 8.9, 6),
    (9.0, 10.0, 10),
]

EPSS_MAP = [
    (0.0, 0.001, 0),
    (0.001, 0.01, 1),
    (0.01, 0.10, 3),
    (0.10, 0.50, 6),
    (0.50, 1.0, 10),
]

EXPLOIT_MAP = {
    "none": 0,
    "poc": 2,
    "private": 5,
    "public_poc": 7,
    "weaponised": 10,
}

IMPACT_MAP = {
    "seo_blacklist": 10,
    "data_loss": 10,
    "compliance": 8,
    "reputation": 7,
    "financial": 5,
    "operational": 4,
    "functional": 2,
    "informational": 0,
}

DIFFICULTY_MAP = {
    "trivial": 1.0,
    "easy": 0.9,
    "moderate": 0.7,
    "complex": 0.5,
    "very_complex": 0.3,
}

CRITICALITY_MAP = {
    "ecommerce": 1.5,
    "admin": 1.3,
    "account": 1.2,
    "public": 1.0,
    "staging": 0.5,
}

# Mandatory overrides, these always rank as Critical
CRITICAL_OVERRIDE_KEYWORDS = [
    "nulled", "backdoor", "webshell", "shell", "malware",
    "c2", "command-and-control", "cryptominer",
]

PRIORITY_THRESHOLDS = [
    (7.0, 10.0, "Critical", "🔴", "Fix within 24 hours"),
    (4.5, 6.9, "High", "🟠", "Fix within 72 hours"),
    (2.0, 4.4, "Medium", "🟡", "Fix within 2 weeks"),
    (0.5, 1.9, "Low", "🔵", "Monitor quarterly"),
    (0.0, 0.49, "Info", "⚪", "Documented for awareness"),
]


# ─── Core Scoring ──────────────────────────────────────────────────────

def lookup(value: float, mapping: list) -> int:
    """Look up a float value in a range-based mapping table."""
    for lo, hi, factor in mapping:
        if lo <= value <= hi:
            return factor
    return 0


def cvss_factor(score: float) -> int:
    return lookup(score, CVSS_MAP)


def epss_factor(probability: float) -> int:
    return lookup(probability, EPSS_MAP)


def calculate_p_score(finding: Dict) -> Dict:
    """
    Calculate the Priority Score (P) for a single finding.

    Expected input format:
    {
        "title": "Exposed debug.log",
        "cvss": 5.9,
        "epss": 0.0,            # 0.0 if no CVE
        "exploit": "public_poc", # see EXPLOIT_MAP keys
        "impact": "data_loss",   # see IMPACT_MAP keys
        "difficulty": "trivial", # see DIFFICULTY_MAP keys
        "criticality": "public", # see CRITICALITY_MAP keys
        "description": "Debug log exposes credentials"
    }
    """
    cvss_f = cvss_factor(finding.get("cvss", 0))
    epss_f = epss_factor(finding.get("epss", 0))
    exploit_f = EXPLOIT_MAP.get(finding.get("exploit", "none"), 0)
    impact_f = IMPACT_MAP.get(finding.get("impact", "informational"), 0)
    difficulty_f = DIFFICULTY_MAP.get(finding.get("difficulty", "moderate"), 0.7)
    criticality_f = CRITICALITY_MAP.get(finding.get("criticality", "public"), 1.0)

    raw_p = (
        (cvss_f * 0.30) +
        (epss_f * 0.15) +
        (exploit_f * 0.25) +
        (impact_f * 0.20)
    ) * difficulty_f * criticality_f

    # Check for mandatory Critical override
    title_lower = finding.get("title", "").lower()
    is_override = any(kw in title_lower for kw in CRITICAL_OVERRIDE_KEYWORDS)

    # Determine priority
    priority_name, priority_icon, sla = "Info", "⚪", "Documented"
    for lo, hi, name, icon, sla_text in PRIORITY_THRESHOLDS:
        if lo <= raw_p <= hi:
            priority_name, priority_icon, sla = name, icon, sla_text
            break

    if is_override:
        priority_name, priority_icon, sla = "Critical", "🔴", "Fix within 24 hours (OVERRIDE)"

    return {
        "title": finding.get("title", "Unknown"),
        "p_score": round(raw_p, 2),
        "priority": priority_name,
        "icon": priority_icon,
        "sla": sla,
        "override": is_override,
        "component_scores": {
            "cvss_factor": cvss_f,
            "epss_factor": epss_f,
            "exploit_factor": exploit_f,
            "impact_factor": impact_f,
            "difficulty_divisor": difficulty_f,
            "criticality_multiplier": criticality_f,
        },
    }


def site_risk_score(findings: List[Dict]) -> Dict:
    """
    Calculate the overall site risk score (0-100%).
    """
    scored = [calculate_p_score(f) for f in findings]
    total_p = sum(s["p_score"] for s in scored)
    max_possible = len(scored) * 10.0
    raw_percentage = (total_p / max_possible * 100) if max_possible > 0 else 0
    percentage = min(100, round(raw_percentage, 1))

    if percentage <= 15:
        classification = "✅ Excellent"
    elif percentage <= 35:
        classification = "🟢 Good"
    elif percentage <= 55:
        classification = "🟡 Moderate"
    elif percentage <= 75:
        classification = "🟠 Elevated"
    else:
        classification = "🔴 Critical"

    return {
        "site_risk_score": percentage,
        "classification": classification,
        "total_findings": len(scored),
        "critical": sum(1 for s in scored if s["priority"] == "Critical"),
        "high": sum(1 for s in scored if s["priority"] == "High"),
        "medium": sum(1 for s in scored if s["priority"] == "Medium"),
        "low": sum(1 for s in scored if s["priority"] == "Low"),
        "info": sum(1 for s in scored if s["priority"] == "Info"),
        "findings": sorted(scored, key=lambda x: x["p_score"], reverse=True),
    }


# ─── CLI Entry Point ───────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: prioritize.py <findings.json>")
        print("       prioritize.py --example")
        sys.exit(1)

    if sys.argv[1] == "--example":
        findings = [
            {"title": "Exposed debug.log", "cvss": 5.9, "epss": 0.0,
             "exploit": "public_poc", "impact": "data_loss",
             "difficulty": "trivial", "criticality": "public"},
            {"title": "Outdated PHP 7.4 (EOL)", "cvss": 8.8, "epss": 0.15,
             "exploit": "weaponised", "impact": "compliance",
             "difficulty": "moderate", "criticality": "public"},
            {"title": "Missing HSTS Header", "cvss": 3.7, "epss": 0.0,
             "exploit": "none", "impact": "functional",
             "difficulty": "trivial", "criticality": "public"},
            {"title": "Nulled Elementor Pro", "cvss": 9.8, "epss": 0.35,
             "exploit": "weaponised", "impact": "data_loss",
             "difficulty": "moderate", "criticality": "public"},
            {"title": "Readme.html readable", "cvss": 2.1, "epss": 0.0,
             "exploit": "poc", "impact": "informational",
             "difficulty": "trivial", "criticality": "public"},
        ]
    else:
        with open(sys.argv[1]) as f:
            findings = json.load(f)

    result = site_risk_score(findings)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
```

**Usage:**
```bash
python3 prioritize.py findings.json
python3 prioritize.py --example
```

**Input format (`findings.json`):**
```json
[
    {
        "title": "Exposed debug.log",
        "cvss": 5.9,
        "epss": 0.0,
        "exploit": "public_poc",
        "impact": "data_loss",
        "difficulty": "trivial",
        "criticality": "public"
    }
]
```

---

## 8. Implementation Script (Bash)

```bash
#!/bin/bash
# WordPress Vulnerability Prioritization, Bash version
# Usage: ./prioritize.sh <findings.tsv>
# Input: TSV with columns: title  cvss  epss  exploit  impact  difficulty  criticality

set -euo pipefail

# ─── Factor Lookup Functions ───────────────────────────────────────────

cvss_factor() {
    local score="$1"
    awk -v s="$score" '
        BEGIN {
            if (s == 0.0)      { print 0; exit }
            if (s >= 0.1 && s <= 3.9) { print 1; exit }
            if (s >= 4.0 && s <= 6.9) { print 3; exit }
            if (s >= 7.0 && s <= 8.9) { print 6; exit }
            if (s >= 9.0 && s <= 10.0){ print 10; exit }
            print 0
        }'
}

exploit_factor() {
    case "$1" in
        none)        echo 0 ;;
        poc)         echo 2 ;;
        private)     echo 5 ;;
        public_poc)  echo 7 ;;
        weaponised)  echo 10 ;;
        *)           echo 0 ;;
    esac
}

impact_factor() {
    case "$1" in
        seo_blacklist|data_loss) echo 10 ;;
        compliance)    echo 8 ;;
        reputation)    echo 7 ;;
        financial)     echo 5 ;;
        operational)   echo 4 ;;
        functional)    echo 2 ;;
        informational) echo 0 ;;
        *)             echo 0 ;;
    esac
}

difficulty_divisor() {
    case "$1" in
        trivial)      echo "1.0" ;;
        easy)         echo "0.9" ;;
        moderate)     echo "0.7" ;;
        complex)      echo "0.5" ;;
        very_complex) echo "0.3" ;;
        *)            echo "0.7" ;;
    esac
}

criticality_mult() {
    case "$1" in
        ecommerce) echo "1.5" ;;
        admin)     echo "1.3" ;;
        account)   echo "1.2" ;;
        public)    echo "1.0" ;;
        staging)   echo "0.5" ;;
        *)         echo "1.0" ;;
    esac
}

priority_label() {
    awk -v p="$1" '
        BEGIN {
            if (p >= 7.0)  { print "Critical\t🔴\tFix within 24h"; exit }
            if (p >= 4.5)  { print "High\t\t🟠\tFix within 72h"; exit }
            if (p >= 2.0)  { print "Medium\t\t🟡\tFix within 2 weeks"; exit }
            if (p >= 0.5)  { print "Low\t\t🔵\tMonitor quarterly"; exit }
            print "Info\t\t⚪\tDocumented for awareness"
        }'
}

# ─── Main Scoring Loop ─────────────────────────────────────────────────

INPUT_FILE="${1:-}"
if [ -z "$INPUT_FILE" ]; then
    echo "Usage: $0 <findings.tsv>"
    echo ""
    echo "Expected TSV format (no header):"
    echo "  title  cvss  epss  exploit  impact  difficulty  criticality"
    echo ""
    echo "Example:"
    echo '  "Exposed debug.log"  5.9  0.0  public_poc  data_loss  trivial  public'
    exit 1
fi

echo "============================================================"
echo "  WordPress Vulnerability Prioritization Report"
echo "============================================================"
echo ""
printf "%-45s %-8s %-10s %s\n" "Finding" "P Score" "Priority" "SLA"
echo "------------------------------------------------------------"

TOTAL_P=0
COUNT=0
CRIT=0
HIGH=0
MED=0
LOW=0
INFO=0

while IFS=$'\t' read -r title cvss epss exploit impact difficulty criticality; do
    # Skip header if present
    [[ "$title" == "title" ]] && continue

    CVSS_F=$(cvss_factor "$cvss")
    EXPLOIT_F=$(exploit_factor "$exploit")
    IMPACT_F=$(impact_factor "$impact")
    DIFF_DIV=$(difficulty_divisor "$difficulty")
    CRIT_MULT=$(criticality_mult "$criticality")

    # EPSS factor: convert probability string to factor
    EPSS_F=$(awk -v e="$epss" '
        BEGIN {
            if (e == "" || e == "N/A" || e == "0.0" || e == 0) { print 0; exit }
            if (e < 0.001)  { print 0; exit }
            if (e < 0.01)   { print 1; exit }
            if (e < 0.10)   { print 3; exit }
            if (e < 0.50)   { print 6; exit }
            print 10
        }')

    # Calculate P score using awk for floating point
    P_SCORE=$(awk -v cvss_f="$CVSS_F" -v epss_f="$EPSS_F" \
                  -v exploit_f="$EXPLOIT_F" -v impact_f="$IMPACT_F" \
                  -v diff_div="$DIFF_DIV" -v crit_mult="$CRIT_MULT" \
        'BEGIN {
            raw = (cvss_f * 0.30) + (epss_f * 0.15) + (exploit_f * 0.25) + (impact_f * 0.20)
            p = raw * diff_div * crit_mult
            printf "%.2f", p
        }')

    # Check for Critical override
    TITLE_LOWER=$(echo "$title" | tr '[:upper:]' '[:lower:]')
    OVERRIDE=0
    for kw in "nulled" "backdoor" "webshell" "shell" "malware" "c2" "cryptominer"; do
        if echo "$TITLE_LOWER" | grep -q "$kw"; then
            OVERRIDE=1
            break
        fi
    done

    if [ "$OVERRIDE" -eq 1 ]; then
        PRIORITY="Critical"
        ICON="🔴"
        SLA="Fix within 24h (OVERRIDE)"
    else
        PRIORITY_LINE=$(priority_label "$P_SCORE")
        PRIORITY=$(echo "$PRIORITY_LINE" | awk '{print $1}')
        ICON=$(echo "$PRIORITY_LINE" | awk '{print $2}')
        SLA=$(echo "$PRIORITY_LINE" | cut -f3-)
    fi

    printf "%-45s %-8s %-10s %s\n" "$title" "$P_SCORE" "$ICON $PRIORITY" "$SLA"

    TOTAL_P=$(awk -v t="$TOTAL_P" -v p="$P_SCORE" 'BEGIN { printf "%.2f", t + p }')
    COUNT=$((COUNT + 1))
    case "$PRIORITY" in
        Critical) CRIT=$((CRIT + 1)) ;;
        High)     HIGH=$((HIGH + 1)) ;;
        Medium)   MED=$((MED + 1)) ;;
        Low)      LOW=$((LOW + 1)) ;;
        Info)     INFO=$((INFO + 1)) ;;
    esac
done < "$INPUT_FILE"

echo "------------------------------------------------------------"
echo ""

# Calculate site risk score
if [ "$COUNT" -gt 0 ]; then
    MAX_POSSIBLE=$(awk -v n="$COUNT" 'BEGIN { printf "%.1f", n * 10 }')
    RISK_PCT=$(awk -v tp="$TOTAL_P" -v mp="$MAX_POSSIBLE" \
        'BEGIN { pct = (tp / mp) * 100; if (pct > 100) pct = 100; printf "%.1f", pct }')

    CLASSIFICATION=""
    if (( $(echo "$RISK_PCT <= 15" | bc -l) )); then
        CLASSIFICATION="✅ Excellent"
    elif (( $(echo "$RISK_PCT <= 35" | bc -l) )); then
        CLASSIFICATION="🟢 Good"
    elif (( $(echo "$RISK_PCT <= 55" | bc -l) )); then
        CLASSIFICATION="🟡 Moderate"
    elif (( $(echo "$RISK_PCT <= 75" | bc -l) )); then
        CLASSIFICATION="🟠 Elevated"
    else
        CLASSIFICATION="🔴 Critical"
    fi

    echo "============================================================"
    echo "  Overall Site Risk Score"
    echo "============================================================"
    echo ""
    echo "  Site Risk Score : $RISK_PCT%"
    echo "  Classification  : $CLASSIFICATION"
    echo "  Total Findings  : $COUNT"
    echo "  Critical        : $CRIT"
    echo "  High            : $HIGH"
    echo "  Medium          : $MED"
    echo "  Low             : $LOW"
    echo "  Info            : $INFO"
    echo ""
fi
```

**Usage:**
```bash
chmod +x prioritize.sh
./prioritize.sh findings.tsv
```

**Input format (`findings.tsv`):**
```tsv
title	cvss	epss	exploit	impact	difficulty	criticality
Exposed debug.log	5.9	0	public_poc	data_loss	trivial	public
Outdated PHP 7.4 (EOL)	8.8	0.15	weaponised	compliance	moderate	public
Missing HSTS Header	3.7	0	none	functional	trivial	public
Nulled Elementor Pro	9.8	0.35	weaponised	data_loss	moderate	public
Readme.html readable	2.1	0	poc	informational	trivial	public
```

---

## Appendix A: Quick Reference Card

### Scoring Cheat Sheet

```
P = (CVSS_F × 0.30 + EPSS_F × 0.15 + EXPLOIT_F × 0.25 + IMPACT_F × 0.20) × DIFF_DIV × CRIT_MULT

        CVSS        EPSS        Exploit     Impact      Difficulty         Criticality
        ─────       ────        ───────     ──────      ──────────         ───────────
 10     9.0-10.0    >0.50       weaponised  seo_blacklist / data_loss  trivial(1.0)  ecomm(1.5)
  6     7.0-8.9     0.10-0.50   private     compliance  easy(0.9)    admin(1.3)
  3     4.0-6.9     0.01-0.10   public_poc  reputation  moderate(0.7)  account(1.2)
  1     0.1-3.9     0.001-0.01  poc         financial   complex(0.5)   public(1.0)
  0     None        <0.001      none        operational v.complex(0.3) staging(0.5)
                                            functional
                                            informational
```

### Bypass Rules (Automatic Critical or High)

| Condition | Bypass To |
|---|---|
| Nulled/pirated premium plugin | 🔴 Critical |
| Backdoor / webshell / eval() injection | 🔴 Critical |
| CISA KEV (Known Exploited Vulnerabilities) catalog entry | 🔴 Critical |
| Active botnet / mass-scanning campaign detected | 🔴 Critical |
| Exposed credentials (plaintext passwords, API keys) | 🔴 Critical |
| Confirmed data breach with evidence | 🔴 Critical |
| All other findings with P ≥ 7.0 | 🔴 Critical |
| Debug log with credentials visible | 🟠 High (min) |
| EOL software (PHP < 8.0, WP < 5.x with known vulns) | 🟠 High (min) |

---

## Appendix B: Error Handling & Edge Cases

| Scenario | Handling |
|---|---|
| No CVE assigned | Set CVSS = projected score from finding template; EPSS = 0 |
| EPSS API unavailable | Use last known EPSS score from cache; fall back to 0 |
| Finding affects multiple impact types | Use the **highest** impact factor value |
| Finding is a false positive in context (e.g., debug log on dev site) | Adjust criticality to `staging` (0.5); note in report |
| Remediation requires paid plugin license | Note cost in finding; difficulty is based on technical complexity, not cost |
| Client disputes priority | Provide P score breakdown showing each factor contribution |
| Same finding on multiple pages/servers | Score once; multiply criticality if affects different assets (e.g., public + admin) |

---

## Appendix C: References

| Source | Description | URL |
|---|---|---|
| NVD / CVSS v3.1 | National Vulnerability Database, CVSS calculator | https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator |
| FIRST.org EPSS | Exploit Prediction Scoring System | https://www.first.org/epss |
| FIRST EPSS API | Programmatic EPSS lookup | https://www.first.org/epss/api |
| CISA KEV | Known Exploited Vulnerabilities Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| WPScan Vulnerability DB | WordPress-specific vulnerability database | https://wpscan.com |
| OWASP WordPress Cheatsheet | Hardening guidance | https://cheatsheetseries.owasp.org/cheatsheets/WordPress_Security_Cheat_Sheet.html |
| Google Safe Browsing | Check if site is blacklisted | https://transparencyreport.google.com/safe-browsing/search |

---

> **Document Maintainer:** Security Audit Team
> **Review Cycle:** Quarterly, or when CVSS/EPSS methodology changes
