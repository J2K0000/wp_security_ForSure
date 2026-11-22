# Checklist 12, Third-Party Scripts & Integrations Risk Assessment

**Audit Type:** Remote (no login required), WordPress  
**Risk Level:** Critical (CVSS 8.0–10.0 depending on script privileges)  
**Attack Surface Note:** Third-party scripts execute in the same browser context as first-party code, inheriting full DOM access, cookie access, and the ability to exfiltrate data, modify page content, or mine cryptocurrency. Each script is a potential supply-chain vector.

---

## Table of Contents

1. [Script Extraction, Find All External Scripts](#1-script-extraction)
2. [Script Categorization](#2-script-categorization)
3. [Subresource Integrity (SRI) Check](#3-subresource-integrity-sri-check)
4. [Mixed Content Detection (HTTP vs HTTPS)](#4-mixed-content-detection)
5. [Known Compromised CDN / Script Risks](#5-known-compromised-cdn--script-risks)
6. [Suspicious Domain Detection](#6-suspicious-domain-detection)
7. [Crypto Miner Detection](#7-crypto-miner-detection)
8. [Data Exfiltration Risks](#8-data-exfiltration-risks)
9. [Excessive Privilege (Browser API Abuse)](#9-excessive-privilege)
10. [Third-Party Fonts & Privacy Implications](#10-third-party-fonts--privacy-implications)
11. [GDPR Compliance, Facebook Pixel, Google Analytics, GTM](#11-gdpr-compliance)
12. [Complete Script Analyzer (Bash)](#12-complete-script-analyzer-bash)

---

## 1. Script Extraction

### 1.1 Grep Page Source for `<script src=`

```bash
# Basic: extract all unique script src from a single page
curl -s "https://example.com" | grep -oP 'src=["'\'']\K[^"'\'' ]+' | grep -E '^https?://' | sort -u

# With protocol normalization
curl -s "https://example.com" | grep -oP '(?:src|href)=["'\'']\K[^"'\'' ]+' | grep -E '^https?://' | sort -u

# Full extraction including protocol-relative URLs (//cdn.example.com/foo.js)
curl -s "https://example.com" | grep -oP '(?:src|href)=["'\'']\K(?:https?:)?//[^"'\'' ]+' | sort -u
```

### 1.2 Expand to All Pages (Sitemap Crawl)

```bash
# Extract all internal URLs from sitemap, then fetch each page for scripts
SITEMAP="https://example.com/sitemap.xml"
curl -s "$SITEMAP" | grep -oP '<loc>\K[^<]+' | while read -r url; do
  curl -s "$url" | grep -oP 'src=["'\'']\Khttps?://[^"'\'' ]+' >> /tmp/all_scripts.txt
done
sort -u /tmp/all_scripts.txt
```

### 1.3 Extract Inline Scripts (for obfuscated / eval-based payloads)

```bash
curl -s "https://example.com" | grep -oP '<script[^>]*>\K.*?(?=</script>)' | grep -v '^$' | head -50
```

### 1.4 Check for Dynamic Script Injection (look for `createElement('script')`)

```bash
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE '(createElement|appendChild|innerHTML.*script|document\.write.*script)'
```

### Extraction Checklist

| # | Check | Command / Method |
|---|-------|------------------|
| 1.1 | `<script src="">` tags extracted | `grep -oP 'src=["...]...'` |
| 1.2 | All pages from sitemap crawled | Full sitemap harvest |
| 1.3 | Inline scripts inspected | `grep -oP '<script>...</script>'` |
| 1.4 | Dynamic injection checked | `createElement` / `appendChild` grep |
| 1.5 | Protocol-relative URLs normalized | `//cdn.example.com` → `https://` |

---

## 2. Script Categorization

Each extracted script URL must be classified. Use the following categories:

| Category | Pattern / Domains | Risk Level |
|----------|------------------|------------|
| **Analytics** | `google-analytics.com`, `googletagmanager.com`, `facebook.net`, `pixel`, `hotjar.com`, `matomo.org`, `clicky.com`, `mixpanel.com`, `amplitude.com`, `heap.io`, `segment.io`, `plausible.io` | Low-Medium |
| **Advertising** | `doubleclick.net`, `adsystem.com`, `adform.net`, `criteo.com`, `criteo.net`, `outbrain.com`, `taboola.com`, `pubmatic.com`, `openx.net`, `rubiconproject.com` | Medium-High |
| **CDN / Libraries** | `cdnjs.cloudflare.com`, `ajax.googleapis.com`, `cdn.jsdelivr.net`, `unpkg.com`, `cdn.polyfill.io`, `code.jquery.com`, `stackpath.bootstrapcdn.com` | Low (but high supply-chain impact) |
| **Social** | `platform.twitter.com`, `connect.facebook.net`, `platform.linkedin.com`, `instagram.com`, `pinterest.com`, `tiktok.com`, `snapchat.com` | Medium |
| **Utility** | `recaptcha.net`, `maps.googleapis.com`, `player.vimeo.com`, `wistia.com`, `typekit.net`, `use.typekit.com`, `cdn.jsdelivr.net/npm/...` | Low |
| **Fonts** | `fonts.googleapis.com`, `fonts.gstatic.com`, `use.typekit.com`, `fast.fonts.net`, `fontawesome.com` | Low (privacy implications only) |
| **Payments** | `stripe.com`, `paypal.com`, `js.braintreegateway.com`, `checkoutshopper-...adyen.com`, `mollie.com`, `square.com` | Critical |

### Categorization Script

```bash
# Categorize a list of script URLs
cat /tmp/all_scripts.txt | while read -r url; do
  case "$url" in
    *google-analytics*|*googletagmanager*|*facebook.net*|*pixel*|*hotjar*|*matomo*|*plausible*|*clicky*|*mixpanel*|*amplitude*|*heap*|*segment*)
      echo "ANALYTICS   $url" ;;
    *doubleclick*|*adsystem*|*adform*|*criteo*|*outbrain*|*taboola*|*pubmatic*|*openx*|*rubicon*)
      echo "ADVERTISING $url" ;;
    *cdnjs*|*ajax.googleapis*|*jsdelivr*|*unpkg*|*polyfill*|*code.jquery*|*bootstrapcdn*)
      echo "CDN/LIB     $url" ;;
    *twitter*|*facebook*|*linkedin*|*instagram*|*pinterest*|*tiktok*|*snapchat*)
      echo "SOCIAL      $url" ;;
    *recaptcha*|*maps.googleapis*|*vimeo*|*wistia*|*typekit*|*youtube*)
      echo "UTILITY     $url" ;;
    *fonts.googleapis*|*fonts.gstatic*|*fontawesome*|*fast.fonts*)
      echo "FONTS       $url" ;;
    *stripe*|*paypal*|*braintree*|*adyen*|*mollie*|*square*|*authorize*)
      echo "PAYMENT     $url" ;;
    *)
      echo "UNKNOWN     $url" ;;
  esac
done
```

### Categorization Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 2.1 | All extracted scripts assigned to a category | |
| 2.2 | Unknown/uncategorized scripts flagged for review | |
| 2.3 | Payment scripts identified and isolated (highest scrutiny) | |
| 2.4 | Advertising scripts reviewed (high data surface area) | |
| 2.5 | Total script count documented per category | |

---

## 3. Subresource Integrity (SRI) Check

SRI allows browsers to verify that fetched scripts match an expected cryptographic hash. Scripts loaded from CDNs **must** have an `integrity` attribute.

### 3.1 Check if Scripts Have Integrity Attributes

```bash
# Extract scripts that use crossorigin AND check integrity
curl -s "https://example.com" | grep -oP '<script[^>]+>' | while read -r tag; do
  src=$(echo "$tag" | grep -oP 'src=["'\'']\K[^"'\'' ]+')
  integrity=$(echo "$tag" | grep -oP 'integrity=["'\'']\K[^"'\'' ]+')
  crossorigin=$(echo "$tag" | grep -oP 'crossorigin=["'\'']?[^"'\''\s]+')
  if [ -n "$src" ] && echo "$src" | grep -qE '^https?://'; then
    if [ -n "$crossorigin" ] && [ -z "$integrity" ]; then
      echo "MISSING SRI: $src (crossorigin without integrity)"
    elif [ -z "$integrity" ]; then
      echo "NO SRI: $src"
    else
      echo "OK (SRI): $src [$integrity]"
    fi
  fi
done
```

### 3.2 Validate Integrity Hashes

```bash
# Verify SRI hash matches actual file content
# Example for a script on the page:
INTEGRITY="sha384-ABC123..."
URL="https://cdn.example.com/script.js"
ACTUAL_HASH=$(curl -s "$URL" | openssl dgst -sha384 -binary | openssl base64 -A)
EXPECTED_HASH=$(echo "$INTEGRITY" | cut -d- -f2)

if [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
  echo "SRI MATCH: $URL"
else
  echo "SRI MISMATCH: $URL (expected $EXPECTED_HASH, got $ACTUAL_HASH)"
fi
```

### 3.3 Critical Crossorigin Without Integrity Patterns

| Script Tag Pattern | Risk | Action |
|--------------------|------|--------|
| `<script src="//cdn..." crossorigin>` | **High** | Add integrity hash |
| `<script src="//cdn..." crossorigin="anonymous">` | **High** | Add integrity hash |
| `<script src="//cdn..." crossorigin="use-credentials">` | **Critical** | Verify credentials required |
| `<script src="//cdn..." integrity="sha384-...">` | Low | OK |
| `<script src="//cdn..." crossorigin integrity="">` | **High** | Empty integrity = no protection |

### SRI Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 3.1 | All external CDN scripts have `integrity` attribute | |
| 3.2 | All cross-origin scripts (`crossorigin=""`) have matching integrity | |
| 3.3 | No integrity attributes are empty strings | |
| 3.4 | Integrity hash matches actual file content | |
| 3.5 | SRI is not `sha1` (deprecated, should be `sha384` or `sha512`) | |

---

## 4. Mixed Content Detection

Mixed content occurs when an HTTPS page loads scripts over HTTP. Browsers block "active mixed content" (scripts), which can break functionality or expose vulnerabilities.

### 4.1 Scan for HTTP Script References

```bash
# Find scripts loaded over plain HTTP on an HTTPS page
curl -s "https://example.com" | grep -oP 'src=["'\'']http://[^"'\'' ]+' | sort -u

# Also check protocol-relative URLs (// without https:)
curl -s "https://example.com" | grep -oP 'src=["'\'']//[^"'\'' ]+' | sort -u

# Find all HTTP resources (images, iframes, etc.)
curl -s "https://example.com" | grep -oP '(?:src|href)=["'\'']http://[^"'\'' ]+' | sort -u
```

### 4.2 Check Content-Security-Policy `upgrade-insecure-requests`

```bash
curl -sI "https://example.com" | grep -i 'content-security-policy'
# Look for: upgrade-insecure-requests
```

### 4.3 Mixed Content Severity Table

| Resource Type | Browser Block? | Impact |
|---------------|----------------|--------|
| `<script src="http://...">` | **Blocked** | Script won't load |
| `<link rel="stylesheet" href="http://...">` | **Blocked** | CSS won't load |
| `<img src="http://...">` | **Warning only** | Image loads (passive) |
| `<iframe src="http://...">` | **Blocked** | Frame won't render |
| `@font-face { src: url(http://...); }` | **Blocked** | Font won't load |
| `fetch('http://...')` / XHR | **Blocked** | API calls fail |

### Mixed Content Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 4.1 | No scripts loaded over HTTP on HTTPS pages | |
| 4.2 | No protocol-relative URLs left unnormalized (// → https://) | |
| 4.3 | Content-Security-Policy includes `upgrade-insecure-requests` | |
| 4.4 | No passive mixed content (images, fonts over HTTP) | |
| 4.5 | All third-party CDN endpoints return HTTPS only (301 check) | |

---

## 5. Known Compromised CDN / Script Risks

### 5.1 Historical Major Incidents

| Incident | Date | Impact | Affected Domains |
|----------|------|--------|------------------|
| **Polyfill.io supply chain attack** | Jun 2024 | 100K+ sites infected. Chinese owner injected malware redirecting mobile users to sports betting via fake analytics domain. | `cdn.polyfill.io`, `polyfill.io` |
| **BootCDN/BootCSS compromise** | Since Jun 2023 | Chinese CDN domains used by same actor to spread malware. | `bootcdn.net`, `bootcss.com`, `staticfile.net`, `staticfile.org` |
| **Union Ads JS** | 2023–2024 | Malicious JS injection from ad network. | `unionadjs.com`, `xhsbpza.com`, `union.macoms.la`, `newcrbpc.com` |
| **Cloudflare CDNJS compromise** | Apr 2024 | Domain takeover via DNS. CDNJS (cdnjs.cloudflare.com) had historical DNS hijack incidents. Research has shown library squatting attacks on popular CDNJS packages. | `cdnjs.cloudflare.com` |
| **OptinMonster supply chain attack** | 2024 | Compromised JS SDK on 1.2M sites via CDN push. | `a.omappapi.com` |
| **Browserify / NPM typosquatting** | Ongoing | Malicious packages mimicking popular libraries pushed to npm. | Various |
| **Fake Google Analytics domains** | 2024 | Typosquatted analytics domains used to exfiltrate data. | `www.googie-anaiytics.com` (polyfill.io attack) |

### 5.2 Domains to Flag Immediately

Add these to your monitoring/blocking list:

```
# Known compromised / high-risk domains (2023–2025)
cdn.polyfill.io
polyfill.io
bootcdn.net
bootcss.com
staticfile.net
staticfile.org
unionadjs.com
xhsbpza.com
union.macoms.la
newcrbpc.com
www.googie-anaiytics.com
kuurza.com
```

### 5.3 Scanner: Check for Compromised CDN Domains

```bash
# Check if any known compromised domains appear in the page
curl -s "https://example.com" | grep -oP 'https?://[^"'\''/ ]+' | sort -u | while read -r url; do
  domain=$(echo "$url" | awk -F/ '{print $3}')
  case "$domain" in
    *polyfill*|*bootcdn*|*bootcss*|*staticfile*|*unionadjs*|*xhsbpza*|*macoms*|*newcrbpc*|*googie-anaiytics*|*kuurza*)
      echo "⚠ COMPROMISED: $url" ;;
  esac
done
```

### Compromised CDN Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 5.1 | No polyfill.io scripts on any page | |
| 5.2 | No bootcdn.net / bootcss.com / staticfile.net scripts | |
| 5.3 | No unionadjs.com / xhsbpza.com / macoms.la / newcrbpc.com scripts | |
| 5.4 | No CDNJS usage from high-risk packages (audit each) | |
| 5.5 | No known typosquatted analytics domains (check section 6) | |

---

## 6. Suspicious Domain Detection

### 6.1 Typosquatting Patterns to Watch

| Legitimate Domain | Suspicious Variant |
|-------------------|-------------------|
| `google-analytics.com` | `googie-anaiytics.com` ⚠ (used in polyfill.io attack) |
| `google-analytics.com` | `google-analytics.co`, `goog1e-analytics.com` |
| `googletagmanager.com` | `googletagmanager.co`, `googletagmanger.com` |
| `cdnjs.cloudflare.com` | `cdnjs.cloudflare.co`, `cdnjs.cloudfare.com` |
| `jsdelivr.net` | `jsdelivr.co`, `jsdelv.net` |
| `facebook.net` | `facebok.net`, `faceboook.net` |
| `stripe.com` | `str1pe.com`, `stripe.co` |
| `paypal.com` | `paypa1.com`, `pay-pal.com` |

### 6.2 Automated Suspicious Domain Detection

```bash
#!/bin/bash
# suspicious_domains.sh - Check for typosquatted or unknown script origins
URL="https://example.com"
KNOWN_GOOD_DOMAINS=(
  "google-analytics.com"
  "googletagmanager.com"
  "facebook.net"
  "cdnjs.cloudflare.com"
  "jsdelivr.net"
  "unpkg.com"
  "code.jquery.com"
  "stackpath.bootstrapcdn.com"
  "fonts.googleapis.com"
  "fonts.gstatic.com"
  "stripe.com"
  "paypal.com"
  "js.braintreegateway.com"
  "maps.googleapis.com"
  "recaptcha.net"
  "player.vimeo.com"
  "wistia.com"
  "hotjar.com"
  "matomo.org"
  "plausible.io"
)

echo "[*] Extracting script domains from $URL..."
curl -s "$URL" | grep -oP 'src=["'\'']?https?://[^"'\''/ ]+' | sort -u | while read -r src; do
  domain=$(echo "$src" | awk -F/ '{print $3}')

  # Check if domain is known-good
  found=0
  for good in "${KNOWN_GOOD_DOMAINS[@]}"; do
    if [ "$domain" = "$good" ]; then
      found=1
      break
    fi
  done

  if [ "$found" -eq 1 ]; then
    echo "✅ KNOWN:     $src"
  else
    echo "❌ UNKNOWN:   $src"

    # Check for typosquatting patterns
    if echo "$domain" | grep -qiE '(googie|anaiytics|googie|analytcs|analytix|analitics)'; then
      echo "   ⚠ TYPOSQUAT: Possible Google Analytics impersonation"
    fi
    if echo "$domain" | grep -qiE '(paypa[^l]|str1pe|stripe[^.]|faceboo?k[^.]|googl[^e])'; then
      echo "   ⚠ TYPOSQUAT: Possible brand impersonation"
    fi
    if ! echo "$domain" | grep -qE '\.(com|org|net|io|app|dev|co|uk|eu)$'; then
      echo "   ⚠ SUSPICIOUS: Unusual TLD"
    fi
  fi
done
```

### 6.3 Domain Age Check (young domains are riskier)

```bash
# Check domain creation date via whois (requires whois installed)
domain="example.com"
whois "$domain" 2>/dev/null | grep -iE 'Creation Date|Created on|created' | head -1
```

### Suspicious Domain Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 6.1 | No unknown CDN / library origins | |
| 6.2 | No typosquatted brand domains | |
| 6.3 | All script domains resolve to expected IP ranges | |
| 6.4 | Young domains (< 6 months old) flagged for review | |
| 6.5 | Domains with unusual TLDs (`.xyz`, `.top`, `.club`, `.work`) reviewed | |

---

## 7. Crypto Miner Detection

### 7.1 Known Crypto Mining JS Signatures

| Miner / Service | URL Pattern | Status |
|-----------------|-------------|--------|
| **Coinhive** (shut down 2019) | `coinhive.com/lib/coinhive.min.js` | Defunct, but clones exist |
| **Coinimp** | `coinimp.com`, `jquery1234.com/imp.js` | Active in wild |
| **CryptoLoot** | `cryptoloot.pro` | Active |
| **Minero.cc** | `minero.cc` | Active |
| **WebMinePool** | `webminepool.com` | Active |
| **JSECoin** | `jsecoin.com` | Active (legitimate but abused) |
| **IPOB** | `ipob.net` | Browser miner |
| **RealtimeCrypto** | `realtimecrypto.pro` | Active |
| **MineScript** | `minescript.js` | Generic miner |
| **AFKSystem** | `afksystem.com` | Browser miner |

### 7.2 Detection Commands

```bash
# Check for known crypto miner URL patterns
curl -s "https://example.com" | grep -oP 'https?://[^"'\'' ]+' | sort -u | while read -r url; do
  domain=$(echo "$url" | awk -F/ '{print $3}')
  case "$domain" in
    *coinimp*|*cryptoloot*|*minero*|*webminepool*|*jsecoin*|*coinhive*|*minescript*|*afksystem*|*realtimecrypto*|*ipob*)
      echo "⚠ CRYPTO MINER DETECTED: $url" ;;
  esac
done

# Check inline scripts for miner patterns
curl -s "https://example.com" | grep -oP '(?<=<script>).*?(?=</script>)' | grep -iE \
  '(cryptonight|cryptonight-lite|cryptonight-heavy|miner|hashrate|throttle|coinimp|startMiner|stopMiner|isRunning|_client|\$\(window\)\.on.*mine)'

# Check for WebAssembly-based miners (WASM crypto)
curl -s "https://example.com" | grep -iE '\.wasm|wasm_miner|WebAssembly\.instantiate'
```

### 7.3 CPU / Performance Symptoms (supplementary check)

| Symptom | Likelihood |
|---------|------------|
| CPU spikes to 80–100% on page load without visible reason | High |
| Battery drains faster on site | High |
| Fans spin up even on static pages | Medium |
| Network requests to miner domains at intervals | High |

### Crypto Miner Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 7.1 | No known crypto miner domains in script sources | |
| 7.2 | No inline JavaScript matching miner patterns | |
| 7.3 | No WebAssembly files loaded from suspicious origins | |
| 7.4 | No Web Worker scripts performing hash functions | |
| 7.5 | No WebSocket connections to mining pools | |

---

## 8. Data Exfiltration Risks

Scripts should only communicate with their own origin. A tracking script phoning home to an unexpected domain is a red flag.

### 8.1 Beacon / Exfiltration Patterns

```bash
# Find scripts making fetch/XHR requests to unexpected domains
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(XMLHttpRequest|fetch\(|axios\.|\.post\(|\.get\(|navigator\.sendBeacon)'

# Check for image beacons (1x1 tracking pixels to unknown domains)
curl -s "https://example.com" | grep -oP 'src=["'\'']https?://[^"'\'' ]+' | while read -r url; do
  # Filter out image beacons
  if echo "$url" | grep -qiE '(pixel|beacon|track|collect|analytics|collector)'; then
    domain=$(echo "$url" | awk -F/ '{print $3}')
    echo "POSSIBLE BEACON: $url [$domain]"
  fi
done
```

### 8.2 Script Behavior Analysis (Read the JS)

```bash
# Download and inspect a suspicious script
curl -s "https://suspicious-cdn.example.com/widget.js" | grep -oP \
  '(https?://[^"'\'',;)]+)' | sort -u | while read -r url; do
  domain=$(echo "$url" | awk -F/ '{print $3}')
  page_domain=$(echo "example.com" | awk -F/ '{print $3}')
  if [ "$domain" != "$page_domain" ] && ! echo "$domain" | grep -qiE \
    '(google|facebook|twitter|cdn|cloudflare|jquery|gstatic)'; then
    echo "⚠ EXFILTRATION RISK: Script ($domain) phones home to $url"
  fi
done
```

### 8.3 Red Flag Behaviors in Third-Party Scripts

| Behavior | Risk Level | Example |
|----------|------------|---------|
| Reads `document.cookie` and sends to remote | **Critical** | Session hijacking |
| Reads `localStorage`/`sessionStorage` and exfiltrates | **Critical** | Token theft |
| Sends `window.location.href` to unexpected domain | **High** | Form data theft |
| Captures form input values (`.value`) via event listeners | **High** | Credit card skimming (Magecart) |
| Sends `document.documentElement.outerHTML` | **High** | Page content exfiltration |
| Reads `navigator.userAgent` for fingerprinting | Medium | Tracking |
| Makes requests to IP addresses (not domains) | **High** | C2 communication |
| Uses Base64-encoded URLs or XOR obfuscation | **High** | Obfuscated C2 |

### 8.4 Magecart / Skimming Specific Checks

```bash
# Check for form input listeners (credit card skimming pattern)
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(addEventListener.*(blur|focus|change|input|submit)|onblur|onchange|oninput|\.value|card|cvv|credit)'
```

### Data Exfiltration Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 8.1 | No scripts sending data to unexpected/unrelated domains | |
| 8.2 | No form input event listeners from third-party scripts | |
| 8.3 | No scripts exfiltrating cookies or localStorage | |
| 8.4 | No scripts using `navigator.sendBeacon()` to unknown origins | |
| 8.5 | No image beacons (1×1 pixels) to suspicious domains | |
| 8.6 | No scripts making fetch/XHR to IP addresses (C2 pattern) | |
| 8.7 | No obfuscated or Base64-encoded URLs in script bodies | |

---

## 9. Excessive Privilege (Browser API Abuse)

Third-party scripts can access browser APIs that expose sensitive data. The following permissions should be flagged.

### 9.1 Browser API Access Detection

```bash
# Check for geolocation access
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(navigator\.geolocation|getCurrentPosition|watchPosition)'

# Check for camera / microphone access
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(getUserMedia|mediaDevices|enumerateDevices|navigator\.media)'

# Check for clipboard access
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(navigator\.clipboard|readText|writeText)'

# Check for battery status API (fingerprinting)
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(navigator\.getBattery|battery|chargingTime|dischargingTime|level)'

# Check for screen capture
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(getDisplayMedia|captureStream)'

# Check for sensor access (accelerometer, gyroscope)
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(Sensor|Accelerometer|Gyroscope|LinearAcceleration|AbsoluteOrientation)'

# Check for gamepad / HID access (fingerprinting)
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(getGamepads|navigator\.hid|requestDevice)'
```

### 9.2 Excessive Privilege Risk Matrix

| API | Script Type | Risk | Why |
|-----|-------------|------|-----|
| `navigator.geolocation` | Any third-party | **High** | User tracking |
| `getUserMedia` (camera/mic) | Any third-party | **Critical** | Surveillance |
| `navigator.clipboard.readText()` | Any third-party | **Critical** | Credential theft |
| `getDisplayMedia` | Any third-party | **Critical** | Screen capture |
| `Battery API` | Analytics | Low | Fingerprinting |
| `Canvas` + `toDataURL()` | Analytics | Medium | Canvas fingerprinting |
| `WebGL` + `getParameter` | Analytics | Medium | Device fingerprinting |
| `AudioContext` + `getFloatFrequencyData` | Analytics | Medium | Audio fingerprinting |
| `Sensor` APIs | Any | Medium | Environment fingerprinting |

### 9.3 Content-Security-Policy as a Mitigation

```bash
# Check current CSP for permissions policy directives
curl -sI "https://example.com" | grep -i 'permissions-policy'

# Recommended restrictive permissions policy:
# Permissions-Policy: geolocation=(), camera=(), microphone=(), 
#                     display-capture=(), clipboard-read=(), 
#                     clipboard-write=(self), battery=()
```

### Excessive Privilege Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 9.1 | No third-party scripts access geolocation API | |
| 9.2 | No third-party scripts access camera/microphone | |
| 9.3 | No third-party scripts access clipboard | |
| 9.4 | No third-party scripts access screen capture | |
| 9.5 | Canvas fingerprinting scripts identified | |
| 9.6 | Permissions-Policy header is restrictive for third-party origins | |

---

## 10. Third-Party Fonts & Privacy Implications

### 10.1 How Font Requests Leak Data

When a browser requests a font from Google Fonts (`fonts.googleapis.com`), the request includes the `Referer` header, exposing every page URL the user visits. Google Fonts also sets cookies and logs IP addresses.

### 10.2 Google Fonts Privacy Issue (GDPR Relevance)

- **What's leaked:** Referrer URL (page path), IP address, User-Agent, browser language.
- **GDPR ruling:** In 2022, a German court ruled that loading Google Fonts without consent violates GDPR. Hundreds of websites received legal warnings.
- **Data sent to:** Google servers in the US (Schrems II implications, no adequate data protection agreement).

### 10.3 Detection

```bash
# Check for Google Fonts
curl -s "https://example.com" | grep -oP 'https?://fonts\.(googleapis|gstatic)\.com/[^"'\'' ]+' | sort -u

# Check for Typekit / Adobe Fonts
curl -s "https://example.com" | grep -oP 'https?://use\.typekit\.net/[^"'\'' ]+' | sort -u

# Check for Font Awesome CDN
curl -s "https://example.com" | grep -oP 'https?://.*fontawesome[^"'\'' ]+' | sort -u

# Check @font-face CSS rules (self-hosted vs external)
curl -s "https://example.com" | grep -oP '@font-face\s*\{.*?\}' | grep -oP 'url\(["'\'']?\K[^"'\''\)]+'
```

### 10.4 Self-Hosting vs CDN Font Comparison

| Font Source | Privacy Impact | GDPR Risk | Performance |
|-------------|---------------|-----------|-------------|
| **Google Fonts CDN** (API + gstatic) | High, leaks referrer + IP | **Yes** (German ruling) | Fast (CDN) |
| **Adobe Typekit** | Medium, cookie-based tracking | **Yes** | Fast |
| **Font Awesome CDN** | Medium, IP + referrer logged | Potentially | Fast |
| **Self-hosted Google Fonts** | None, no external request | **No** | Slower (self) |
| **System fonts stack** | None, no request at all | **No** | Fastest |
| **Self-hosted WOFF/WOFF2** | None | **No** | Normal |

### 10.5 Self-Host Google Fonts (Remediation Command)

```bash
# Download Google Fonts for self-hosting (example)
# Using a tool like google-webfonts-helper:
# https://gwfh.mranftl.com/fonts
```

### Third-Party Fonts Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 10.1 | Google Fonts loaded from external CDN (leak referrer) | |
| 10.2 | Adobe Typekit / Font Awesome CDN used (cookie tracking) | |
| 10.3 | Font requests include cookies or tracking parameters | |
| 10.4 | Self-hosting considered as alternative | |
| 10.5 | `link[rel=preconnect]` for font origins documented | |
| 10.6 | GDPR consent obtained before loading external fonts (EU visitors) | |

---

## 11. GDPR Compliance

### 11.1 Facebook / Meta Pixel GDPR Requirements

**Meta Pixel** (formerly Facebook Pixel) sends extensive data to Facebook servers:
- Page URL, referrer, browser info, and user interactions
- If user is logged into Facebook: cross-site tracking occurs
- Can trigger Custom Audiences and conversion tracking

**GDPR Requirements since 2023:**

| Requirement | Detail |
|-------------|--------|
| ✅ **Explicit consent** before Pixel fires | Consent must be "freely given, specific, informed, unambiguous", pre-ticked boxes are invalid |
| ✅ **Cookie Consent Banner** | Must have granular opt-in/out for marketing cookies |
| ✅ **Data Processing Agreement (DPA)** with Meta | Required under GDPR Article 28 |
| ✅ **Data Transfer mechanism** (EU→US) | Must rely on SCCs or DPF (Schrems II considerations) |
| ✅ **Privacy Policy disclosure** | Must list Meta Pixel, data categories, and purposes |
| ✅ **User deletion/access rights** | Must provide mechanism for data subject requests |

### 11.2 Detection Commands

```bash
# Check for Facebook Pixel
curl -s "https://example.com" | grep -oP '(connect\.facebook\.net|facebook\.com/tr|fbq\(|_fbq|\/pixel)' | head -5

# Check for Google Analytics
curl -s "https://example.com" | grep -oP '(google-analytics\.com|gtag\(|ga\()|gtag\.js|analytics\.js|ga\.js)' | head -5

# Check for Google Tag Manager
curl -s "https://example.com" | grep -oP '(googletagmanager\.com|gtm\.js|dataLayer)' | head -5

# Extract GTM container ID
curl -s "https://example.com" | grep -oP 'GTM-[A-Z0-9]+' | sort -u

# Extract Facebook Pixel ID
curl -s "https://example.com" | grep -oP '(?:pixel_id|fbq\(["'\'']init["'\''],\s*["'\''])([0-9]+)' | sort -u
```

### 11.3 Google Analytics / GTM GDPR Requirements

| Requirement | Detail |
|-------------|--------|
| ✅ **IP Anonymization** (`anonymizeIp: true` in gtag) | Required by GDPR, Google Analytics by default logs IPs |
| ✅ **Consent Mode v2** | Since March 2024, Google requires consent signals for EU users |
| ✅ **Data Retention** | Must be set to minimum (14 months default, 2 months recommended) |
| ✅ **No data sharing with Google** | Disable "Google signals" and "data sharing" settings |
| ✅ **DPA with Google** | Required under GDPR |
| ✅ **Cookie Consent for analytics cookies** | Even if "essential" claim, analytics cookies typically need consent |

### 11.4 Check Consent Mode Implementation

```bash
# Look for consent-related gtag calls
curl -s "https://example.com" | grep -oP '<script[^>]*>.*?</script>' | grep -iE \
  '(consent|default|denied|granted|wait_for_update|ads_data_redaction|url_passthrough)'

# Check if Cookie Consent banner / CMP is loaded (e.g., Cookiebot, OneTrust, Complianz)
curl -s "https://example.com" | grep -oP '(cookiebot|cookielaw|onetrust|complianz|consent|optanon|usercentrics)' | sort -u
```

### 11.5 GDPR Compliance Scoring Table

| Script Type | Consent Required? | DPIA Needed? | Notes |
|-------------|------------------|--------------|-------|
| Google Analytics (gtag) | **Yes** | Maybe | IP anonymization required |
| Google Analytics (GA4) | **Yes** | Maybe | Consent Mode v2 required from March 2024 |
| Google Tag Manager | **Yes** | No (container) | Depends on tags fired |
| Facebook / Meta Pixel | **Yes** | **Yes** | High privacy risk |
| Hotjar / Session recording | **Yes** | **Yes** | Records user behavior |
| Google Ads conversion | **Yes** | No | Marketing consent needed |
| Stripe / Paypal (payment) | **Maybe** | No | Legitimate interest possible |
| reCAPTCHA | **Yes** | Maybe | Sends data to Google |
| Google Fonts | **Yes** | No | Per German court ruling (2022) |
| YouTube embeds | **Yes** | Maybe | Enhanced privacy mode recommended |
| Vimeo embeds | **Yes** | Maybe | DNT header setting available |

### GDPR Compliance Checklist

| # | Check | Pass/Fail |
|---|-------|-----------|
| 11.1 | Facebook/Meta Pixel has explicit opt-in consent before firing | |
| 11.2 | Google Analytics has `anonymizeIp: true` configured | |
| 11.3 | Google Consent Mode v2 implemented (granted/denied signals) | |
| 11.4 | Cookie Consent banner present and functional | |
| 11.5 | Granular consent (analytics vs marketing vs functional) available | |
| 11.6 | DPA signed with Meta/Facebook (if Pixel is used) | |
| 11.7 | DPA signed with Google (if GA/GTM is used) | |
| 11.8 | Data transfer mechanism (SCCs or DPF) documented for EU→US transfers | |
| 11.9 | Privacy policy lists all third-party scripts and data categories | |
| 11.10 | Data retention configured to minimum period | |
| 11.11 | reCAPTCHA has loading delayed until consent (where applicable) | |
| 11.12 | YouTube embeds use `youtube-nocookie.com` (enhanced privacy mode) | |

---

## 12. Complete Script Analyzer (Bash)

Save the following as `/root/workspace/cyber-securite/tools/analyze-third-party-scripts.sh`:

```bash
#!/bin/bash
# =============================================================================
# WordPress Third-Party Script Analyzer
# Usage: ./analyze-third-party-scripts.sh https://target-site.com
# Requirements: curl, openssl, whois (optional)
# =============================================================================

set -e

TARGET="${1}"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <url>"
  echo "Example: $0 https://example.com"
  exit 1
fi

TMPDIR=$(mktemp -d)
PAGE_SOURCE="$TMPDIR/page.html"
SCRIPTS_LIST="$TMPDIR/scripts.txt"
INLINE_SCRIPTS="$TMPDIR/inline.txt"
RESULTS="$TMPDIR/results.json"

echo "============================================"
echo " WordPress Third-Party Script Analyzer"
echo " Target: $TARGET"
echo " Date:   $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

# --- Step 1: Fetch page ---
echo "[1/12] Fetching page source..."
curl -sL "$TARGET" -o "$PAGE_SOURCE" -w "HTTP Status: %{http_code}\nSize: %{size_download} bytes\n"

# --- Step 2: Extract all <script src=> ---
echo "[2/12] Extracting script sources..."
grep -oP 'src=["'\'']\Khttps?://[^"'\'' ]+' "$PAGE_SOURCE" | sort -u > "$SCRIPTS_LIST"
SCRIPT_COUNT=$(wc -l < "$SCRIPTS_LIST")
echo "  Found $SCRIPT_COUNT external scripts"
cat "$SCRIPTS_LIST"

# --- Step 3: Extract inline scripts ---
echo "[3/12] Extracting inline scripts..."
grep -oP '<script[^>]*>.*?</script>' "$PAGE_SOURCE" > "$INLINE_SCRIPTS"

# --- Step 4: Categorize scripts ---
echo "[4/12] Categorizing scripts..."
while read -r url; do
  case "$url" in
    *google-analytics*|*googletagmanager*|*facebook.net*|*pixel*|*hotjar*|*matomo*|*plausible*)
      echo "  [ANALYTICS]   $url" ;;
    *doubleclick*|*adsystem*|*adform*|*criteo*|*outbrain*|*taboola*|*pubmatic*)
      echo "  [ADVERTISING] $url" ;;
    *cdnjs*|*ajax.googleapis*|*jsdelivr*|*unpkg*|*polyfill*|*code.jquery*|*bootstrapcdn*)
      echo "  [CDN/LIB]     $url" ;;
    *twitter*|*facebook*|*linkedin*|*instagram*|*pinterest*|*tiktok*)
      echo "  [SOCIAL]      $url" ;;
    *recaptcha*|*maps.googleapis*|*vimeo*|*wistia*|*typekit*|*youtube*)
      echo "  [UTILITY]     $url" ;;
    *fonts.googleapis*|*fonts.gstatic*|*fontawesome*)
      echo "  [FONTS]       $url" ;;
    *stripe*|*paypal*|*braintree*|*adyen*|*mollie*|*square*)
      echo "  [PAYMENT]     $url" ;;
    *)
      echo "  [UNKNOWN]     $url" ;;
  esac
done < "$SCRIPTS_LIST"

# --- Step 5: SRI check ---
echo "[5/12] Checking Subresource Integrity..."
grep -oP '<script[^>]+>' "$PAGE_SOURCE" | while read -r tag; do
  src=$(echo "$tag" | grep -oP 'src=["'\'']\K[^"'\'' ]+')
  integrity=$(echo "$tag" | grep -oP 'integrity=["'\'']\K[^"'\'' ]+')
  crossorigin=$(echo "$tag" | grep -oP 'crossorigin')
  if [ -n "$src" ] && echo "$src" | grep -qE '^https?://'; then
    if [ -n "$crossorigin" ] && [ -z "$integrity" ]; then
      echo "  ⚠ MISSING SRI: $src (crossorigin without integrity)"
    elif [ -z "$integrity" ]; then
      echo "  ℹ NO SRI: $src"
    fi
  fi
done

# --- Step 6: Mixed content check ---
echo "[6/12] Checking mixed content..."
HTTP_SCRIPTS=$(grep -cE 'src=["'\'']http://' "$PAGE_SOURCE" || true)
echo "  Scripts loaded over HTTP: $HTTP_SCRIPTS"
if [ "$HTTP_SCRIPTS" -gt 0 ]; then
  grep -oP 'src=["'\'']http://[^"'\'' ]+' "$PAGE_SOURCE" | while read -r s; do
    echo "  ❌ $s"
  done
fi

# --- Step 7: Known compromised CDN check ---
echo "[7/12] Checking known compromised CDNs..."
while read -r url; do
  domain=$(echo "$url" | awk -F/ '{print $3}')
  case "$domain" in
    *polyfill*|*bootcdn*|*bootcss*|*staticfile*|*unionadjs*|*xhsbpza*|*macoms*|*newcrbpc*|*googie-anaiytics*)
      echo "  ❌ COMPROMISED CDN: $url" ;;
  esac
done < "$SCRIPTS_LIST"

# --- Step 8: Suspicious domains ---
echo "[8/12] Checking suspicious domains..."
KNOWN_GOOD=("google-analytics.com" "googletagmanager.com" "facebook.net"
  "cdnjs.cloudflare.com" "jsdelivr.net" "unpkg.com" "code.jquery.com"
  "stackpath.bootstrapcdn.com" "fonts.googleapis.com" "fonts.gstatic.com"
  "stripe.com" "paypal.com" "maps.googleapis.com" "recaptcha.net"
  "player.vimeo.com" "hotjar.com" "matomo.org" "plausible.io")

while read -r url; do
  domain=$(echo "$url" | awk -F/ '{print $3}')
  found=0
  for good in "${KNOWN_GOOD[@]}"; do
    [ "$domain" = "$good" ] && found=1 && break
  done
  if [ "$found" -eq 0 ]; then
    echo "  ⚠ UNKNOWN ORIGIN: $url"
  fi
done < "$SCRIPTS_LIST"

# --- Step 9: Crypto miner check ---
echo "[9/12] Checking for crypto miners..."
MINER_FOUND=0
while read -r url; do
  case "$(echo "$url" | awk -F/ '{print $3}')" in
    *coinimp*|*cryptoloot*|*minero*|*webminepool*|*jsecoin*|*coinhive*|*minescript*)
      echo "  ❌ CRYPTO MINER: $url"
      MINER_FOUND=1 ;;
  esac
done < "$SCRIPTS_LIST"
grep -iE '(cryptonight|cryptonight-lite|startMiner|stopMiner|isRunning|hashrate|throttle)' \
  "$INLINE_SCRIPTS" > /dev/null 2>&1 && \
  echo "  ❌ MINER PATTERNS DETECTED IN INLINE SCRIPTS" && MINER_FOUND=1
[ "$MINER_FOUND" -eq 0 ] && echo "  ✅ No crypto miners detected"

# --- Step 10: Data exfiltration check ---
echo "[10/12] Checking data exfiltration patterns..."
while read -r url; do
  domain=$(echo "$url" | awk -F/ '{print $3}')
  page_domain=$(echo "$TARGET" | awk -F/ '{print $3}')
  script_body=$(curl -sL "$url" 2>/dev/null)
  if echo "$script_body" | grep -qiE '(document\.cookie|localStorage|sessionStorage)'; then
    echo "  ⚠ Script reads cookies/storage: $url"
  fi
  if echo "$script_body" | grep -qiE '(credit|card|cvv|cc_number|cc-exp|cc-csc)'; then
    echo "  ❌ POSSIBLE SKIMMER: $url (credit card field references)"
  fi
done < "$SCRIPTS_LIST"

# --- Step 11: Excessive privilege check ---
echo "[11/12] Checking excessive browser privileges..."
grep -iE '(geolocation|getCurrentPosition|watchPosition|getUserMedia|mediaDevices|clipboard\.read|clipboard\.write|getDisplayMedia|captureStream|BatteryManager|getBattery)' \
  "$INLINE_SCRIPTS" "$PAGE_SOURCE" > /dev/null 2>&1 && \
  echo "  ⚠ Inline scripts access browser APIs, review required"

while read -r url; do
  script_body=$(curl -sL "$url" 2>/dev/null)
  if echo "$script_body" | grep -qiE '(navigator\.geolocation|getCurrentPosition|getUserMedia|clipboard\.read|getDisplayMedia)'; then
    echo "  ❌ EXCESSIVE PRIVILEGE: $url"
  fi
done < "$SCRIPTS_LIST"

# --- Step 12: GDPR compliance check ---
echo "[12/12] Checking GDPR compliance..."
FB_PIXEL=$(grep -cE '(connect\.facebook\.net|fbq\(|_fbq)' "$PAGE_SOURCE" || true)
GA_SCRIPT=$(grep -cE '(google-analytics\.com|gtag\(|gtag\.js)' "$PAGE_SOURCE" || true)
GTM_SCRIPT=$(grep -cE '(googletagmanager\.com|gtm\.js|dataLayer)' "$PAGE_SOURCE" || true)
CONSENT=$(grep -cE '(cookiebot|cookielaw|onetrust|complianz|consent|usercentrics)' "$PAGE_SOURCE" || true)

[ "$FB_PIXEL" -gt 0 ] && echo "  📢 Facebook/Meta Pixel detected, requires explicit consent"
[ "$GA_SCRIPT" -gt 0 ] && echo "  📊 Google Analytics detected, requires anonymizeIp + consent"
[ "$GTM_SCRIPT" -gt 0 ] && echo "  🔧 Google Tag Manager detected, review all fired tags"
[ "$CONSENT" -eq 0 ] && echo "  ❌ No consent management platform (CMP) detected!"
[ "$CONSENT" -gt 0 ] && echo "  ✅ Consent management platform detected"

echo ""
echo "============================================"
echo " ANALYSIS COMPLETE"
echo "============================================"
echo ""
echo "Scripts found:      $SCRIPT_COUNT"
echo "Total risk finding: inspect output above"
echo "Raw data:           $TMPDIR"

# Cleanup (comment out to keep temp files)
rm -rf "$TMPDIR"
```

---

## Summary Risk Score Matrix

| Section | Critical | High | Medium | Low | Score |
|---------|----------|------|--------|-----|-------|
| 1. Script Extraction | 0 findings | 1–2 missing | 3–4 missing | Full coverage | /5 |
| 2. Categorization | Payment scripts | Unknown scripts | All categorized | Complete | /5 |
| 3. SRI | Crossorigin no integrity | Missing SRI | SHA1 integrity | SHA384/512 | /5 |
| 4. Mixed Content | Active mixed content | Passive mixed content | No upgrade-insecure | Fully HTTPS | /5 |
| 5. Compromised CDN | Polyfill/BootCDN | Old compromised CDN | No known issues | Clean | /5 |
| 6. Suspicious Domains | Typosquatted CDN | Unknown origin | Known origin | Trusted | /5 |
| 7. Crypto Miners | Active miner detected | Suspicious WASM | No miner files | Clean | /5 |
| 8. Data Exfiltration | Skimmer/exfil C2 | Cookie theft | Unknown beacons | Clean | /5 |
| 9. Excessive Privilege | Camera/mic/geo | Fingerprinting | Canvas FP | No access | /5 |
| 10. Fonts | Google Fonts no consent | Typekit/FA CDN | Self-hosted fonts | No fonts | /5 |
| 11. GDPR | No CMP + Pixel | No CMP | CMP present | Full compliance | /5 |
| **Total** | | | | | **/55** |

### Risk Interpretation

| Score | Rating | Action Required |
|-------|--------|----------------|
| 0–15 | **Critical** | Immediate remediation required. Site likely compromised. |
| 16–30 | **High** | Multiple risks identified. Schedule remediation within 48 hours. |
| 31–45 | **Medium** | Some risks present. Address within next sprint cycle. |
| 46–55 | **Low** | Good posture. Maintain regular monitoring. |

---

*End of Checklist 12, Third-Party Scripts & Integrations Risk Assessment*
