# SCBurpScan

A Burp Suite Community Edition extension that brings **passive and active vulnerability scanning** to HTTP history — no Pro license required.

When a pentester browses a target through Burp Proxy, SCBurpScan automatically analyzes every request/response in the background. Findings appear in a dedicated tab with an Advisory/Request/Response detail panel, right-click send-to-tool support, and a fully extensible rule system via JSON files.

---

## Features

| Feature | Details |
|---|---|
| **Passive Scan** | Always-on, zero extra requests. Detects XSS reflection, SQL errors, open redirects, SSRF params, sensitive info leakage, missing security headers |
| **Active Scan** | Toggle-on fuzzing. Tests each parameter with XSS, SQLi (error + time-based + boolean-based), and path traversal payloads |
| **In-Scope Filter** | Toggle to only scan URLs in Burp's defined scope |
| **Deduplication** | Same rule + host + path + param never fires twice |
| **Custom Rules** | Load your own rules from a JSON folder — no recompile needed |
| **Send to Tools** | Right-click any finding → Send to Repeater / Intruder / Comparer |
| **Advisory Panel** | Burp Pro-style detail view: severity badge, meta info, request/response side by side |

---

## Screenshots

> Install the extension, browse any target through Burp Proxy, and findings appear automatically.

```
SCBurpScan tab layout:

┌──────────────────────┬───────────────────────────────────────────┐
│  Issues              │  [Advisory]  [Request]  [Response]        │
│  ─────────────────   │                                           │
│  # Sev  Host  Rule   │  ┌─ HIGH ──┐  ┌─ PASSIVE ──┐            │
│  1 HIGH …     XSS    │  Reflected XSS (Passive)                  │
│  2 LOW  …     CSP    │                                           │
│  3 MED  …     SQLi   │  Host     testphp.vulnweb.com             │
│  ...                 │  URL      https://…/search.php?q=test     │
│                      │  Method   POST                            │
│  [right-click]       │  ────────────────────────────────         │
│  Send to Repeater    │  Parameter 'q' value reflected in body    │
│  Send to Intruder    │  Evidence: …test…                         │
│  Send Req/Resp to    │                                           │
│  Comparer            │                                           │
└──────────────────────┴───────────────────────────────────────────┘
```

---

## Requirements

- Burp Suite Community or Professional (tested on 2023.x+)
- Java 17+
- `javac` in PATH (for building from source)

---

## Installation

### Option A — Build from source

```bash
git clone https://github.com/yourname/scburpscan.git
cd scburpscan
bash build.sh
```

Output: `build/libs/scburpscan.jar`

Then in Burp Suite:
1. **Extensions → Installed → Add**
2. Extension type: **Java**
3. Select `build/libs/scburpscan.jar`
4. Click **Next** → the **SCBurpScan** tab appears

### Option B — Pre-built JAR

Download `scburpscan.jar` from [Releases](../../releases) and add it directly in Burp Extensions.

---

## Usage

### Passive Scan (always active)

Every HTTP response passing through Burp Proxy is automatically analyzed. No configuration needed. Findings appear in the **Issues** table instantly.

### Active Scan (toggle required)

1. Go to the **SCBurpScan → Scanner** tab
2. Click **○ Active Scan** → turns to **● Active Scan**
3. Browse the target — each new URL will be fuzzed with payloads in the background

> ⚠️ Active scan sends additional requests to the target. Only enable on authorized targets.

### In-Scope Filter

Click **○ In-Scope Only** to restrict scanning to URLs in Burp's **Target → Scope**. Useful when browsing many sites in one session.

### Right-click Actions

Right-click any row in the Issues table:

| Menu Item | Action |
|---|---|
| Send to Repeater | Opens request in Burp Repeater for manual testing |
| Send to Intruder | Opens request in Burp Intruder for payload-based fuzzing |
| Send Request to Comparer | Sends raw request bytes to Comparer |
| Send Response to Comparer | Sends raw response bytes to Comparer |

---

## Built-in Rules

### Passive Rules (always-on)

| Rule | Severity | What it detects |
|---|---|---|
| Reflected XSS (Passive) | HIGH | Parameter values reflected verbatim in response body |
| SQL Injection (Passive) | HIGH | SQL error messages from MySQL, MSSQL, PostgreSQL, Oracle, SQLite |
| Open Redirect (Passive) | MEDIUM | Redirect params pointing to external domains; external `Location` headers |
| SSRF (Passive) | HIGH / MEDIUM | URL-like params pointing to internal IPs or arbitrary URLs |
| Sensitive Info Disclosure | HIGH–LOW | AWS keys, Google API keys, JWTs, private keys, stack traces, generic secrets |
| Missing Security Headers | LOW | Absence of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy |

### Active Rules (toggle required)

| Rule | Severity | Technique |
|---|---|---|
| Reflected XSS (Active) | HIGH | Injects 6 XSS payloads per param; checks if reflected unencoded |
| SQL Injection – Error Based | HIGH | Injects `'`, `"`, `OR 1=1` style payloads; detects DB error messages |
| SQL Injection – Time Based | HIGH | Injects `SLEEP`/`WAITFOR`/`pg_sleep` for MySQL, MSSQL, PostgreSQL, Oracle; flags if response delayed ≥ baseline + 4 s |
| SQL Injection – Boolean Based | HIGH | Injects TRUE/FALSE condition pairs; flags if response body or status differs significantly |
| Path Traversal (Active) | HIGH | Injects `../../../../etc/passwd` and Windows `win.ini` variants; checks file contents in response |

---

## Custom Rules

Custom rules are JSON files loaded from a user-configured folder — **no recompile needed**.

### Setup

1. Go to **SCBurpScan → Settings** tab
2. Enter (or Browse) a folder path
3. Click **Write Templates** — example files are written to the folder
4. Edit the template files, rename them (remove the `_template` prefix)
5. Click **Reload Rules** — rules load instantly, no Burp restart required

The folder path is saved between Burp sessions automatically.

### Rule File Format

```json
{
  "name": "My Rule Name",
  "severity": "HIGH",
  "description": "What this rule detects (shown in Advisory panel)",

  "passive": {
    "bodyPatterns":   ["java-regex-1", "java-regex-2"],
    "headerPatterns": ["Header-Name: java-regex"],
    "paramReflection": false
  },

  "active": {
    "payloads":          ["payload1", "payload2"],
    "appendToValue":     false,
    "detectInBody":      ["java-regex"],
    "detectInHeaders":   ["Header-Name: java-regex"],
    "detectStatusCode":  500
  }
}
```

#### Field Reference

**Top level**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | ✓ | Display name in findings table |
| `severity` | string | ✓ | `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `description` | string | | Text shown in Advisory panel |
| `passive` | object | at least one | Passive check config |
| `active` | object | at least one | Active check config |

**`passive` section**

| Field | Type | Description |
|---|---|---|
| `bodyPatterns` | string[] | Java regex matched against full response body |
| `headerPatterns` | string[] | Format `"Header-Name: regex"` matched against response headers |
| `paramReflection` | boolean | Flag if any param value (≥4 chars) appears verbatim in response |

**`active` section**

| Field | Type | Description |
|---|---|---|
| `payloads` | string[] | Values to inject into each parameter |
| `appendToValue` | boolean | `true` = append to existing value; `false` = replace entirely |
| `detectInBody` | string[] | Java regex matched against fuzzed response body |
| `detectInHeaders` | string[] | Format `"Header-Name: regex"` matched against fuzzed response headers |
| `detectStatusCode` | int | Trigger if response HTTP status equals this value (`0` = disabled) |

#### Examples

**Passive — detect debug info:**
```json
{
  "name": "Debug Mode Exposed",
  "severity": "MEDIUM",
  "description": "Application debug information is visible in the response.",
  "passive": {
    "bodyPatterns": [
      "(?i)debug\\s*=\\s*true",
      "(?i)Traceback \\(most recent call",
      "(?i)Fatal error:.*on line \\d+"
    ]
  }
}
```

**Active — custom XSS payloads:**
```json
{
  "name": "Custom XSS Probes",
  "severity": "HIGH",
  "description": "Tests additional XSS payloads for WAF bypass.",
  "active": {
    "payloads": [
      "<img/src=x onerror=confirm(document.domain)>",
      "<details open ontoggle=alert(1)>"
    ],
    "appendToValue": false,
    "detectInBody": ["onerror=confirm", "ontoggle=alert"]
  }
}
```

**Combined — exposed `.git` directory:**
```json
{
  "name": "Exposed .git Directory",
  "severity": "HIGH",
  "description": "Git metadata is publicly accessible.",
  "passive": {
    "bodyPatterns": ["ref: refs/heads/"]
  },
  "active": {
    "payloads": ["/.git/HEAD", "/../.git/HEAD"],
    "appendToValue": false,
    "detectInBody": ["ref: refs/heads/"]
  }
}
```

> **Regex tip:** In JSON, backslashes must be escaped. `\d+` becomes `"\\d+"`. Test at [regex101.com](https://regex101.com) with the **Java 8** flavor.

---

## Project Structure

```
scburpscan/
├── build.sh                                    # Build script (no Gradle install needed)
├── build.gradle / settings.gradle             # Gradle config (optional)
├── libs/                                       # montoya-api + gson JARs (auto-downloaded)
└── src/main/java/com/scburpscan/
    ├── BurpScanExtension.java                  # Entry point
    ├── HttpScanHandler.java                    # Intercepts Burp HTTP traffic
    ├── ScanEngine.java                         # Orchestrates rules, dedup, threading
    ├── ScanRule.java                           # Interface all rules implement
    ├── ActiveRequester.java                    # Callback for active rules to send requests
    ├── FindingEntry.java                       # Data model for each finding
    ├── CustomRule.java                         # Runtime rule built from JSON config
    ├── CustomRuleConfig.java                   # POJO mapped from JSON files
    ├── CustomRuleLoader.java                   # Loads/validates JSON rule files
    ├── HttpUtil.java                           # Helper: HttpRequest/Response → raw string
    ├── ScannerTab.java                         # Main UI (issues table + advisory panel)
    ├── SettingsPanel.java                      # Settings UI (custom rules folder)
    └── rules/
        ├── XssPassiveRule.java                 # Reflected XSS detection
        ├── XssActiveRule.java                  # XSS fuzzing
        ├── SqliPassiveRule.java                # SQL error detection
        ├── SqliActiveRule.java                 # SQLi error-based fuzzing
        ├── SqliTimeBasedRule.java              # Blind SQLi — time-based
        ├── SqliBooleanBasedRule.java           # Blind SQLi — boolean-based
        ├── OpenRedirectPassiveRule.java        # Open redirect detection
        ├── SsrfPassiveRule.java                # SSRF parameter detection
        ├── SensitiveInfoPassiveRule.java       # Secrets/tokens/stack traces
        ├── SecurityHeadersPassiveRule.java     # Missing security headers
        └── PathTraversalActiveRule.java        # Directory traversal fuzzing
```

---

## Building

```bash
bash build.sh
```

The script:
1. Checks for `javac` (offers install hint if missing)
2. Downloads `montoya-api-2023.12.1.jar` and `gson-2.10.1.jar` if not in `libs/`
3. Compiles all sources
4. Packages a fat JAR (Gson embedded) at `build/libs/scburpscan.jar`

---

## Limitations & Notes

- **Community Edition only** — uses the public Montoya Extension API, no Pro-only APIs
- **Active scan is intentionally conservative** — thread pool of 4, one confirmed finding per parameter to reduce noise
- **Time-based SQLi threshold** — baseline measured from 2 requests; trigger requires response ≥ baseline + 4 000 ms. High-latency targets may produce false positives — adjust `THRESHOLD_MS` in `SqliTimeBasedRule.java`
- **Boolean-based SQLi** requires response body or status to differ by ≥ 50 bytes or 5% between TRUE/FALSE conditions
- **Custom rules are reloaded live** — no Burp restart needed after editing JSON files

---

## Related Projects

- **[SCBurpLogs](../scburplog/)** — Save and restore full Burp HTTP session history (the companion extension)

---

## License

MIT
