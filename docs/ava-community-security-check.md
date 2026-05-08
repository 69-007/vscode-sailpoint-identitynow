# AVA Community Security Check Runbook

## 1) Ownership, scope, support level

- **Owner:** SailPoint Identity Security Cloud VS Code Community Maintainers
- **Scope:** local, read-only baseline checks on the machine where the script is executed
- **Support level:** community best-effort, no official SailPoint product support

## 2) Purpose

The script (`scripts/ava-community-security-check.ps1`) helps small teams and community users get a quick, understandable baseline view of workstation security posture (Defender, firewall, remote access, startup entries, suspicious PowerShell process flags, selected network signals, update hints).

## 3) Parameters

- `-OutputDirectory <path>`
  - Optional.
  - Sets the base directory where reports are written.
  - If omitted, the script attempts Desktop and falls back to temp if Desktop is unavailable.
- `-SkipOpenReport`
  - Optional switch.
  - Prevents automatic opening of the generated HTML report.

## 4) Output artifacts and locations

Each execution creates a timestamped folder:

- `AVA_COMMUNITY_SECURITY_CHECK_yyyyMMdd_HHmmss`

Within that folder:

- `ava_community_security_report.html`
- `ava_community_security_report.txt`
- `ava_community_security_report.json`

## 5) Privacy and data handling notes

- Local execution only (no remote scanning).
- No intended data transmission to third parties.
- Sensitive values in collected text fields are redacted before report output (see redaction rules below).
- If temp fallback is used for output, the report includes a warning recommending a protected output directory.

## 6) Central redaction rules (maintained in script)

The script maintains redaction patterns centrally in `$RedactionRules` to keep masking logic consistent and reviewable.

Current rule categories:

1. Authorization / bearer token strings
2. URI embedded credentials (`scheme://user:password@...`)
3. Password segments in connection-string style data (`password=...;`)
4. Quoted secret assignments (`token: "..."`, `api_key='...'`, etc.)
5. Unquoted secret assignments (`token=abc`, `client-secret:xyz`, etc.)

## 7) Regression-test approach for redaction

Use deterministic example input/output pairs to verify masking behavior after script updates.

Recommended sample vectors:

- `Authorization eyJhbGciOi...` → `Authorization <redacted>`
- `Bearer eyJhbGciOi...` → `Bearer <redacted>`
- `https://alice:superSecret@server.local` → `https://<redacted>:<redacted>@server.local`
- `Server=.;Password=MyPass123;Trusted_Connection=False;` → `Server=.;Password=<redacted>;Trusted_Connection=False;`
- `token: "abcd-1234"` → `token=<redacted>`
- `client_secret=abcDEF123` → `client_secret=<redacted>`

Practical check options:

- Lightweight manual check in PowerShell by calling the internal redaction helper with sample lines.
- Optional automated check by asserting expected masked strings in a CI-side PowerShell test harness.

## 8) Example invocations

```powershell
# Default behavior
.\scripts\ava-community-security-check.ps1

# Store reports in a protected folder
.\scripts\ava-community-security-check.ps1 -OutputDirectory "C:\Security\AVA-Reports"

# CI/non-interactive usage (no auto-open)
.\scripts\ava-community-security-check.ps1 -SkipOpenReport

# Both options
.\scripts\ava-community-security-check.ps1 -OutputDirectory "C:\Security\AVA-Reports" -SkipOpenReport
```
