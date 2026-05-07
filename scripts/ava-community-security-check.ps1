#requires -Version 5.1
<#
AVA COMMUNITY SECURITY CHECK v1
Ehrenamtlich / Respektvoll / Gesellschaftlich wertvoll
Lokal / Read-Only / Keine Angriffe / Keine Änderungen

Ziel:
- Kleine Vereine, Familien, Ehrenamt, Kleinbetriebe unterstützen
- Sicherheitsbasis sichtbar machen
- Verständlicher HTML-Report
- Keine Daten an Dritte
- Keine fremden Systeme scannen
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$Now = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir = Join-Path ([Environment]::GetFolderPath("Desktop")) "AVA_COMMUNITY_SECURITY_CHECK_$Now"
$ReportHtml = Join-Path $OutDir "ava_community_security_report.html"
$ReportTxt = Join-Path $OutDir "ava_community_security_report.txt"
$ReportJson = Join-Path $OutDir "ava_community_security_report.json"
$SuspiciousPowerShellFlags = @("-enc", "encodedcommand", "bypass", "downloadstring", "iex", "invoke-expression", "-nop", "hidden")
$RiskyPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986) # FTP, Telnet, RPC, NetBIOS, SMB, RDP, WinRM HTTP, WinRM HTTPS
$PowerShellMetaPropertyNames = @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")
$CriticalPenalty = 25
$WarnPenalty = 7
$ScoreVeryStableThreshold = 85
$ScoreSolidThreshold = 65
$ScoreNeedsImprovementThreshold = 40
$MaxRecentHotfixes = 5

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Category,
        [string]$Status,
        [string]$Title,
        [string]$Message,
        [string]$Recommendation
    )

    $Results.Add([pscustomobject]@{
            Time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Category = $Category
            Status = $Status
            Title = $Title
            Message = $Message
            Recommendation = $Recommendation
        })
}

function ConvertTo-HtmlEncodedString {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

# =========================
# SYSTEMBASIS
# =========================
try {
    $os = $null
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Result "System" "INFO" "Betriebssystem" `
        "$($os.Caption) | Version: $($os.Version) | Build: $($os.BuildNumber)" `
        "System regelmäßig aktualisieren und alte Geräte dokumentieren."
}
catch {
    Add-Result "System" "WARN" "Betriebssystem konnte nicht gelesen werden" "$($_.Exception.Message)" "PowerShell als normaler Benutzer reicht meist, Admin erhöht die Details."
}

try {
    if ($null -ne $os -and $os.LastBootUpTime) {
        $uptime = (Get-Date) - $os.LastBootUpTime
        Add-Result "System" "INFO" "Laufzeit seit Neustart" `
            ("{0} Tage, {1} Stunden" -f [int]$uptime.TotalDays, $uptime.Hours) `
            "Sehr lange Laufzeiten können Updates blockieren. Gelegentlich sauber neu starten."
    }
}
catch {}

# =========================
# DEFENDER / ANTIVIRUS
# =========================
try {
    $mp = Get-MpComputerStatus

    if ($mp.RealTimeProtectionEnabled) {
        Add-Result "Schutz" "OK" "Microsoft Defender Echtzeitschutz" "Aktiv" "Sehr gut. Echtzeitschutz aktiviert lassen."
    }
    else {
        Add-Result "Schutz" "CRITICAL" "Microsoft Defender Echtzeitschutz" "Nicht aktiv" "Echtzeitschutz prüfen und aktivieren."
    }

    if ($mp.AntivirusSignatureLastUpdated) {
        Add-Result "Schutz" "INFO" "Defender Signaturen" `
            "Letztes Update: $($mp.AntivirusSignatureLastUpdated)" `
            "Signaturen sollten regelmäßig aktualisiert werden."
    }

}
catch {
    Add-Result "Schutz" "WARN" "Defender Status nicht verfügbar" `
        "$($_.Exception.Message)" `
        "Falls ein anderes Antivirus aktiv ist, dort Schutzstatus prüfen."
}

# =========================
# FIREWALL
# =========================
try {
    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        if ($p.Enabled) {
            Add-Result "Firewall" "OK" "Firewall Profil: $($p.Name)" "Aktiv" "Firewall aktiv lassen."
        }
        else {
            Add-Result "Firewall" "CRITICAL" "Firewall Profil: $($p.Name)" "Nicht aktiv" "Firewall-Profil prüfen und aktivieren."
        }
    }
}
catch {
    Add-Result "Firewall" "WARN" "Firewall Status nicht lesbar" "$($_.Exception.Message)" "Mit Adminrechten erneut prüfen."
}

# =========================
# REMOTE ZUGRIFFE
# =========================
try {
    $rdp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop
    if ($rdp.fDenyTSConnections -eq 1) {
        Add-Result "Remote Zugriff" "OK" "Remote Desktop" "RDP ist deaktiviert" "Gut für normale Vereins-/Büro-PCs."
    }
    else {
        Add-Result "Remote Zugriff" "WARN" "Remote Desktop" "RDP ist aktiviert" "Nur aktiv lassen, wenn wirklich benötigt. Starke Passwörter und VPN verwenden."
    }
}
catch {
    Add-Result "Remote Zugriff" "INFO" "Remote Desktop" "Status konnte nicht gelesen werden" "Bei Bedarf manuell prüfen."
}

try {
    $winrm = Get-Service WinRM -ErrorAction Stop
    if ($winrm.Status -eq "Running") {
        Add-Result "Remote Zugriff" "WARN" "WinRM Dienst" "WinRM läuft" "Nur für verwaltete Systeme aktiv lassen."
    }
    else {
        Add-Result "Remote Zugriff" "OK" "WinRM Dienst" "WinRM läuft nicht" "Für normale Clients meist sinnvoll."
    }
}
catch {}

# =========================
# LOKALE ADMINISTRATOREN
# =========================
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    foreach ($a in $admins) {
        Add-Result "Konten" "INFO" "Lokaler Administrator" `
            "$($a.Name) | $($a.ObjectClass)" `
            "Adminrechte regelmäßig prüfen. Nur notwendige Personen sollten Admin sein."
    }

    if ($admins.Count -gt 3) {
        Add-Result "Konten" "WARN" "Viele lokale Administratoren" `
            "$($admins.Count) Administrator-Einträge gefunden" `
            "Für Vereine/Kleinbetriebe: Adminrechte sparsam vergeben."
    }
}
catch {
    Add-Result "Konten" "WARN" "Administratoren konnten nicht gelesen werden" "$($_.Exception.Message)" "Mit Adminrechten erneut ausführen."
}

# =========================
# AUTOSTART
# =========================
try {
    $startupPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty $path
            $props = $items.PSObject.Properties | Where-Object {
                $_.Name -notin $PowerShellMetaPropertyNames
            }

            foreach ($prop in $props) {
                Add-Result "Autostart" "INFO" "Autostart Eintrag" `
                    "$($prop.Name): $($prop.Value)" `
                    "Unbekannte Autostarts prüfen, aber nichts vorschnell löschen."
            }
        }
    }
}
catch {
    Add-Result "Autostart" "WARN" "Autostart konnte nicht geprüft werden" "$($_.Exception.Message)" "Manuell im Task-Manager prüfen."
}

# =========================
# AUFFÄLLIGE POWERSHELL PROZESSE
# =========================
try {
    # $PID ist kein nutzbarer Wert in WMI-Filterstrings, daher Ausschluss des aktuellen Prozesses nachgelagert.
    $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" | Where-Object {
        $_.ProcessId -ne $PID
    }

    if ($procs) {
        foreach ($p in $procs) {
            $cmd = "$($p.CommandLine)"
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
            $lower = $cmd.ToLowerInvariant()
            $hits = @()

            foreach ($f in $SuspiciousPowerShellFlags) {
                if ($lower.Contains($f)) { $hits += $f }
            }

            if ($hits.Count -gt 0) {
                Add-Result "Prozesse" "WARN" "Auffälliger PowerShell Prozess" `
                    "PID $($p.ProcessId) | Treffer: $($hits -join ', ') | $cmd" `
                    "Prüfen, ob dieser Prozess zu einem legitimen Admin-/Updatevorgang gehört."
            }
        }
    }
    else {
        Add-Result "Prozesse" "OK" "PowerShell Prozesse" "Keine weiteren PowerShell-Prozesse gefunden" "Gut."
    }
}
catch {
    Add-Result "Prozesse" "WARN" "Prozessprüfung fehlgeschlagen" "$($_.Exception.Message)" "Später erneut prüfen."
}

# =========================
# NETZWERK - NUR LOKAL, KEIN SCAN
# =========================
try {
    $connections = Get-NetTCPConnection -State Established -ErrorAction Stop

    foreach ($c in $connections) {
        if ($c.RemotePort -in $RiskyPorts) {
            Add-Result "Netzwerk" "WARN" "Verbindung zu sensiblem Port" `
                "Local: $($c.LocalAddress):$($c.LocalPort) -> Remote: $($c.RemoteAddress):$($c.RemotePort)" `
                "Nur prüfen. Nicht jede Verbindung ist gefährlich, aber sensible Ports verdienen Aufmerksamkeit."
        }
    }

    Add-Result "Netzwerk" "INFO" "Aktive TCP-Verbindungen" `
        "$($connections.Count) etablierte Verbindungen gefunden" `
        "Nur lokale Sicht. Kein Fremdscan wurde durchgeführt."
}
catch {
    Add-Result "Netzwerk" "WARN" "Netzwerkverbindungen konnten nicht gelesen werden" "$($_.Exception.Message)" "Mit Adminrechten erneut prüfen."
}

# =========================
# WINDOWS UPDATE HINWEIS
# =========================
try {
    $hotfixes = Get-HotFix | Sort-Object @{
        Expression = { if ($_.InstalledOn) { $_.InstalledOn } else { [datetime]::MinValue } }
        Descending = $true
    } | Select-Object -First $MaxRecentHotfixes
    foreach ($h in $hotfixes) {
        $installedOnText = if ($h.InstalledOn) { $h.InstalledOn } else { "Unbekannt" }
        Add-Result "Updates" "INFO" "Installiertes Update" `
            "$($h.HotFixID) | Installiert am: $installedOnText" `
            "Updates regelmäßig prüfen."
    }
}
catch {
    Add-Result "Updates" "INFO" "Updates" "Hotfix-Liste konnte nicht gelesen werden" "Windows Update manuell prüfen."
}

# =========================
# RISIKO-SCORE
# =========================
$critical = ($Results | Where-Object Status -eq "CRITICAL").Count
$warn = ($Results | Where-Object Status -eq "WARN").Count

$Score = 100 - ($critical * $CriticalPenalty) - ($warn * $WarnPenalty)
if ($Score -lt 0) { $Score = 0 }

$ScoreText = if ($Score -ge $ScoreVeryStableThreshold) {
    "Sehr stabil"
}
elseif ($Score -ge $ScoreSolidThreshold) {
    "Solide, aber prüfenswert"
}
elseif ($Score -ge $ScoreNeedsImprovementThreshold) {
    "Verbesserungsbedarf"
}
else {
    "Dringend prüfen"
}

# =========================
# EXPORT JSON / TXT
# =========================
$Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportJson -Encoding UTF8

$txt = @()
$txt += "AVA COMMUNITY SECURITY CHECK v1"
$txt += "Zeit: $(Get-Date)"
$txt += "Computer: $env:COMPUTERNAME"
$txt += "Benutzer: $env:USERNAME"
$txt += "Score: $Score / 100 - $ScoreText"
$txt += ""
$txt += "Leitsatz:"
$txt += "Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle."
$txt += ""
foreach ($r in $Results) {
    $txt += "[$($r.Status)] $($r.Category) - $($r.Title)"
    $txt += "  $($r.Message)"
    $txt += "  Empfehlung: $($r.Recommendation)"
    $txt += ""
}
$txt -join "`r`n" | Out-File -FilePath $ReportTxt -Encoding UTF8

# =========================
# HTML REPORT
# =========================
$rows = foreach ($r in $Results) {
    $color = switch ($r.Status) {
        "OK" { "#1f8f4d" }
        "INFO" { "#2f6fed" }
        "WARN" { "#d68a00" }
        "CRITICAL" { "#c62828" }
        default { "#777777" }
    }

    @"
<tr>
  <td>$(ConvertTo-HtmlEncodedString $r.Time)</td>
  <td>$(ConvertTo-HtmlEncodedString $r.Category)</td>
  <td><span style="font-weight:700;color:$color;">$(ConvertTo-HtmlEncodedString $r.Status)</span></td>
  <td>$(ConvertTo-HtmlEncodedString $r.Title)</td>
  <td>$(ConvertTo-HtmlEncodedString $r.Message)</td>
  <td>$(ConvertTo-HtmlEncodedString $r.Recommendation)</td>
</tr>
"@
}

$html = @"
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <title>AVA Community Security Check</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #f8fafc; color: #0f172a; }
    .card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .score { font-size: 22px; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; background: #ffffff; }
    th, td { border: 1px solid #e2e8f0; text-align: left; padding: 8px; vertical-align: top; }
    th { background: #f1f5f9; }
    .muted { color: #475569; }
  </style>
</head>
<body>
  <div class="card">
    <h1>AVA COMMUNITY SECURITY CHECK v1</h1>
    <p class="muted">Lokal / Read-Only / Keine Angriffe / Keine Änderungen</p>
    <p><strong>Zeit:</strong> $(ConvertTo-HtmlEncodedString (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))</p>
    <p><strong>Computer:</strong> $(ConvertTo-HtmlEncodedString $env:COMPUTERNAME)</p>
    <p><strong>Benutzer:</strong> $(ConvertTo-HtmlEncodedString $env:USERNAME)</p>
    <p class="score">Score: $(ConvertTo-HtmlEncodedString "$Score") / 100 - $(ConvertTo-HtmlEncodedString $ScoreText)</p>
    <p><em>Leitsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.</em></p>
  </div>

  <div class="card">
    <h2>Ergebnisse</h2>
    <table>
      <thead>
        <tr>
          <th>Zeit</th>
          <th>Kategorie</th>
          <th>Status</th>
          <th>Titel</th>
          <th>Meldung</th>
          <th>Empfehlung</th>
        </tr>
      </thead>
      <tbody>
        $($rows -join "`n")
      </tbody>
    </table>
  </div>
</body>
</html>
"@

$html | Out-File -FilePath $ReportHtml -Encoding UTF8

Write-Host ""
Write-Host "AVA COMMUNITY SECURITY CHECK abgeschlossen." -ForegroundColor Green
Write-Host "Score: $Score / 100 - $ScoreText" -ForegroundColor Yellow
Write-Host ""
Write-Host "HTML Report:" -ForegroundColor Cyan
Write-Host $ReportHtml
Write-Host ""
Write-Host "TXT Report:" -ForegroundColor Cyan
Write-Host $ReportTxt
Write-Host ""
Write-Host "JSON Report:" -ForegroundColor Cyan
Write-Host $ReportJson
Write-Host ""
Write-Host "Leitsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle." -ForegroundColor Green

Start-Process $ReportHtml
