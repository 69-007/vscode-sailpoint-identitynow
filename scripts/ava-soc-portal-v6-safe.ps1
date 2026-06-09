#requires -Version 5.1
<#
AVA SOC PORTAL V6 SAFE EDITION
Lokal / Defensiv / Read-Only

Keine Angriffe
Keine Exploits
Keine Fremdscans
Keine automatische Ausbreitung
Keine Änderungen am System

Funktionen:
- Host / MAC / IP Monitoring
- WLAN / LAN Neighbor Sicht
- Baseline + Delta Detection
- Timeline JSONL
- Risk Score
- Tangle Hash Chain
- HTML Security Dashboard
#>

param(
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function Get-OutputBaseDirectory {
    param([string]$RequestedDirectory)

    if (-not [string]::IsNullOrWhiteSpace($RequestedDirectory)) {
        return $RequestedDirectory
    }

    $desktop = [Environment]::GetFolderPath("Desktop")
    if (-not [string]::IsNullOrWhiteSpace($desktop) -and (Test-Path -LiteralPath $desktop)) {
        return $desktop
    }

    return [IO.Path]::GetTempPath()
}

$Now = Get-Date -Format "yyyyMMdd_HHmmss"
$OutBase = Get-OutputBaseDirectory -RequestedDirectory $OutputDirectory
$Root = Join-Path $OutBase "AVA_SOC_PORTAL_V6_SAFE"
$LogDir = Join-Path $Root "Logs"
$StateDir = Join-Path $Root "State"
$ReportDir = Join-Path $Root "Reports"

$SnapshotJson = Join-Path $ReportDir "snapshot_latest.json"
$AnalysisJson = Join-Path $ReportDir "analysis_latest.json"
$PortalHtml = Join-Path $ReportDir "ava_soc_portal_v6_safe.html"
$TimelineLog = Join-Path $LogDir "ava_v6_timeline.jsonl"
$AlertLog = Join-Path $LogDir "ava_v6_alerts.jsonl"
$TangleLog = Join-Path $LogDir "ava_v6_tangle.jsonl"
$TangleState = Join-Path $StateDir "tangle_state.json"
$BaselinePath = Join-Path $StateDir "baseline.json"

$RiskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)

foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }
}

function H {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Sha256Text {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Write-JsonLine {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 30 -Compress | Add-Content -LiteralPath $Path -Encoding UTF8
}

function New-TimelineEvent {
    param([string]$Category, [string]$Title, [string]$Message, [string]$Severity, [object]$Data)
    Write-JsonLine -Path $TimelineLog -Object ([ordered]@{
            time = (Get-Date).ToString("o")
            category = $Category
            title = $Title
            message = $Message
            severity = $Severity
            data = $Data
        })
}

function Add-Alert {
    param([string]$Severity, [string]$Title, [string]$Message, [int]$Score, [object]$Data)
    $alert = [ordered]@{
        time = (Get-Date).ToString("o")
        severity = $Severity
        title = $Title
        message = $Message
        score = $Score
        data = $Data
    }
    Write-JsonLine -Path $AlertLog -Object $alert
    New-TimelineEvent -Category "Alert" -Title $Title -Message $Message -Severity $Severity -Data $Data
    $alert
}

function Write-Tangle {
    param([string]$Type, [string]$Summary, [object]$Data)
    $prev = $null
    if (Test-Path -LiteralPath $TangleState) {
        try { $prev = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash } catch {}
    }

    $event = [ordered]@{
        time = (Get-Date).ToString("o")
        computer = $env:COMPUTERNAME
        user = $env:USERNAME
        type = $Type
        summary = $Summary
        previous_hash = $prev
        data = $Data
    }

    $raw = $event | ConvertTo-Json -Depth 30 -Compress
    $hash = Sha256Text $raw
    $event["hash"] = $hash
    Write-JsonLine -Path $TangleLog -Object $event

    [pscustomobject]@{ updated = (Get-Date).ToString("o"); last_hash = $hash } |
        ConvertTo-Json | Set-Content -LiteralPath $TangleState -Encoding UTF8
}

function Get-WlanNetworksSafe {
    try {
        $raw = netsh wlan show networks mode=bssid 2>&1 | Out-String
    }
    catch {
        return @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $items = New-Object System.Collections.Generic.List[object]
    $ssid = $null
    $auth = $null
    $enc = $null

    foreach ($line in ($raw -split "`r?`n")) {
        $l = $line.Trim()
        if ($l -match "^SSID\s+\d+\s+:\s+(.*)$") {
            $ssid = $Matches[1]
            $auth = $null
            $enc = $null
        }
        elseif ($l -match "^Authentication\s+:\s+(.*)$") { $auth = $Matches[1] }
        elseif ($l -match "^Encryption\s+:\s+(.*)$") { $enc = $Matches[1] }
        elseif ($l -match "^BSSID\s+\d+\s+:\s+(.*)$") {
            $items.Add([pscustomobject]@{ SSID = $ssid; BSSID = $Matches[1]; Authentication = $auth; Encryption = $enc; Signal = $null; Channel = $null }) | Out-Null
        }
        elseif ($l -match "^Signal\s+:\s+(.*)$") { if ($items.Count -gt 0) { $items[$items.Count - 1].Signal = $Matches[1] } }
        elseif ($l -match "^Channel\s+:\s+(.*)$") { if ($items.Count -gt 0) { $items[$items.Count - 1].Channel = $Matches[1] } }
    }

    $items
}

function New-Snapshot {
    [ordered]@{
        time = (Get-Date).ToString("o")
        computer = $env:COMPUTERNAME
        user = $env:USERNAME
        mode = "LOCAL_DEFENSIVE_READ_ONLY"
        defender = try { Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AntivirusSignatureLastUpdated } catch { [pscustomobject]@{ Error = $_.Exception.Message } }
        firewall = try { Get-NetFirewallProfile | Select-Object Name, Enabled } catch { @([pscustomobject]@{ Error = $_.Exception.Message }) }
        adapters = try { Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed } catch { @([pscustomobject]@{ Error = $_.Exception.Message }) }
        neighbors = try { Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne "Unreachable" } | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State } catch { @([pscustomobject]@{ Error = $_.Exception.Message }) }
        wlan = Get-WlanNetworksSafe
        connections = try { Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess } catch { @([pscustomobject]@{ Error = $_.Exception.Message }) }
        processes = try { Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine } catch { @([pscustomobject]@{ Error = $_.Exception.Message }) }
        services = try { Get-CimInstance Win32_Service | Where-Object State -eq "Running" | Select-Object Name, StartMode, StartName } catch { @([pscustomobject]@{ Error = $_.Exception.Message }) }
        tasks = try { Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object TaskName, TaskPath, State } catch { @([pscustomobject]@{ Error = $_.Exception.Message }) }
    }
}

function Load-Baseline {
    if (Test-Path -LiteralPath $BaselinePath) {
        try { return Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json } catch { return $null }
    }
    $null
}

function Save-Baseline {
    param([object]$Snapshot)
    $Snapshot | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $BaselinePath -Encoding UTF8
}

function Analyze-Snapshot {
    param([object]$Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]
    $score = 0

    if ($Snapshot.defender.RealTimeProtectionEnabled -eq $false) {
        $score += 100
        $alerts.Add((Add-Alert "CRITICAL" "Defender Echtzeitschutz deaktiviert" "Windows Defender Echtzeitschutz ist aus." 100 $Snapshot.defender)) | Out-Null
    }

    foreach ($fw in @($Snapshot.firewall)) {
        if ($fw.Enabled -eq $false) {
            $score += 80
            $alerts.Add((Add-Alert "HIGH" "Firewall deaktiviert" "Firewall-Profil deaktiviert: $($fw.Name)" 80 $fw)) | Out-Null
        }
    }

    foreach ($c in @($Snapshot.connections)) {
        if ($null -ne $c.RemotePort -and ($RiskPorts -contains [int]$c.RemotePort)) {
            $s = if ([int]$c.RemotePort -in @(445, 3389, 5985, 5986)) { 75 } else { 45 }
            $sev = if ($s -eq 75) { "HIGH" } else { "MEDIUM" }
            $score += $s
            $alerts.Add((Add-Alert $sev "Risiko-Port Verbindung" "$($c.RemoteAddress):$($c.RemotePort)" $s $c)) | Out-Null
        }
    }

    $baseline = Load-Baseline
    $delta = [ordered]@{ baseline_exists = $null -ne $baseline; new_neighbors = @(); new_wlan_bssid = @(); new_processes = @(); new_services = @(); new_tasks = @() }

    if ($null -eq $baseline) {
        Save-Baseline $Snapshot
        New-TimelineEvent "Baseline" "Baseline erstellt" "Erster Snapshot wurde als Baseline gespeichert." "INFO" $null
    }
    else {
        $oldNeighbors = @($baseline.neighbors | ForEach-Object { "$($_.IPAddress)|$($_.LinkLayerAddress)" })
        foreach ($n in @($Snapshot.neighbors)) { if ($n.IPAddress -and ($oldNeighbors -notcontains "$($n.IPAddress)|$($n.LinkLayerAddress)")) { $delta.new_neighbors += $n; $score += 20 } }

        $oldBssid = @($baseline.wlan | ForEach-Object { $_.BSSID })
        foreach ($w in @($Snapshot.wlan)) { if ($w.BSSID -and ($oldBssid -notcontains $w.BSSID)) { $delta.new_wlan_bssid += $w; $score += 10 } }

        $oldProc = @($baseline.processes | ForEach-Object { $_.Name } | Sort-Object -Unique)
        foreach ($p in @($Snapshot.processes)) { if ($p.Name -and ($oldProc -notcontains $p.Name)) { $delta.new_processes += $p.Name; $score += 5 } }

        $oldServices = @($baseline.services | ForEach-Object { $_.Name })
        foreach ($s in @($Snapshot.services)) { if ($s.Name -and ($oldServices -notcontains $s.Name)) { $delta.new_services += $s; $score += 20 } }

        $oldTasks = @($baseline.tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
        foreach ($t in @($Snapshot.tasks)) { if ($t.TaskName -and ($oldTasks -notcontains "$($t.TaskPath)$($t.TaskName)")) { $delta.new_tasks += $t; $score += 25 } }

        if (@($delta.new_neighbors).Count -gt 0) { New-TimelineEvent "Delta" "Neue LAN-Nachbarn" "$(@($delta.new_neighbors).Count) neue Nachbarn seit Baseline." "WARN" $delta.new_neighbors }
        if (@($delta.new_wlan_bssid).Count -gt 0) { New-TimelineEvent "Delta" "Neue WLAN-BSSID" "$(@($delta.new_wlan_bssid).Count) neue WLAN-BSSID seit Baseline." "INFO" $delta.new_wlan_bssid }
    }

    [ordered]@{ time = (Get-Date).ToString("o"); score = [Math]::Min($score, 999); alert_count = @($alerts).Count; alerts = $alerts; delta = $delta }
}

function Build-Portal {
    param([object]$Snapshot, [object]$Analysis)

    $score = [int]$Analysis.score
    $health = if ($score -ge 500) { "CRITICAL" } elseif ($score -ge 300) { "HIGH" } elseif ($score -ge 150) { "WARN" } else { "OK" }
    $lastHash = "N/A"
    if (Test-Path -LiteralPath $TangleState) { try { $lastHash = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash } catch {} }

    $alertRows = foreach ($a in @($Analysis.alerts)) {
        "<tr><td>$(H $a.time)</td><td>$(H $a.severity)</td><td>$(H $a.title)</td><td>$(H $a.message)</td><td>$(H $a.score)</td></tr>"
    }
    if (-not $alertRows) { $alertRows = '<tr><td colspan="5">Keine Alerts gefunden.</td></tr>' }

    $timelineRows = if (Test-Path -LiteralPath $TimelineLog) {
        Get-Content -LiteralPath $TimelineLog -Tail 100 | ForEach-Object {
            $t = $_ | ConvertFrom-Json
            "<tr><td>$(H $t.time)</td><td>$(H $t.category)</td><td>$(H $t.severity)</td><td>$(H $t.title)</td><td>$(H $t.message)</td></tr>"
        }
    }
    if (-not $timelineRows) { $timelineRows = '<tr><td colspan="5">Noch keine Timeline Events.</td></tr>' }

    $html = @"
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8" />
<title>AVA SOC PORTAL V6 SAFE</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #0f172a; color: #e2e8f0; }
.card { background: #111827; border: 1px solid #334155; border-radius: 10px; padding: 14px; margin-bottom: 14px; }
.badge { display:inline-block;padding:4px 10px;border-radius:12px;background:#1e293b;font-weight:700; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #334155; text-align: left; padding: 6px; vertical-align: top; }
th { background: #1e293b; }
small { color: #94a3b8; }
</style>
</head>
<body>
<div class="card">
  <h1>AVA SOC PORTAL V6 SAFE EDITION</h1>
  <p><strong>Host:</strong> $(H $Snapshot.computer) | <strong>User:</strong> $(H $Snapshot.user)</p>
  <p><strong>Score:</strong> $(H $score) | <strong>Health:</strong> <span class="badge">$(H $health)</span></p>
  <p><strong>Alert Count:</strong> $(H $Analysis.alert_count) | <strong>Tangle Last Hash:</strong> <small>$(H $lastHash)</small></p>
</div>

<div class="card">
  <h2>Alerts</h2>
  <table><thead><tr><th>Time</th><th>Severity</th><th>Title</th><th>Message</th><th>Score</th></tr></thead><tbody>
  $($alertRows -join "`n")
  </tbody></table>
</div>

<div class="card">
  <h2>Timeline (letzte 100)</h2>
  <table><thead><tr><th>Time</th><th>Category</th><th>Severity</th><th>Title</th><th>Message</th></tr></thead><tbody>
  $($timelineRows -join "`n")
  </tbody></table>
</div>
</body>
</html>
"@

    $html | Set-Content -LiteralPath $PortalHtml -Encoding UTF8
}

$snapshot = New-Snapshot
$snapshot | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $SnapshotJson -Encoding UTF8
$analysis = Analyze-Snapshot -Snapshot $snapshot
$analysis | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $AnalysisJson -Encoding UTF8

Write-Tangle -Type "snapshot" -Summary "Snapshot + Analyse erstellt" -Data ([ordered]@{ snapshot = $SnapshotJson; analysis = $AnalysisJson; score = $analysis.score; alert_count = $analysis.alert_count })
Build-Portal -Snapshot $snapshot -Analysis $analysis

Write-Output "AVA SOC PORTAL V6 SAFE abgeschlossen"
Write-Output "Snapshot: $SnapshotJson"
Write-Output "Analysis: $AnalysisJson"
Write-Output "Portal: $PortalHtml"
