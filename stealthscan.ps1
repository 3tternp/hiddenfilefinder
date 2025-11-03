<#
StealthDetectionAuditor.ps1
Stealth Detection Auditor — deep, non-destructive enumeration for forensic triage.
- PowerShell 7+ recommended (pwsh.exe).
- Safe: Does not read raw binary contents or modify files by default.
- Paranoid Mode: enumerates C:\ but avoids aggressive binary reads that trigger AV heuristics.
- Optional: compute SHA256 hashes and run VirusTotal lookups — only enable in an isolated analysis VM.
#>

param(
    [switch]$ComputeHashes,                # OFF by default; set true only in isolated VM
    [string]$VirusTotalApiKey = "",        # optional, used only if ComputeHashes is true and you want VT lookups
    [switch]$QuarantineCopy,               # copy-only quarantine (non-destructive) - use in lab if needed
    [string]$QuarantinePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# Banner
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "   Stealth Detection Auditor (SDA)" -ForegroundColor Green
Write-Host "===================================`n" -ForegroundColor Cyan

if ($QuarantineCopy -and [string]::IsNullOrEmpty($QuarantinePath)) {
    $QuarantinePath = "$env:USERPROFILE\Desktop\SDA_Quarantine_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}

# Controls
$StartTime = Get-Date
$ReportFile = "$env:USERPROFILE\Desktop\SDA_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$Findings = [System.Collections.Generic.List[object]]::new()

function Add-Record {
    param($Type,$Name,$Location,$Details,$Score)
    $Findings.Add([PSCustomObject]@{
        Type = $Type
        Name = $Name
        Location = $Location
        Details = $Details
        Score = $Score
        SHA256 = ""
        VT = $null
    })
}

function Safe-ScoreHints {
    param($path,$isStartup)
    # Small, explainable scoring for triage only
    $score = 0
    try {
        if ($path -and (Test-Path $path)) {
            $fi = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
            if ($fi -and ($fi.Attributes -band [IO.FileAttributes]::Hidden)) { $score += 2 }
            $ext = [IO.Path]::GetExtension($path).ToLower()
            if ($ext -in '.exe','.dll','.ps1','.vbs','.bat') { $score += 1 }
            if ($isStartup) { $score += 2 }
        } else { $score += 1 }
    } catch {}
    return $score
}

# Helper: run schtasks parsing
function Get-ScheduledTasksParsed {
    try {
        $raw = schtasks /query /fo LIST /v 2>$null | Out-String
        $blocks = ($raw -split "`r?`n`r?`n") | Where-Object { $_ -match '\S' }
        foreach ($b in $blocks) {
            $name=""; $taskToRun=""; $author=""; $status=""
            foreach ($line in ($b -split "`r?`n")) {
                if ($line -match '^TaskName:\s*(.+)$') { $name = $Matches[1].Trim() }
                if ($line -match '^Task To Run:\s*(.+)$') { $taskToRun = $Matches[1].Trim() }
                if ($line -match '^Author:\s*(.+)$') { $author = $Matches[1].Trim() }
                if ($line -match '^Status:\s*(.+)$') { $status = $Matches[1].Trim() }
            }
            [PSCustomObject]@{ Name=$name; Action=$taskToRun; Author=$author; Status=$status }
        }
    } catch { return @() }
}

# Phase A: Persistence collection (registry, startup folders, scheduled tasks, services)
Write-Host "[*] Collecting persistence artifacts..." -ForegroundColor Yellow
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        if ($props) {
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match '^PS') { continue }
                $val = $p.Value -as [string]
                $exe = $null
                if ($val) {
                    $cand = ($val -split '\s+') | Where-Object { $_ -match '\.exe$|\.dll$|\.ps1$|\.bat$' }
                    if ($cand) { $exe = ($cand | Select-Object -First 1).Trim('"') }
                }
                $score = Safe-ScoreHints -path $exe -isStartup $true
                Add-Record "RegistryStartup" $p.Name $rp ("Value=$val; ScoreHints=$score") $score
            }
        }
    }
}

# Startup folders
$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($sf in $startupFolders) {
    if (Test-Path $sf) {
        Get-ChildItem -LiteralPath $sf -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
            $score = Safe-ScoreHints -path $_.FullName -isStartup $true
            Add-Record "StartupFolder" $_.Name $_.FullName ("ScoreHints=$score") $score
        }
    }
}

# Scheduled tasks
$tasks = Get-ScheduledTasksParsed
foreach ($t in $tasks) {
    $score = Safe-ScoreHints -path $t.Action -isStartup $true
    Add-Record "ScheduledTask" $t.Name $t.Action ("Author=$($t.Author); Status=$($t.Status); ScoreHints=$score") $score
}

# Services (metadata only)
try {
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $exe = $_.PathName
        $clean = $null
        if ($exe) { $clean = ($exe -replace '^[\s"]+|[\s"]+$','') -split '\s+' | Select-Object -First 1 }
        $score = Safe-ScoreHints -path $clean -isStartup $true
        Add-Record "Service" $_.Name $clean ("DisplayName=$($_.DisplayName); StartMode=$($_.StartMode); ScoreHints=$score") $score
    }
} catch {}

# Phase B: Processes & listening connections (metadata only)
Write-Host "[*] Collecting processes and network connections..." -ForegroundColor Yellow
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $pPath = $_.ExecutablePath
        $score = Safe-ScoreHints -path $pPath -isStartup $false
        Add-Record "Process" $_.Name $pPath ("PID=$($_.ProcessId); Cmd=$($_.CommandLine); ScoreHints=$score") $score
    }
} catch {}

# Listening/established network connections
try {
    Get-NetTCPConnection -State Listen,Established -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Record "NetConn" ($_.LocalAddress.ToString() + ":" + $_.LocalPort) $_.OwningProcess ("State=$($_.State); Remote=$($_.RemoteAddress):$($_.RemotePort)") 1
    }
} catch {}

# Phase C: Paranoid filesystem enumeration for metadata only (no binary read)
Write-Host "[*] Paranoid filesystem enumeration (metadata only). This can take time..." -ForegroundColor Yellow
$queue = New-Object System.Collections.Generic.Queue[string]
$queue.Enqueue("C:\")
$exts = @('.exe','.dll','.scr','.ps1','.vbs','.bat','.cmd','.js')
while ($queue.Count -gt 0) {
    $d = $queue.Dequeue()
    try {
        $files = Get-ChildItem -LiteralPath $d -Force -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            if ($exts -contains $f.Extension.ToLower()) {
                # collect metadata only — no Get-Content, no binary read
                $score = Safe-ScoreHints -path $f.FullName -isStartup $false
                Add-Record "File" $f.Name $f.FullName ("Length=$($f.Length); Created=$($f.CreationTime); ScoreHints=$score") $score
            }
        }
        $subdirs = Get-ChildItem -LiteralPath $d -Force -Directory -ErrorAction SilentlyContinue
        foreach ($sd in $subdirs) {
            try {
                if ($sd.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue } # skip junctions
                $queue.Enqueue($sd.FullName)
            } catch {}
        }
    } catch {
        # skip directories that throw (permissions/transactions)
        continue
    }
}

# Phase D: ADS detection using cmd /c dir /R on targeted areas (lightweight)
Write-Host "[*] ADS detection (targeted areas)..." -ForegroundColor Yellow
$adsTargets = @("C:\Users","C:\ProgramData","C:\Windows\Temp")
foreach ($t in $adsTargets) {
    if (-not (Test-Path $t)) { continue }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "cmd.exe"
        $psi.Arguments = "/c dir `"$t`" /S /R"
        $psi.RedirectStandardOutput = $true
        $psi.UseShellExecute = $false
        $proc = [System.Diagnostics.Process]::Start($psi)
        $reader = $proc.StandardOutput
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($line -match ':\S+:$DATA') {
                $parts = $line -split ':'
                if ($parts.Count -ge 2) {
                    $filePath = $parts[0].Trim()
                    if (-not ([System.IO.Path]::IsPathRooted($filePath))) {
                        $possible = Join-Path -Path $t -ChildPath $filePath
                        if (Test-Path $possible) { $filePath = $possible }
                    }
                    Add-Record "ADS" (Split-Path $filePath -Leaf) $filePath "Alternate Data Stream detected" 3
                }
            }
        }
        $proc.WaitForExit()
    } catch {}
}

# Phase E: Optional hashing and VirusTotal lookups (ONLY if ComputeHashes is explicit)
if ($ComputeHashes) {
    Write-Host "[*] Computing hashes for suspicious items (explicitly enabled)..." -ForegroundColor Yellow
    # compute SHA256 for top suspicious items (score >=3), do VT if API key provided
    $susp = $Findings | Where-Object { $_.Score -ge 3 } | Sort-Object -Property Score -Descending
    foreach ($it in $susp) {
        if ($it.Location -and (Test-Path $it.Location)) {
            try {
                $h = (Get-FileHash -Path $it.Location -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                if ($h) { $it.SHA256 = $h }
                if ($h -and -not [string]::IsNullOrEmpty($VirusTotalApiKey)) {
                    try {
                        $vt = Query-VirusTotal -sha256 $h
                        if ($vt) { $it.VT = $vt }
                    } catch {}
                }
                # optional quarantine copy in lab
                if ($QuarantineCopy) {
                    if (-not (Test-Path $QuarantinePath)) { New-Item -Path $QuarantinePath -ItemType Directory -Force | Out-Null }
                    $dest = Join-Path -Path $QuarantinePath -ChildPath ([IO.Path]::GetFileName($it.Location))
                    if (-not (Test-Path $dest)) { Copy-Item -LiteralPath $it.Location -Destination $dest -ErrorAction SilentlyContinue }
                    $it.Details = $it.Details + " | QuarantineCopy=$dest"
                }
            } catch {}
        }
    }
}

# Finalize: build report
Write-Host "[*] Building HTML report..." -ForegroundColor Yellow
function HtmlEncode { param($t) if ($null -eq $t) { return "" } else { return [System.Web.HttpUtility]::HtmlEncode($t) } }

$css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 14px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 6px; font-size: 12px; vertical-align: top; }
th { background: #f2f2f2; }
.high { background: #ffd6d6; }
.medium { background: #fff2cc; }
.low { background: #e6f7ff; }
pre { margin:0; white-space:pre-wrap; word-wrap:break-word; font-size:11px; }
</style>
"@

$all = $Findings.ToArray()
$susp = $all | Where-Object { $_.Score -ge 3 } | Sort-Object -Property Score -Descending
$header = @"
<h1>Stealth Detection Auditor — Paranoid Mode (Metadata-only)</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p>ComputeHashes: $($ComputeHashes)</p>
<p>VirusTotal lookups: $([bool](-not [string]::IsNullOrEmpty($VirusTotalApiKey)))</p>
<p>Total Findings: $($all.Count)</p>
<p>Potential risks (Score ≥ 3): $($susp.Count)</p>
<hr/>
"@

$tableHeader = "<table><thead><tr><th>Type</th><th>Name</th><th>Location</th><th>Score</th><th>SHA256</th><th>VT</th><th>Details</th></tr></thead><tbody>"
$rows = ""
foreach ($it in $all | Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Type';Descending=$false}) {
    $vtSummary = ""
    if ($it.VT) {
        try { $mal = $it.VT.data.attributes.last_analysis_stats; $vtSummary = "$($mal.malicious)/$($mal.undetected)" } catch { $vtSummary = "VT:unknown" }
    }
    $rows += "<tr class=''><td>$([System.Web.HttpUtility]::HtmlEncode($it.Type))</td><td>$([System.Web.HttpUtility]::HtmlEncode($it.Name))</td><td><pre>$([System.Web.HttpUtility]::HtmlEncode($it.Location))</pre></td><td>$($it.Score)</td><td><code>$([System.Web.HttpUtility]::HtmlEncode($it.SHA256))</code></td><td>$([System.Web.HttpUtility]::HtmlEncode($vtSummary))</td><td><pre>$([System.Web.HttpUtility]::HtmlEncode($it.Details))</pre></td></tr>"
}
$footer = "</tbody></table>"
$recommend = "<h2>Recommendations</h2><ul><li>Investigate high-score items (Score ≥ 6) first.</li><li>If ComputeHashes is required, run with -ComputeHashes in an isolated analysis VM and then enable VT lookups.</li><li>For kernel/rootkit suspicions, capture memory and use Volatility or commercial tools.</li></ul>"

$final = "<html><head><meta charset='utf-8'/>$css</head><body>$header $tableHeader $rows $footer $recommend</body></html>"

try {
    $final | Out-File -FilePath $ReportFile -Encoding UTF8BOM -Force
    Write-Host "Report saved to: $ReportFile" -ForegroundColor Green
    Start-Process -FilePath $ReportFile -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Unable to write or open report: $_"
}

Write-Host "`nScan complete. Elapsed: $(([math]::Round(((Get-Date) - $StartTime).TotalSeconds,2)))s" -ForegroundColor Cyan
