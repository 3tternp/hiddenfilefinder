<#
.SYNOPSIS
  MalwareScan_Advanced_Patched.ps1
.DESCRIPTION
  Advanced malware-indicator scanner (Quick/Full) with:
    - Correct DeepScan reporting
    - Parallelized file scoring/hashing when PS7+ available
    - Progress + ETA
    - Autoruns-style enumeration
    - Authenticode signature checks
    - Optional VirusTotal lookup (API key required)
    - Non-destructive quarantine (copy-only)
    - Auto-open HTML report
  Run as Administrator for best results.
.PARAMETER Mode
  "Quick" (default) or "Full"
.PARAMETER OutputHtml
  Path to save HTML report (default: Desktop timestamped)
.PARAMETER VirusTotalApiKey
  Optional VirusTotal API key (v3) - if provided, will query VT for SHA256.
.PARAMETER Quarantine
  Switch to copy suspicious files (Score >= 3) to quarantine folder.
.PARAMETER QuarantinePath
  Custom quarantine folder. If not set, default Desktop\Quarantine_<timestamp>.
#>

param(
    [ValidateSet("Quick","Full")]
    [string]$Mode = "Quick",
    [string]$OutputHtml = "$env:USERPROFILE\Desktop\MalwareScanReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [string]$VirusTotalApiKey = "",
    [switch]$Quarantine,
    [string]$QuarantinePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# Determine deep scan boolean and if parallel processing available
$DeepScan = if ($Mode -eq 'Full') { $true } else { $false }
$UseParallel = ($PSVersionTable.PSVersion.Major -ge 7)

# Progress steps
$steps = @(
    "Enumerate Autoruns/Startup",
    "Scan Running Processes",
    "Scan Services & Drivers",
    "Scan File System (risky folders)",
    "Network checks",
    "Finalize report (hashing, VT lookups, quarantine)"
)
$TotalSteps = $steps.Count
$CurrentStep = 0
$StartTime = Get-Date

function Show-Progress {
    param([string]$Activity)
    $CurrentStep++
    $elapsed = (Get-Date) - $StartTime
    $percent = [int](($CurrentStep / $TotalSteps) * 100)
    $etaSec = 0
    if ($CurrentStep -gt 0) { $etaSec = [math]::Max(0, [math]::Round($elapsed.TotalSeconds / $CurrentStep * ($TotalSteps - $CurrentStep))) }
    $status = "Elapsed: $([int]$elapsed.TotalSeconds)s | ETA: ${etaSec}s"
    Write-Progress -Activity $Activity -Status $status -PercentComplete $percent
}

# Utility functions
function Compute-HashSafe {
    param([string]$Path)
    try {
        if (-not [string]::IsNullOrEmpty($Path) -and (Test-Path $Path)) {
            $h = Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop
            return $h.Hash
        }
    } catch {}
    return ""
}

function Get-AuthSignStatus {
    param([string]$Path)
    try {
        if (-not [string]::IsNullOrEmpty($Path) -and (Test-Path $Path)) {
            $s = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
            if ($s) { return $s.Status.ToString() }
        }
    } catch {}
    return "Unknown"
}

function Query-VirusTotal {
    param([string]$sha256)
    if ([string]::IsNullOrEmpty($VirusTotalApiKey) -or [string]::IsNullOrEmpty($sha256)) { return $null }
    try {
        $uri = "https://www.virustotal.com/api/v3/files/$sha256"
        $hdr = @{ "x-apikey" = $VirusTotalApiKey }
        $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $hdr -ErrorAction Stop -TimeoutSec 30
        return $resp
    } catch { return $null }
}

function New-Finding {
    param($Type,$Name,$Location,$Score,$Details,$SHA256,$Signed,$VTResult)
    [PSCustomObject]@{
        Type = $Type
        Name = $Name
        Location = $Location
        Score = $Score
        Details = $Details
        SHA256 = $SHA256
        Signed = $Signed
        VT = $VTResult
    }
}

# Scoring logic (kept conservative and fast)
function Score-File {
    param([string]$Path, [bool]$IsStartup)
    $score = 0
    $reasons = @()
    try {
        if (-not [string]::IsNullOrEmpty($Path) -and (Test-Path $Path)) {
            $info = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
            if ($info) {
                if ($info.Attributes -band [System.IO.FileAttributes]::Hidden) { $score += 2; $reasons += "Hidden attribute" }
                $age = (Get-Date) - $info.CreationTime
                if ($age.TotalDays -le 30) { $score += 1; $reasons += "Recent (<=30d)" }
            }
            $susFolders = @("$env:TEMP","$env:USERPROFILE\AppData\Local","$env:USERPROFILE\AppData\Roaming","$env:USERPROFILE\Downloads")
            foreach ($sf in $susFolders) { if ($Path -like "$sf*") { $score += 2; $reasons += "Located in suspicious folder ($sf)"; break } }
            $ext = [System.IO.Path]::GetExtension($Path).ToLower()
            if ($ext -in '.exe','.dll','.scr','.ps1','.vbs','.bat','.js') { $score += 1; $reasons += "Executable/script ($ext)" }
            if ($IsStartup) { $score += 2; $reasons += "Startup/persistence" }
            if ($ext -in '.exe','.dll') {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
                    if ($sig -and $sig.Status -ne 'Valid') { $score += 3; $reasons += "Unsigned/invalid signature ($($sig.Status))" }
                } catch { $reasons += "Signature check error" }
            }
        } else {
            $score += 1; $reasons += "Path not resolved (value may be a commandline)"
        }
    } catch { $reasons += "Scoring error: $_" }
    return @{ Score = $score; Reasons = ($reasons -join '; ') }
}

# Data collection container
$Findings = [System.Collections.Generic.List[object]]::new()

# ---------- 1) Autoruns-style startup enumeration ----------
Show-Progress $steps[0]
$autorunRegistry = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
foreach ($rp in $autorunRegistry) {
    try {
        if (Test-Path $rp) {
            $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -match '^PS') { continue }
                    $val = $p.Value -as [string]
                    $extracted = $null
                    if (-not [string]::IsNullOrEmpty($val)) {
                        $possible = ($val -split '\s+') | Where-Object { $_ -match '\.exe$|\.dll$|\.ps1$|\.bat$|\.cmd$|\.vbs$|\.js$' }
                        if ($possible) { $extracted = ($possible | Select-Object -First 1).Trim('"') }
                        else {
                            $quoted = ($val -split '"') | Where-Object { $_ -match '\.exe$|\.ps1$' }
                            if ($quoted) { $extracted = ($quoted | Select-Object -First 1).Trim() }
                        }
                    }
                    $res = Score-File -Path $extracted -IsStartup $true
                    $sha = ""
                    if ($res.Score -ge 2 -and -not [string]::IsNullOrEmpty($extracted)) { $sha = Compute-HashSafe -Path $extracted }
                    $signed = Get-AuthSignStatus -Path $extracted
                    $vt = $null
                    if ($DeepScan -and -not [string]::IsNullOrEmpty($sha) -and -not [string]::IsNullOrEmpty($VirusTotalApiKey)) { $vt = Query-VirusTotal -sha256 $sha }
                    $Findings.Add((New-Finding -Type "RegistryStartup" -Name $p.Name -Location $rp -Score $res.Score -Details ("Value=$val; Reasons=$($res.Reasons)") -SHA256 $sha -Signed $signed -VTResult $vt))
                }
            }
        }
    } catch {}
}

# Startup folders
$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($sf in $startupFolders) {
    try {
        if (Test-Path $sf) {
            Get-ChildItem -LiteralPath $sf -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
                $res = Score-File -Path $_.FullName -IsStartup $true
                $sha = ""
                if ($res.Score -ge 2) { $sha = Compute-HashSafe -Path $_.FullName }
                $signed = Get-AuthSignStatus -Path $_.FullName
                $vt = $null
                if ($DeepScan -and -not [string]::IsNullOrEmpty($sha) -and -not [string]::IsNullOrEmpty($VirusTotalApiKey)) { $vt = Query-VirusTotal -sha256 $sha }
                $Findings.Add((New-Finding -Type "StartupFolder" -Name $_.Name -Location $_.FullName -Score $res.Score -Details $res.Reasons -SHA256 $sha -Signed $signed -VTResult $vt))
            }
        }
    } catch {}
}

# ---------- 2) Running processes ----------
Show-Progress $steps[1]
try {
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $pPath = $p.ExecutablePath
        if (-not $pPath -and $p.CommandLine) {
            $pPath = ($p.CommandLine -split '\s+') | Where-Object { $_ -match '\.exe$|\.ps1$' } | Select-Object -First 1
        }
        $res = Score-File -Path $pPath -IsStartup $false
        $sha = ""
        if ($res.Score -ge 2 -and -not [string]::IsNullOrEmpty($pPath)) { $sha = Compute-HashSafe -Path $pPath }
        $signed = Get-AuthSignStatus -Path $pPath
        $vt = $null
        if ($DeepScan -and -not [string]::IsNullOrEmpty($sha) -and -not [string]::IsNullOrEmpty($VirusTotalApiKey)) { $vt = Query-VirusTotal -sha256 $sha }
        $Findings.Add((New-Finding -Type "Process" -Name $p.Name -Location $pPath -Score $res.Score -Details ("PID=$($p.ProcessId); Cmd=$($p.CommandLine); $($res.Reasons)") -SHA256 $sha -Signed $signed -VTResult $vt))
    }
} catch {}

# ---------- 3) Services & drivers ----------
Show-Progress $steps[2]
try {
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($s in $services) {
        $exe = $s.PathName
        $clean = $null
        if ($exe) { $clean = ($exe -replace '^[\s"]+|[\s"]+$','') -split '\s+' | Select-Object -First 1 }
        $res = Score-File -Path $clean -IsStartup $true
        $sha = ""
        if ($res.Score -ge 2 -and -not [string]::IsNullOrEmpty($clean)) { $sha = Compute-HashSafe -Path $clean }
        $signed = Get-AuthSignStatus -Path $clean
        $vt = $null
        if ($DeepScan -and -not [string]::IsNullOrEmpty($sha) -and -not [string]::IsNullOrEmpty($VirusTotalApiKey)) { $vt = Query-VirusTotal -sha256 $sha }
        $Findings.Add((New-Finding -Type "Service" -Name $s.Name -Location $clean -Score $res.Score -Details ("DisplayName=$($s.DisplayName); StartMode=$($s.StartMode); $($res.Reasons)") -SHA256 $sha -Signed $signed -VTResult $vt))
    }

    $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue
    foreach ($d in $drivers) {
        $fn = $d.PathName
        $res = Score-File -Path $fn -IsStartup $true
        $sha = ""
        if ($res.Score -ge 2 -and -not [string]::IsNullOrEmpty($fn)) { $sha = Compute-HashSafe -Path $fn }
        $signed = Get-AuthSignStatus -Path $fn
        $vt = $null
        if ($DeepScan -and -not [string]::IsNullOrEmpty($sha) -and -not [string]::IsNullOrEmpty($VirusTotalApiKey)) { $vt = Query-VirusTotal -sha256 $sha }
        $Findings.Add((New-Finding -Type "Driver" -Name $d.Name -Location $fn -Score $res.Score -Details ("DisplayName=$($d.DisplayName); State=$($d.State); $($res.Reasons)") -SHA256 $sha -Signed $signed -VTResult $vt))
    }
} catch {}

# ---------- 4) Filesystem: risky folders (parallelized when possible) ----------
Show-Progress $steps[3]
$risky = @("$env:USERPROFILE\AppData\Roaming","$env:USERPROFILE\AppData\Local","$env:USERPROFILE\Downloads","$env:TEMP","$env:ProgramFiles","$env:ProgramFiles(x86)")
# Ensure only existing paths
$riskyPaths = $risky | Where-Object { Test-Path $_ }

# Helper to process a collection of FileInfo objects (scoring + conditional hashing)
$processFileScript = {
    param($filePath, $DeepScan, $VirusTotalApiKey)
    $localResult = $null
    try {
        $res = & ${function:Score-File} -Path $filePath -IsStartup $false
        if ($res.Score -ge 2) {
            $sha = ""
            if ($DeepScan) { $sha = & ${function:Compute-HashSafe} -Path $filePath }
            $signed = & ${function:Get-AuthSignStatus} -Path $filePath
            $vt = $null
            if ($DeepScan -and -not [string]::IsNullOrEmpty($sha) -and -not [string]::IsNullOrEmpty($VirusTotalApiKey)) { $vt = & ${function:Query-VirusTotal} -sha256 $sha }
            $localResult = New-Object PSObject -Property @{
                Type = "File"
                Name = [System.IO.Path]::GetFileName($filePath)
                Location = $filePath
                Score = $res.Score
                Details = $res.Reasons
                SHA256 = $sha
                Signed = $signed
                VT = $vt
            }
        }
    } catch {}
    return $localResult
}

# Collect file list once (avoid re-scanning directories multiple times).
$fileCandidates = New-Object System.Collections.Generic.List[string]
foreach ($rp in $riskyPaths) {
    try {
        if ($DeepScan) {
            # Full: gather all file candidates with suspicious extensions
            $items = Get-ChildItem -LiteralPath $rp -Recurse -Force -ErrorAction SilentlyContinue -File |
                Where-Object { $_.Extension -in '.exe','.dll','.scr','.ps1','.vbs','.bat','.cmd','.js' } |
                Select-Object -ExpandProperty FullName
        } else {
            # Quick: recent files only
            $items = Get-ChildItem -LiteralPath $rp -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { ($_.LastWriteTime -gt (Get-Date).AddDays(-30)) -and ($_.Extension -in '.exe','.dll','.scr','.ps1','.vbs','.bat','.cmd','.js') } |
                Select-Object -ExpandProperty FullName
        }
        foreach ($i in $items) { $fileCandidates.Add($i) }
    } catch {}
}

# Process fileCandidates parallel when possible
if ($UseParallel -and $fileCandidates.Count -gt 0) {
    # run in parallel with throttle
    $throttle = [int]([math]::Min(8, [math]::Max(2, [int]([Environment]::ProcessorCount / 2))))
    $scriptBlock = {
        param($chunk, $DeepScanParam, $VTKey)
        $out = @()
        foreach ($fp in $chunk) {
            $r = & ${function:processFileScript} -filePath $fp -DeepScan $DeepScanParam -VirusTotalApiKey $VTKey
            if ($r -ne $null) { $out += $r }
        }
        return $out
    }

    # Break into batches to avoid creating huge parallel tasks
    $batchSize = 200
    for ($i = 0; $i -lt $fileCandidates.Count; $i += $batchSize) {
        $batch = $fileCandidates[$i..([math]::Min($i + $batchSize - 1, $fileCandidates.Count - 1))]
        $results = $batch | ForEach-Object -Parallel {
            param($bItem,$DeepScanLocal,$VTKeyLocal)
            # call the existing processFileScript via the function name in using:
            $res = & ${using:processFileScript} -filePath $bItem -DeepScan $DeepScanLocal -VirusTotalApiKey $VTKeyLocal
            if ($res) { $res }
        } -ArgumentList $DeepScan, $VirusTotalApiKey -ThrottleLimit $throttle
        foreach ($r in $results) { if ($r) { $Findings.Add($r) } }
    }
} else {
    # Serial processing
    foreach ($fp in $fileCandidates) {
        $r = & ${function:processFileScript} -filePath $fp -DeepScan $DeepScan -VirusTotalApiKey $VirusTotalApiKey
        if ($r) { $Findings.Add($r) }
    }
}

# ---------- 5) Network checks ----------
Show-Progress $steps[4]
try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        if ($c.RemoteAddress -and ($c.RemoteAddress -notmatch '^(127\.|0\.|::1)')) {
            $procPath = ""
            try { $pr = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; $procPath = $pr.Path } catch {}
            $score = 0; $reasons = @()
            if ($procPath) {
                $res = Score-File -Path $procPath -IsStartup $false
                $score = $res.Score + 1
                $reasons += "Network connection to $($c.RemoteAddress):$($c.RemotePort)"
            } else {
                $score = 1
                $reasons += "Network connection to $($c.RemoteAddress):$($c.RemotePort)"
            }
            $sha = ""
            if ($score -ge 2 -and -not [string]::IsNullOrEmpty($procPath)) { $sha = Compute-HashSafe -Path $procPath }
            $signed = Get-AuthSignStatus -Path $procPath
            $vt = $null
            if ($DeepScan -and -not [string]::IsNullOrEmpty($sha) -and -not [string]::IsNullOrEmpty($VirusTotalApiKey)) { $vt = Query-VirusTotal -sha256 $sha }
            $Findings.Add((New-Finding -Type "Network" -Name $c.RemoteAddress -Location $procPath -Score $score -Details ($reasons -join '; ') -SHA256 $sha -Signed $signed -VTResult $vt))
        }
    }
} catch {}

# ---------- 6) Finalize: quarantine & report ----------
Show-Progress $steps[5]

# Prepare quarantine folder
if ($Quarantine) {
    if ([string]::IsNullOrEmpty($QuarantinePath)) {
        $QuarantinePath = "$env:USERPROFILE\Desktop\Quarantine_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    if (-not (Test-Path $QuarantinePath)) { New-Item -Path $QuarantinePath -ItemType Directory -Force | Out-Null }
}

# Convert Findings list to array for easier LINQ-like operations
$FindingsArray = $Findings.ToArray()

# Suspicious threshold
$Suspicious = $FindingsArray | Where-Object { $_.Score -ge 3 } | Sort-Object -Property Score -Descending

# Quarantine non-destructive copy
foreach ($s in $Suspicious) {
    if ($Quarantine -and -not [string]::IsNullOrEmpty($s.Location) -and (Test-Path $s.Location)) {
        try {
            $destName = [IO.Path]::GetFileName($s.Location)
            $dest = Join-Path -Path $QuarantinePath -ChildPath $destName
            if (Test-Path $dest) { $dest = "$dest.$(Get-Date -Format 'yyyyMMddHHmmss')" }
            Copy-Item -LiteralPath $s.Location -Destination $dest -Force -ErrorAction SilentlyContinue
            $s.Details = $s.Details + " | QuarantinedCopy=$dest"
        } catch { $s.Details = $s.Details + " | QuarantineFailed" }
    }
}

# Build HTML report (Simple & professional format - option B)
function Html-Encode { param($t) if ($null -eq $t) { return "" } else { return [System.Web.HttpUtility]::HtmlEncode($t) } }

$css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 16px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 6px; font-size: 12px; vertical-align: top; }
th { background: #f2f2f2; }
.high { background: #ffd6d6; }
.medium { background: #fff2cc; }
.low { background: #e6f7ff; }
pre { margin:0; white-space:pre-wrap; word-wrap:break-word; font-size:11px; }
</style>
"@

$summary = @"
<h1>Windows suspicious item scan</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p>DeepScan: $($DeepScan)</p>
<p>Total Items: $($FindingsArray.Count)</p>
<p>Risk Detections (Score ≥ 3): $($Suspicious.Count)</p>
"@

$header = "<table><thead><tr><th>Type</th><th>Name</th><th>Location</th><th>Score</th><th>Signed</th><th>SHA256</th><th>VirusTotal</th><th>Details</th></tr></thead><tbody>"
$rows = ""
foreach ($it in $FindingsArray | Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Type';Descending=$false}) {
    $cls = if ($it.Score -ge 6) {'high'} elseif ($it.Score -ge 3) {'medium'} else {'low'}
    $vtSummary = ""
    if ($it.VT) {
        try {
            $mal = $it.VT.data.attributes.last_analysis_stats
            $vtSummary = "Malicious:$($mal.malicious) | Undetected:$($mal.undetected)"
        } catch { $vtSummary = "VT: unknown" }
    }
    $rows += "<tr class='$cls'><td>$([System.Web.HttpUtility]::HtmlEncode($it.Type))</td><td>$([System.Web.HttpUtility]::HtmlEncode($it.Name))</td><td><pre>$([System.Web.HttpUtility]::HtmlEncode($it.Location))</pre></td><td>$($it.Score)</td><td>$([System.Web.HttpUtility]::HtmlEncode($it.Signed))</td><td><code>$([System.Web.HttpUtility]::HtmlEncode($it.SHA256))</code></td><td>$([System.Web.HttpUtility]::HtmlEncode($vtSummary))</td><td><pre>$([System.Web.HttpUtility]::HtmlEncode($it.Details))</pre></td></tr>"
}
$footer = "</tbody></table>"

$recommend = "<h2>Recommendations</h2><ul><li>Investigate high-score items first.</li><li>Use offline analysis VM for dynamic tests.</li><li>Do not delete without IR procedures; quarantine copies are non-destructive.</li></ul>"

$finalHtml = "<html><head><meta charset='utf-8'/>$css</head><body>$summary$header$rows$footer$recommend</body></html>"

try {
    $outDir = Split-Path -Path $OutputHtml -Parent
    if ($outDir -and -not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
    $finalHtml | Out-File -FilePath $OutputHtml -Encoding UTF8 -Force
    Write-Host "Report written to: $OutputHtml" -ForegroundColor Green
    Start-Process -FilePath $OutputHtml -ErrorAction SilentlyContinue
    if ($Quarantine) { Write-Host "Quarantine folder: $QuarantinePath" -ForegroundColor Yellow }
} catch {
    Write-Host "Failed to write or open report: $_" -ForegroundColor Red
}

Write-Host "Scan complete." -ForegroundColor Green
# End of script
