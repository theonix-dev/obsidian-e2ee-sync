# setup.ps1 — interactive setup wizard for Obsidian E2EE Sync.
#
# Runs on Windows PowerShell 5.1+ and pwsh 7+ (cross-platform via pwsh).
# It can:
#   1) configure and run the sync server   (server\server.js — zero npm deps)
#   2) build the plugin and install it into one of your vaults
#   3) both of the above (default)
#   4) stop a previously background-started server
#
# Usage:  powershell -ExecutionPolicy Bypass -File setup.ps1
#         (or: pwsh -File setup.ps1)
#
# The shared configuration file server\run.env (KEY=VALUE) is compatible with
# setup.sh — configure once with either script, reuse anywhere.

[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$ScriptDir = $PSScriptRoot
$ServerDir = Join-Path $ScriptDir 'server'
$PluginDir = Join-Path $ScriptDir 'plugin'
$PluginId  = 'e2ee-vault-sync'
$RunEnv    = Join-Path $ServerDir 'run.env'
$PidFile   = Join-Path $ServerDir 'server.pid'
$LogFile   = Join-Path $ServerDir 'server.log'
$ErrFile   = Join-Path $ServerDir 'server.err.log'

foreach ($d in @($ServerDir, $PluginDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        Write-Host " [x]  $d not found next to this script." -ForegroundColor Red
        exit 1
    }
}

# ---------------------------------------------------------------- ui helpers
function Write-Step { param([string]$m) Write-Host "==> $m" -ForegroundColor White }
function Write-Ok   { param([string]$m) Write-Host " [ok] $m" -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host " [!]  $m" -ForegroundColor Yellow }
function Die        { param([string]$m) Write-Host " [x]  $m" -ForegroundColor Red; exit 1 }

function Read-Default {   # Read-Default QUESTION DEFAULT -> string
    param([string]$Question, [string]$Default = '')
    if ($Default -ne '') {
        $p = Read-Host "$Question [$Default]"
    } else {
        $p = Read-Host $Question
    }
    if ([string]::IsNullOrWhiteSpace($p)) { $Default } else { $p.Trim() }
}

function Confirm-YN {   # Confirm-YN QUESTION [default y|n] -> bool
    param([string]$Question, [string]$Default = 'y')
    while ($true) {
        $a = (Read-Default "$Question [y/n]" $Default).ToLowerInvariant()
        if ($a -in @('y','yes')) { return $true }
        if ($a -in @('n','no'))  { return $false }
        Write-Warn2 "Please answer y or n."
    }
}

# ---------------------------------------------------------------- checks/utils
function New-Token {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Assert-Node {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Die "node not found. Install Node.js >= 18 from https://nodejs.org"
    }
    $v = (& node -v) -replace '^v', '' -replace '\..*$', ''
    $n = 0
    if (-not [int]::TryParse($v, [ref]$n)) { Die "Cannot parse node version: $v" }
    if ($n -lt 18) { Die "Node.js >= 18 required (found $(node -v))." }
}

function Test-PortBusy {   # Test-PortBusy HOST PORT -> bool
    param([string]$HostName, [int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connected = $client.ConnectAsync($HostName, $Port).Wait(400)
        return ($connected -and $client.Connected)
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Invoke-HealthCheck {   # Invoke-HealthCheck HOST PORT -> bool
    param([string]$HostName, [int]$Port)
    try {
        $r = Invoke-WebRequest -Uri "http://${HostName}:${Port}/api/health" -UseBasicParsing -TimeoutSec 5
        return ($r.StatusCode -eq 200)
    } catch {
        return $false
    }
}

function Get-LanIp {   # best effort; empty string when unknown
    try {
        if ($env:OS -eq 'Windows_NT' -and (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue)) {
            $a = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } |
                 Select-Object -First 1
            if ($a) { return $a.IPAddress }
        }
        $addrs = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
                 Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.ToString() -ne '127.0.0.1' } |
                 Select-Object -First 1
        if ($addrs) { return $addrs.ToString() }
    } catch { }
    return ''
}

function Expand-UserPath {   # expands leading ~ and %ENV% variables
    param([string]$Path)
    if ($null -eq $Path) { return '' }
    if ($Path.StartsWith('~')) { $Path = $Home + $Path.Substring(1) }
    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Show-TokenMasked {   # first 8 chars + "..." + last 4
    param([string]$Token)
    if ($Token.Length -gt 16) {
        return $Token.Substring(0, 8) + '...' + $Token.Substring($Token.Length - 4)
    }
    return $Token
}

# ------------------------------------------------------------- run.env I/O --
function Write-RunEnv {
    param([int]$Port, [string]$BindHost, [string]$DataDir, [string]$Token)
    $lines = @(
        '# Generated by setup.sh / setup.ps1 — loaded on server start.',
        '# Keep AUTH_TOKEN secret.',
        "PORT=$Port",
        "HOST=$BindHost",
        "DATA_DIR=`"$DataDir`"",
        "AUTH_TOKEN=$Token"
    )
    Set-Content -LiteralPath $RunEnv -Value $lines -Encoding UTF8
}

function Read-RunEnv {   # -> hashtable with PORT/HOST/DATA_DIR/AUTH_TOKEN (or $null)
    if (-not (Test-Path -LiteralPath $RunEnv)) { return $null }
    $result = @{}
    foreach ($line in (Get-Content -LiteralPath $RunEnv)) {
        $t = $line.TrimStart([char]0xFEFF).TrimEnd()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $eq = $t.IndexOf('=')
        if ($eq -lt 1) { continue }
        $key = $t.Substring(0, $eq).Trim()
        $val = $t.Substring($eq + 1).Trim().Trim('"')
        $result[$key] = $val
    }
    return $result
}

# ---------------------------------------------------------------- server flow
function Ask-ServerParams {
    param([hashtable]$Saved)

    $script:Port = 0
    while ($true) {
        $def = if ($Saved -and $Saved.PORT) { $Saved.PORT } else { '8080' }
        $p = Read-Default 'Port to listen on' $def
        if ($p -notmatch '^\d+$') { Write-Warn2 'Port must be a number.'; continue }
        $n = [int]$p
        if ($n -lt 1 -or $n -gt 65535) { Write-Warn2 'Port must be 1-65535.'; continue }
        $probeHost = '127.0.0.1'
        if ($script:BindHost) { $probeHost = $script:BindHost }
        if (Test-PortBusy $probeHost $n) { Write-Warn2 "Port $n is already in use."; continue }
        $script:Port = $n
        break
    }

    $def = if ($Saved -and $Saved.HOST) { $Saved.HOST } else { '127.0.0.1' }
    $script:BindHost = Read-Default 'Bind address' $def
    if ($script:BindHost -eq '0.0.0.0' -or $script:BindHost -eq '::') {
        Write-Warn2 'Binding to all interfaces: anything that reaches this machine can connect.'
        Write-Warn2 'For internet exposure put nginx + HTTPS in front (see server/nginx.conf.example).'
    }

    $def = if ($Saved -and $Saved.DATA_DIR) { $Saved.DATA_DIR } else { Join-Path $ServerDir 'data' }
    $script:DataDir = Expand-UserPath (Read-Default 'Data directory' $def)
    New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null

    $t = Read-Default 'API token — press Enter to generate a secure one, or paste your own' ''
    if ($t -ne '') {
        if ($t.Length -lt 16) { Die 'Token must be at least 16 characters.' }
        $script:Token = $t
    } else {
        $script:Token = New-Token
    }
}

function Invoke-ServerFlow {
    Assert-Node

    $Saved = Read-RunEnv
    $savedComplete = $Saved -and $Saved.PORT -and $Saved.HOST -and $Saved.DATA_DIR -and $Saved.AUTH_TOKEN
    if ($savedComplete) {
        Write-Step "Found saved configuration: $RunEnv"
        Write-Host ("      port={0}  host={1}  data={2}" -f $Saved.PORT, $Saved.HOST, $Saved.DATA_DIR)
        Write-Host ("      token={0}" -f (Show-TokenMasked "$($Saved.AUTH_TOKEN)"))
        if (Confirm-YN 'Change these settings' 'n') {
            $script:BindHost = $Saved.HOST
            Ask-ServerParams $Saved
        } else {
            $script:Port     = [int]$Saved.PORT
            $script:BindHost = $Saved.HOST
            $script:DataDir  = $Saved.DATA_DIR
            $script:Token    = $Saved.AUTH_TOKEN
        }
    } else {
        if ($Saved) { Write-Warn2 "Saved configuration in $RunEnv is incomplete — reconfiguring." }
        $script:BindHost = ''
        Ask-ServerParams $Saved
    }
    Write-RunEnv -Port $script:Port -BindHost $script:BindHost -DataDir $script:DataDir -Token $script:Token

    Write-Host ''
    Write-Step 'Configuration summary'
    Write-Host ("      Server URL : http://127.0.0.1:{0}  (for this machine)" -f $script:Port)
    $ip = Get-LanIp
    if ($ip -ne '') {
        Write-Host ("      LAN URL    : http://{0}:{1}  (same network; for mobile devices)" -f $ip, $script:Port)
    }
    Write-Host ("      Data dir   : {0}" -f $script:DataDir)
    Write-Host ("      API token  : {0}   (full value in {1})" -f (Show-TokenMasked $script:Token), $RunEnv)
    Write-Host ''

    $mode = (Read-Default 'Start mode — (f)oreground, Ctrl+C stops, or (b)ackground' 'b').ToLowerInvariant()
    if ($mode.StartsWith('f')) {
        Write-Step 'Starting in FOREGROUND — press Ctrl+C to stop.'
        $env:PORT = "$($script:Port)"; $env:HOST = $script:BindHost
        $env:DATA_DIR = $script:DataDir; $env:AUTH_TOKEN = $script:Token
        & node (Join-Path $ServerDir 'server.js')
        return
    }

    Write-Step "Starting in BACKGROUND (log: $LogFile)."
    $env:PORT = "$($script:Port)"; $env:HOST = $script:BindHost
    $env:DATA_DIR = $script:DataDir; $env:AUTH_TOKEN = $script:Token
    $proc = Start-Process -FilePath 'node' `
        -ArgumentList ('"{0}"' -f (Join-Path $ServerDir 'server.js')) `
        -WorkingDirectory $ServerDir -WindowStyle Hidden `
        -RedirectStandardOutput $LogFile -RedirectStandardError $ErrFile -PassThru
    Set-Content -LiteralPath $PidFile -Value $proc.Id
    Start-Sleep -Seconds 1

    $checkHost = $script:BindHost
    if ($checkHost -eq '0.0.0.0' -or $checkHost -eq '::') { $checkHost = '127.0.0.1' }
    if (Invoke-HealthCheck $checkHost $script:Port) {
        Write-Ok "Server is running (pid $($proc.Id)) — http://$checkHost:$($script:Port)"
    } else {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        Write-Host "----- last log lines ($LogFile) -----" -ForegroundColor Red
        if (Test-Path -LiteralPath $LogFile) { Get-Content -LiteralPath $LogFile -Tail 20 }
        if (Test-Path -LiteralPath $ErrFile) { Get-Content -LiteralPath $ErrFile -Tail 20 }
        Die 'Server failed to start — see the log above.'
    }

    Write-Host ''
    Write-Step 'To stop it later:  run setup.ps1  ->  choose 4'
}

function Invoke-StopFlow {
    if (-not (Test-Path -LiteralPath $PidFile)) {
        Die "No PID file ($PidFile) — the server was not started in background by this script."
    }
    $procId = (Get-Content -LiteralPath $PidFile | Select-Object -First 1).ToString().Trim()
    $alive = $false
    try { $alive = -not (Get-Process -Id ([int]$procId) -ErrorAction Stop).HasExited } catch { }
    if ($alive) {
        Stop-Process -Id ([int]$procId) -Force
        Write-Ok "Server stopped (pid $procId)."
    } else {
        Write-Ok "Process $procId was already stopped."
    }
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- plugin flow
function Invoke-PluginFlow {
    Assert-Node

    $build = $false
    if (-not (Test-Path -LiteralPath (Join-Path $PluginDir 'main.js'))) {
        $build = $true
    } elseif (Confirm-YN 'Plugin is already built — rebuild from source (needs npm)' 'y') {
        $build = $true
    }

    if ($build) {
        if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
            Die 'npm not found. Install Node.js (includes npm) or copy main.js from another machine.'
        }
        Write-Step 'Building plugin...'
        if (-not (Test-Path -LiteralPath (Join-Path $PluginDir 'node_modules'))) {
            Push-Location $PluginDir
            & npm install --no-fund --no-audit
            $code = $LASTEXITCODE
            Pop-Location
            if ($code -ne 0) { Die 'npm install failed.' }
        }
        Push-Location $PluginDir
        & npm run build
        $code = $LASTEXITCODE
        Pop-Location
        if ($code -ne 0) { Die 'Plugin build failed.' }
    }

    if (-not (Test-Path -LiteralPath (Join-Path $PluginDir 'main.js'))) {
        Die "main.js is missing in $PluginDir — build the plugin first."
    }

    $vault = ''
    while ($true) {
        $vault = Expand-UserPath (Read-Default 'Path to your Obsidian vault (the folder that contains .obsidian)' '')
        if ($vault -eq '') { Write-Warn2 'Path cannot be empty.'; continue }
        if (-not (Test-Path -LiteralPath $vault)) { Write-Warn2 "Not a directory: $vault"; continue }
        if (Test-Path -LiteralPath (Join-Path $vault '.obsidian')) { break }
        Write-Warn2 'No .obsidian folder inside — this does not look like an opened Obsidian vault.'
        if (Confirm-YN 'Use this folder anyway' 'n') { break }
    }

    $dest = Join-Path $vault ".obsidian\plugins\$PluginId"
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    foreach ($f in @('main.js', 'manifest.json', 'styles.css')) {
        $src = Join-Path $PluginDir $f
        if (-not (Test-Path -LiteralPath $src)) { Die "Missing $src — build the plugin first." }
        Copy-Item -LiteralPath $src -Destination (Join-Path $dest $f) -Force
    }
    Write-Ok "Plugin installed: $dest"

    Write-Host ''
    Write-Step 'Next steps in Obsidian:'
    Write-Host "  1. Settings -> Community plugins -> enable 'E2EE Vault Sync'"
    Write-Host '  2. Settings -> E2EE Vault Sync:'
    $saved = Read-RunEnv
    $urlPort = if ($script:Port) { $script:Port } elseif ($saved) { $saved.PORT } else { '8080' }
    $tokenShown = if ($script:Token) { Show-TokenMasked $script:Token } elseif ($saved) { Show-TokenMasked "$($saved.AUTH_TOKEN)" } else { "see $RunEnv" }
    Write-Host ("       Server URL    : http://127.0.0.1:{0}   (or https://your-domain)" -f $urlPort)
    Write-Host ("       API token     : {0}" -f $tokenShown)
    Write-Host '       E2EE password : choose one — THE SAME on every device'
    Write-Host "  3. Press 'Test connection', then run 'Force full sync'."
    Write-Host '  Note: on iOS/Android use the LAN/VPS URL — 127.0.0.1 only works on this machine.'
}

# ---------------------------------------------------------------- main
Write-Step 'Obsidian E2EE Sync — setup wizard'
Write-Host '  1) Run the sync server'
Write-Host '  2) Install the plugin into a vault'
Write-Host '  3) Both (default)'
Write-Host '  4) Stop the background server'
Write-Host '  q) Quit'
$choice = Read-Default 'Choose' '3'
switch ($choice) {
    '1' { Invoke-ServerFlow }
    '2' { Invoke-PluginFlow }
    '3' { Invoke-PluginFlow; Invoke-ServerFlow }
    '4' { Invoke-StopFlow }
    'q' { exit 0 }
    'Q' { exit 0 }
    default { Die "Unknown choice: $choice" }
}
