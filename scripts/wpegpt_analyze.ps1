#Requires -Version 5.0
param(
    [Parameter(Mandatory=$true)]
    [string]$BinaryPath,

    [ValidateSet('light', 'full', 'vuln')]
    [string]$Mode = 'light'
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ConfigPath = Join-Path $ScriptDir '..\config\config.ini'

# ---- Resolve binary path ----
if (-not (Test-Path $BinaryPath)) {
    Write-Host "[ERROR] File not found: $BinaryPath" -ForegroundColor Red
    exit 1
}
$BinaryPath = (Resolve-Path $BinaryPath).Path

# ---- Parse config ----
$config = @{}
if (Test-Path $ConfigPath) {
    Get-Content $ConfigPath | Where-Object { $_ -match '^\s*([a-z_]+)\s*=' } | ForEach-Object {
        if ($_ -match '^\s*([a-z_]+)\s*=\s*(.+)$') {
            $config[$Matches[1]] = $Matches[2].Trim()
        }
    }
}

if (-not $config.ContainsKey('ida_dir')) {
    Write-Host "[ERROR] ida_dir not configured in config.ini" -ForegroundColor Red
    Write-Host "[*] Please configure: $ConfigPath"
    exit 1
}

$idaDir = $config['ida_dir']
$idaExe = Join-Path $idaDir 'ida.exe'
$ida64Exe = Join-Path $idaDir 'ida64.exe'
$controllerPath = Join-Path $idaDir 'plugins\WPeGPT_Config\wpe_ai_controller.py'

# ---- Validate dependencies ----
if (-not (Test-Path $idaExe)) {
    Write-Host "[ERROR] ida.exe not found: $idaExe" -ForegroundColor Red
    Write-Host "[*] Please check ida_dir in config.ini: $ConfigPath"
    exit 1
}
if (-not (Test-Path (Join-Path $idaDir 'plugins\WPeGPT.py'))) {
    Write-Host "[ERROR] WPeGPT.py not found in $($idaDir)\plugins\" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $controllerPath)) {
    Write-Host "[ERROR] wpe_ai_controller.py not found: $controllerPath" -ForegroundColor Red
    exit 1
}

# ---- Detect binary architecture ----
$bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
$is64 = $false
$bitStr = "32-bit"

# Check ELF magic
if ($bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46) {
    # ELF file: byte at offset 4 indicates class (1=32-bit, 2=64-bit)
    $elfClass = $bytes[4]
    if ($elfClass -eq 2) {
        $is64 = $true
    }
    if ($is64) { $bitStr = "64-bit" }
    # Determine machine type from ELF e_machine (offset 0x12, 2 bytes)
    $e_machine = [BitConverter]::ToUInt16($bytes, 0x12)
    $archName = switch ($e_machine) {
        0x03 { "Intel 80386" }
        0x3E { "x86-64" }
        0x08 { "MIPS" }
        0x28 { "ARM" }
        0xB7 { "AArch64" }
        0x14 { "PowerPC" }
        0x02 { "SPARC" }
        0x07 { "x86" }
        default { "Unknown (0x$($e_machine.ToString('X')))" }
    }
    Write-Host "[*] Detected ELF binary ($archName, $bitStr)"
}
# Check PE magic (MZ)
elseif ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
    $peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $is64 = ($machine -eq 0x8664)
    if ($is64) { $bitStr = "64-bit" }
    Write-Host "[*] Detected PE binary ($bitStr)"
}
else {
    Write-Host "[WARN] Unknown file format, defaulting to ida.exe"
}

if ($is64) {
    if (Test-Path $ida64Exe) {
        Write-Host "[*] Detected 64-bit binary, using ida64.exe"
        $idaRun = $ida64Exe
    } else {
        Write-Host "[WARN] ida64.exe not found, falling back to ida.exe"
        $idaRun = $idaExe
    }
} else {
    Write-Host "[*] Detected 32-bit binary, using ida.exe"
    $idaRun = $idaExe
}

Write-Host ""
Write-Host "========================================"
Write-Host " WPeGPT Binary Analysis"
Write-Host "========================================"
Write-Host " Binary : $BinaryPath"
Write-Host " Mode   : $Mode"
Write-Host " IDA    : $idaDir"
Write-Host "========================================"
Write-Host ""

# ---- Find Python ----
$pythonExe = $null

# Try 1: Config-specified python_path
if ($config.ContainsKey('python_path') -and (Test-Path $config['python_path'])) {
    $pythonExe = $config['python_path']
    Write-Host "[*] Using configured Python: $pythonExe"
}

# Try 2: Search PATH
if (-not $pythonExe) {
    $pythonExe = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
}
if (-not $pythonExe) {
    $pythonExe = Get-Command pythonw.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
}

if (-not $pythonExe) {
    Write-Host "[ERROR] Python.exe not found." -ForegroundColor Red
    Write-Host "[*] Please set python_path in config.ini to your Python installation path."
    Write-Host "[*] Common: C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python310\python.exe"
    exit 1
}

Write-Host "[*] Using Python: $pythonExe"
Write-Host ""

# ---- Clean old port files ----
Remove-Item "$env:TEMP\.wpe_server_port_*" -ErrorAction SilentlyContinue

# ---- Step 1: Launch IDA ----
Write-Host "[*] Step 1/2: Launching IDA with WPeGPT plugin..."
Start-Process -FilePath $idaRun -ArgumentList "-A", $BinaryPath -WindowStyle Minimized

# ---- Step 2: Wait for WPeServer, run controller ----
Write-Host "[*] Step 2/2: Waiting for WPeServer to be ready..."
$waitCount = 0
$maxWait = 240

while ($waitCount -lt $maxWait) {
    Start-Sleep -Seconds 2
    $waitCount += 2

    $portFiles = Get-ChildItem "$env:TEMP\.wpe_server_port_*" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    if ($portFiles) {
        $portFile = $portFiles[0]
        break
    }

    if ($waitCount % 20 -eq 0) {
        Write-Host "[*] Still waiting... (${waitCount}s elapsed)"
    }
}

if ($waitCount -ge $maxWait) {
    Write-Host "[ERROR] WPeServer did not start within ${maxWait}s." -ForegroundColor Red
    Write-Host "[*] Check the IDA Output window for WPeGPT startup errors."
    Write-Host "[*] Ensure WPeGPT.py is installed in IDA's plugins directory."
    exit 1
}

Write-Host "[*] WPeServer detected (port file: $($portFile.Name))"
Write-Host ""
Write-Host "[*] Starting $Mode analysis (this may take a few minutes)..."
Write-Host ""

& $pythonExe $controllerPath --mode $Mode
$exitCode = $LASTEXITCODE

Write-Host ""
if ($exitCode -eq 0) {
    $binaryDir = Split-Path $BinaryPath -Parent
    $binaryName = Split-Path $BinaryPath -Leaf
    $reportDir = Join-Path $binaryDir "${binaryName}_WPeAI_Results"
    Write-Host ""
    Write-Host "========================================"
    Write-Host " Reports"
    Write-Host "========================================"
    Write-Host " Dir : $reportDir"
    Write-Host " JSON: $reportDir\analysis_report-$Mode.json"
    Write-Host " MD  : $reportDir\analysis_report-$Mode.md"
    Write-Host "========================================"
} else {
    Write-Host "[WARN] Analysis exited with code $exitCode, check output above."
}

Write-Host ""
Write-Host "[*] Done!"
