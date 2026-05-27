@echo off
REM ==========================================
REM WPeGPT Binary Analyzer
REM ==========================================
REM Usage: wpegpt_analyze.bat <binary_path> [mode]
REM   mode: light (default) / full / vuln
REM ==========================================

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set CONFIG=%SCRIPT_DIR%..\config\config.ini

if "%~1"=="" (
    echo Usage: %~nx0 ^<binary_path^> [mode]
    echo   mode: light ^(default^) / full / vuln
    echo Example: %~nx0 C:\samples\malware.exe light
    exit /b 1
)

set BINARY=%~f1
set MODE=%2
if "!MODE!"=="" set MODE=light

if not exist "%BINARY%" (
    echo [ERROR] File not found: %BINARY%
    exit /b 1
)

REM ---- Load / initialize config ----
for /f "tokens=1,2 delims==" %%a in ('findstr /i "^ida_dir" "%CONFIG%" 2^>nul') do set IDA_DIR=%%b

if "!IDA_DIR!"=="" (
    echo [ERROR] IDA path not configured.
    echo [*] Please configure config.ini first:
    echo     %CONFIG%
    echo [*] Or ask the assistant to set it up interactively.
    exit /b 1
)

set IDA_EXE=!IDA_DIR!\ida.exe
set IDA64_EXE=!IDA_DIR!\ida64.exe
set CONTROLLER_PATH=!IDA_DIR!\plugins\WPeGPT_Config\wpe_ai_controller.py

if not exist "!IDA_EXE!" (
    echo [ERROR] ida.exe not found: !IDA_EXE!
    echo [*] Please check your IDA path in config.ini: %CONFIG%
    exit /b 1
)

if not exist "!IDA_DIR!\plugins\WPeGPT.py" (
    echo [ERROR] WPeGPT.py not found: !IDA_DIR!\plugins\
    echo [*] Ensure WPeGPT files are installed in IDA's plugins directory.
    exit /b 1
)

if not exist "!CONTROLLER_PATH!" (
    echo [ERROR] wpe_ai_controller.py not found: !CONTROLLER_PATH!
    exit /b 1
)

REM ---- Detect 32-bit or 64-bit binary via ELF or PE header ----
set IS_64=0
set ARCH_INFO=
powershell -NoProfile -Command "$f=[System.IO.File]::ReadAllBytes('%BINARY%'); if($f[0]-eq0x7F -and $f[1]-eq0x45 -and $f[2]-eq0x4C -and $f[3]-eq0x46){ $c=$f[4]; $m=[BitConverter]::ToUInt16($f,0x12); $n=switch($m){0x03{'x86'};0x3E{'x86_64'};0x08{'MIPS'};0x28{'ARM'};0xB7{'AArch64'};0x14{'PowerPC'};0x02{'SPARC'};default{'Unknown(0x{0:X}'-f$m)}}; Write-Host('[ELF] {0} {1}'-f$n,(if($c-eq2){'64-bit'}else{'32-bit'})); if($c-eq2){exit 0}else{exit 1} }elseif($f[0]-eq0x4D -and $f[1]-eq0x5A){ $pe=[BitConverter]::ToUInt32($f,0x3C); $m=[BitConverter]::ToUInt16($f,$pe+4); Write-Host('[PE] {0}'-f(if($m-eq0x8664){'64-bit'}else{'32-bit'})); if($m-eq0x8664){exit 0}else{exit 1} }else{ Write-Host('[Unknown format]'); exit 1 }"
if %ERRORLEVEL% equ 0 set IS_64=1

if !IS_64! equ 1 (
    if exist "!IDA64_EXE!" (
        echo [*] Detected 64-bit binary, using ida64.exe
        set IDA_RUN="!IDA64_EXE!"
    ) else (
        echo [WARN] ida64.exe not found, falling back to ida.exe
        set IDA_RUN="!IDA_EXE!"
    )
) else (
    echo [*] Detected 32-bit binary, using ida.exe
    set IDA_RUN="!IDA_EXE!"
)

echo.
echo ========================================
echo  WPeGPT Binary Analysis
echo ========================================
echo  Binary : %BINARY%
echo  Mode   : %MODE%
echo  IDA    : !IDA_DIR!
echo ========================================
echo.

REM ---- Find Python ----
set PYTHON_EXE=

REM Try 1: Config-specified python_path
for /f "tokens=1,2 delims==" %%a in ('findstr /i "^python_path" "%CONFIG%" 2^>nul') do set PYTHON_EXE=%%b
if not "!PYTHON_EXE!"=="" (
    if exist "!PYTHON_EXE!" (
        echo [*] Using configured Python: !PYTHON_EXE!
        goto python_ok
    ) else (
        echo [WARN] Configured python_path not found: !PYTHON_EXE!
        echo [*] Falling back to PATH search...
        set PYTHON_EXE=
    )
)

REM Try 2: Search PATH for python.exe
for /f "delims=" %%p in ('where python.exe 2^>nul') do (
    set "PYTHON_EXE=%%p"
    goto python_ok
)

REM Try 3: Search PATH for pythonw.exe
for /f "delims=" %%p in ('where pythonw.exe 2^>nul') do (
    set "PYTHON_EXE=%%p"
    goto python_ok
)

REM Failed
echo [ERROR] Python.exe not found.
echo [*] Please set python_path in config.ini to your Python installation path.
echo [*] Common paths: C:\Python310\python.exe
echo [*]             or C:\Users\%%USERNAME%%\AppData\Local\Programs\Python\Python310\python.exe
exit /b 1

:python_ok
echo [*] Using Python: !PYTHON_EXE!
echo.

REM ---- Clean old port files ----
del /q "%TEMP%\.wpe_server_port_*" 2>nul

REM ---- Step 1: Launch IDA (plugin auto-loads, WPeServer starts) ----
echo [*] Step 1/2: Launching IDA with WPeGPT plugin (minimized)...
start /MIN "WPeGPT-IDA" !IDA_RUN! -A "%BINARY%"

REM ---- Step 2: Wait for WPeServer port file, then run controller ----
echo [*] Step 2/2: Waiting for WPeServer to be ready...
set WAIT_COUNT=0
set MAX_WAIT=240

:wait_loop
timeout /t 2 /nobreak >nul
set /a WAIT_COUNT+=1

set PORT_FILE=
for /f "delims=" %%f in ('dir /b /o-d "%TEMP%\.wpe_server_port_*" 2^>nul') do (
    set "PORT_FILE=%%f"
    goto found_port
)

if !WAIT_COUNT! geq !MAX_WAIT! (
    echo [ERROR] WPeServer did not start within !MAX_WAIT! seconds.
    echo [*] Check the IDA Output window for WPeGPT startup errors.
    echo [*] Ensure WPeGPT.py is installed in IDA's plugins directory.
    exit /b 1
)
goto wait_loop

:found_port
echo [*] WPeServer detected (port file: !PORT_FILE!)
echo.
echo [*] Starting !MODE! analysis (this may take a few minutes)...
echo.

REM Run the controller - it connects to WPeServer via TCP and drives analysis
"!PYTHON_EXE!" "!CONTROLLER_PATH!" --mode !MODE!

set EXIT_CODE=!ERRORLEVEL!

echo.
if !EXIT_CODE! equ 0 (
    echo.
    echo ========================================
    echo  Reports
    echo ========================================
    for %%F in ("%BINARY%") do (
        set "BINARY_DIR=%%~dpF"
        set "BINARY_NAME=%%~nxF"
    )
    set "REPORT_DIR=!BINARY_DIR!!BINARY_NAME!_WPeAI_Results"
    echo  Dir : !REPORT_DIR!
    echo  JSON: !REPORT_DIR!\analysis_report-!MODE!.json
    echo  MD  : !REPORT_DIR!\analysis_report-!MODE!.md
    echo ========================================
) else (
    echo [WARN] Analysis exited with code !EXIT_CODE!, check output above.
)

echo.
echo [*] Done!
