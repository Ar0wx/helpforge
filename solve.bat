@echo off
setlocal

cd /d "%~dp0"

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=192.168.56.102"

where py >nul 2>nul
if "%ERRORLEVEL%"=="0" (
    set "PYTHON_CMD=py"
) else (
    where python >nul 2>nul
    if "%ERRORLEVEL%"=="0" (
        set "PYTHON_CMD=python"
    ) else (
        echo [!] Python was not found. Install Python 3 and enable "Add python.exe to PATH".
        exit /b 1
    )
)

%PYTHON_CMD% -c "import paramiko" >nul 2>nul
if not "%ERRORLEVEL%"=="0" (
    echo [!] Missing Python module: paramiko
    echo     Install it with:
    echo     %PYTHON_CMD% -m pip install paramiko
    exit /b 1
)

%PYTHON_CMD% autosolve.py "%TARGET%"
exit /b %ERRORLEVEL%
