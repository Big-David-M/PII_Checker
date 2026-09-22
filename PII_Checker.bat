@echo off
:: Launch PII Checker without a terminal window.
:: Tries pythonw (no console), then pyw, then falls back to py.

where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "" pythonw "%~dp0pii_checker.py"
    exit /b
)

where pyw >nul 2>&1
if %errorlevel%==0 (
    start "" pyw "%~dp0pii_checker.py"
    exit /b
)

where py >nul 2>&1
if %errorlevel%==0 (
    start "" py "%~dp0pii_checker.py"
    exit /b
)

:: Last resort: try the common install path directly
if exist "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" (
    start "" "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" "%~dp0pii_checker.py"
    exit /b
)

echo Python not found. Install Python 3.8+ from https://python.org
echo Or download PII_Checker.exe from the GitHub Releases page.
pause
