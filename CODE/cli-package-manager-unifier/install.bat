@echo off
REM Installation script for Windows
echo Installing unified package manager CLI...
echo.

REM Check if pip is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Install in editable mode
echo Installing package in editable mode...
pip install -e .

if errorlevel 1 (
    echo.
    echo Installation failed!
    pause
    exit /b 1
)

echo.
echo ======================================
echo Installation successful!
echo ======================================
echo.
echo You can now use the following commands:
echo   unified list
echo   unified search ^<package^>
echo   unified install ^<package^> -m ^<manager^>
echo   unified update
echo   unified update ^<package^>
echo   unified upgrade ^<package^> -m ^<manager^>
echo.
echo Note: You may need to restart your terminal for the changes to take effect.
echo.
pause
