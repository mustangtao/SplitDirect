@echo off
cd /d "%~dp0"

rem Old SplitDirect must not be running while building
tasklist /FI "IMAGENAME eq SplitDirect.exe" 2>nul | find /I "SplitDirect.exe" >nul
if not errorlevel 1 (
    echo SplitDirect is running. Right-click its tray icon, choose Exit, then run build.bat again.
    pause
    exit /b 1
)

echo [1/2] Installing dependencies ...
rem -i: Tsinghua PyPI mirror (fast in China). Remove it to use the default PyPI.
python -m pip install -r requirements.txt pyinstaller -i https://pypi.tuna.tsinghua.edu.cn/simple
if errorlevel 1 goto fail

echo.
echo [2/2] Building SplitDirect.exe ...
python -m PyInstaller --noconfirm --clean --windowed --uac-admin --icon splitdirect.ico --name SplitDirect --collect-all pydivert --hidden-import psutil._psutil_windows gui.py
if errorlevel 1 goto fail

echo.
echo Done: %~dp0dist\SplitDirect\SplitDirect.exe
explorer "%~dp0dist\SplitDirect"
pause
exit /b 0

:fail
echo.
echo Build failed. If you report an issue on GitHub, please include the error above.
echo If the error mentions WinDivert64.sys and access denied, the driver is still loaded:
echo run "sc stop WinDivert" in an administrator cmd, or restart the computer, then try again.
pause
exit /b 1
