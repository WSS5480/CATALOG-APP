@echo off
cd /d "%~dp0"
echo Pushing CATALOG-APP to GitHub...
git add -A
set "MSG=%~1"
if "%MSG%"=="" set /p MSG="Describe the change (Enter for default): "
if "%MSG%"=="" set "MSG=Update catalog app"
git commit -m "%MSG%"
git push origin main
if errorlevel 1 (echo. & echo PUSH FAILED - check the remote is set. ) else (echo. & echo SUCCESS - Render will redeploy.)
echo.
pause
