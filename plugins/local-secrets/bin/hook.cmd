@echo off
rem local-secrets : lanceur des hooks. Si secret.exe manque ou ne demarre pas (antivirus, mise a
rem jour en cours, fichier abime), il le dit clairement et ne bloque que les acces qui visent un .env, au lieu de bloquer
rem tous les outils de Claude.
setlocal
set "EVENT=%~1"
set "EXE=%~dp0secret.exe"
if not exist "%EXE%" goto broken
"%EXE%" hook %EVENT%
if %errorlevel% neq 0 goto broken
exit /b 0

:broken
if /i "%EVENT%"=="session-start" goto warn_session
if /i "%EVENT%"=="pre-tool-use" goto guard
exit /b 0

:warn_session
echo {"systemMessage":"local-secrets : secret.exe est introuvable ou ne démarre pas. La protection des fichiers .env est inactive et Claude ne pourra pas les lire. Lance secret doctor, ou réinstalle le plugin."}
exit /b 0

:guard
findstr /i /l /c:".env" >nul
if %errorlevel% neq 0 exit /b 0
echo local-secrets : secret.exe est introuvable ou ne démarre pas. Accès à ce fichier .env bloqué par précaution, pour que ses valeurs ne te soient pas transmises. Demande à l'utilisateur de lancer secret doctor, ou de désactiver le plugin : claude plugin disable local-secrets@local-secrets 1>&2
exit /b 2
