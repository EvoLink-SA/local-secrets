#requires -Version 7
# Tests de bout en bout de secret.exe : CLI et hooks, dans un coffre et un projet temporaires.
# Les valeurs ci-dessous sont factices.
param([string]$Exe = (Join-Path $PSScriptRoot '..\plugins\local-secrets\bin\secret.exe'))

$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path $Exe).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('local-secrets-e2e-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$env:LOCAL_SECRETS_HOME = Join-Path $root 'home'
$proj = Join-Path $root 'monprojet'
New-Item -ItemType Directory -Force (Join-Path $proj 'sub') | Out-Null
$script:failures = 0

function Check([bool]$condition, [string]$label) {
    if ($condition) { "  OK     $label" } else { "  ÉCHEC  $label"; $script:failures++ }
}

Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue
Remove-Item Env:LOCAL_SECRETS_LEGACY_DIRS -ErrorAction SilentlyContinue

function Hook([string]$event, [hashtable]$payload) {
    if (-not $payload.ContainsKey('cwd')) { $payload.cwd = $proj }
    $payload.session_id = 'e2e'
    ($payload | ConvertTo-Json -Depth 10 -Compress) | & $Exe hook $event | Out-String
}

$secrets = 'Xk9#mP2vL!q', 'sk-proj-a8F3kL9mN2pQ7rS4tU6vW', 'Winter2025!'
$envText = @(
    'SERVER_IP=192.168.10.25'
    'FQDN=app.client.ch'
    'HTTP_PORT=8443'
    'TZ=Europe/Zurich'
    'POSTGRES_USER=appuser'
    'POSTGRES_PASSWORD=Xk9#mP2vL!q'
    'API_TOKEN=sk-proj-a8F3kL9mN2pQ7rS4tU6vW'
    'DATABASE_URL=postgres://appuser:Xk9#mP2vL!q@db:5432/app'
    'SSH_USER=root'
    'SSH_PASS=Winter2025!'
    'SMTP_HOST=mail.client.ch'
    'DEBUG=false'
    ''
) -join "`r`n"
$envPath = Join-Path $proj '.env'
[IO.File]::WriteAllText($envPath, $envText)

Push-Location $proj
try {
    'CLI'
    $status = & $Exe status | Out-String
    Check (([regex]::Matches($status, 'à chiffrer')).Count -eq 4) 'status : 4 valeurs à chiffrer avant conversion'

    & $Exe import | Out-Null
    $converted = [IO.File]::ReadAllText($envPath)
    Check (-not ($secrets | Where-Object { $converted.Contains($_) })) 'import : plus aucune valeur sensible en clair dans le fichier'
    Check ($converted.Contains('SERVER_IP=192.168.10.25') -and $converted.Contains('SMTP_HOST=mail.client.ch')) 'import : IP et FQDN laissés en clair'
    Check ($converted.Contains("`r`n") -and $converted.Contains('POSTGRES_PASSWORD=secret://monprojet/POSTGRES_PASSWORD')) 'import : références écrites, fins de ligne CRLF conservées'

    $list = & $Exe list | Out-String
    Check ($list.Contains('monprojet/SSH_PASS') -and -not ($secrets | Where-Object { $list.Contains($_) })) 'list : noms seulement'

    $out = & $Exe run -- cmd /c 'echo pw=%POSTGRES_PASSWORD% ip=%SERVER_IP%' | Out-String
    Check ($out.Contains('pw=[secret:monprojet/POSTGRES_PASSWORD]') -and $out.Contains('ip=192.168.10.25')) 'run : variables injectées, valeur masquée dans la sortie'

    $out = & $Exe run -- cmd /c 'echo secret://SSH_PASS' | Out-String
    Check ($out.Contains('[secret:monprojet/SSH_PASS]') -and -not $out.Contains('Winter2025!')) 'run : secret:// remplacé dans les arguments puis masqué'

    & $Exe run -- cmd /c 'exit 3' | Out-Null
    Check ($LASTEXITCODE -eq 3) "run : code de sortie transmis ($LASTEXITCODE)"

    $out = & $Exe reveal SSH_PASS 2>&1 | Out-String
    Check ($LASTEXITCODE -ne 0 -and -not $out.Contains('Winter2025!')) 'reveal : refusé hors terminal interactif'

    Add-Content -LiteralPath $envPath -Value 'NEW_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' -NoNewline
    & $Exe run -- cmd /c 'echo ok' 2>$null | Out-Null
    Check ([IO.File]::ReadAllText($envPath).Contains('NEW_TOKEN=secret://monprojet/NEW_TOKEN')) 'run : valeur ajoutée en clair chiffrée avant lancement'

    'Valeur-Par-Stdin-42' | & $Exe set EXTRA_PASSWORD | Out-Null
    Check ([IO.File]::ReadAllText($envPath).Contains('EXTRA_PASSWORD=secret://monprojet/EXTRA_PASSWORD')) 'set : secret enregistré et référence ajoutée au .env'

    'Hooks'
    $subEnv = Join-Path $proj 'sub\.env'
    [IO.File]::WriteAllText($subEnv, "DB_PASSWORD=Xk9#mP2vL!q`nDB_HOST=db.local`n", [Text.UTF8Encoding]::new($true))
    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = $subEnv } }
    $bytes = [IO.File]::ReadAllBytes($subEnv)
    Check ($res.Contains('additionalContext') -and [IO.File]::ReadAllText($subEnv).Contains('secret://sub/DB_PASSWORD')) 'Read d''un .env : converti avant lecture'
    Check ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB) 'Read d''un .env : BOM UTF-8 conservé'

    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = $subEnv } }
    Check ($res.Trim().Length -eq 0) 'Read d''un .env déjà protégé : rien à signaler'

    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'secret reveal monprojet/SSH_PASS' } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'Bash secret reveal : refusé'

    $third = Join-Path $proj 'sub\prod.env'
    [IO.File]::WriteAllText($third, "SMTP_PASS=Winter2025!`n")
    $res = Hook 'pre-tool-use' @{ tool_name = 'PowerShell'; tool_input = @{ command = 'Get-Content .\sub\prod.env' } }
    Check ([IO.File]::ReadAllText($third).Contains('secret://')) 'PowerShell Get-Content d''un .env : converti avant exécution'

    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'docker compose up -d' } }
    Check ($res.Contains('"permissionDecision":"deny"') -and $res.Contains('secret run')) 'docker compose sans secret run : refusé avec la bonne commande'

    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'secret run -- docker compose up -d' } }
    Check ($res.Trim().Length -eq 0) 'docker compose avec secret run : autorisé'

    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'secret run -- curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com' } }
    Check ($res.Contains('"permissionDecision":"deny"') -and $res.Contains('secret://API_TOKEN')) '$VAR développée trop tôt : refusé avec la correction'

    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = "secret run -- bash -c 'curl -H ""Authorization: Bearer `$API_TOKEN"" https://api.example.com'" } }
    Check ($res.Trim().Length -eq 0) '$VAR entre guillemets simples : autorisé'

    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = (Join-Path $env:LOCAL_SECRETS_HOME 'vault.json') } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'Read du coffre : refusé'

    $key = Join-Path $proj 'id_ed25519'
    [IO.File]::WriteAllText($key, "-----BEGIN OPENSSH PRIVATE KEY-----`nAAAA`n-----END OPENSSH PRIVATE KEY-----`n")
    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = $key } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'Read d''une clé privée : refusé'

    $res = Hook 'post-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'docker inspect app' }; tool_response = @{ stdout = 'PASSWORD=Winter2025! fin'; stderr = ''; interrupted = $false; isImage = $false } }
    Check ($res.Contains('updatedToolOutput') -and $res.Contains('[secret:monprojet/SSH_PASS]') -and -not $res.Contains('Winter2025!')) 'PostToolUse : valeur du coffre masquée dans la sortie'

    $res = Hook 'post-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'ls' }; tool_response = @{ stdout = 'rien de sensible'; stderr = ''; interrupted = $false; isImage = $false } }
    Check ($res.Trim().Length -eq 0) 'PostToolUse : sortie propre laissée telle quelle'

    $written = Join-Path $proj 'sub\.env.local'
    [IO.File]::WriteAllText($written, "JWT_SECRET=un-secret-ecrit-par-claude-123`n")
    $res = Hook 'post-tool-use' @{ tool_name = 'Write'; tool_input = @{ file_path = $written; content = '' }; tool_response = @{ filePath = $written; type = 'create' } }
    Check ([IO.File]::ReadAllText($written).Contains('secret://')) 'PostToolUse Write d''un .env : converti juste après écriture'

    $res = Hook 'user-prompt-submit' @{ prompt = 'connecte-toi au serveur, le mot de passe est Zq8!rT4#pL' }
    Check ($res.Contains('"decision":"block"')) 'message avec mot de passe : bloqué'
    $res = Hook 'user-prompt-submit' @{ prompt = 'redémarre le conteneur avec secret run' }
    Check ($res.Trim().Length -eq 0) 'message normal : laissé passer'
    $res = Hook 'user-prompt-submit' @{ prompt = 'le mot de passe est Zq8!rT4#pL [nosecret]' }
    Check ($res.Trim().Length -eq 0) 'message marqué [nosecret] : laissé passer'

    $fresh = Join-Path $proj 'compose\.env'
    New-Item -ItemType Directory -Force (Split-Path $fresh) | Out-Null
    [IO.File]::WriteAllText($fresh, "REDIS_PASSWORD=Rd7!kq2Mz`n")
    $env:CLAUDE_PROJECT_DIR = $proj
    $res = Hook 'session-start' @{ source = 'startup' }
    Remove-Item Env:CLAUDE_PROJECT_DIR
    Check ($res.Contains('additionalContext') -and $res.Contains('POSTGRES_PASSWORD') -and -not [IO.File]::ReadAllText($fresh).Contains('secret://')) 'SessionStart : rien converti, clés déjà protégées listées pour Claude'
    Check (-not ($secrets + 'Rd7!kq2Mz' | Where-Object { $res.Contains($_) })) 'SessionStart : aucune valeur dans le contexte'

    'Hôte distant, masquage générique et interrupteur'
    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'ssh root@10.0.0.5 "cd /opt/app && docker compose up -d"' } }
    Check ($res.Trim().Length -eq 0) 'docker compose via ssh : autorisé malgré le .env local protégé'

    $remote = @{ tool_name = 'Bash'; tool_input = @{ command = 'ssh root@10.0.0.5 "cat /opt/app/.env"' }; tool_response = @{ stdout = "DB_HOST=db`nREMOTE_PASSWORD=Zr4!pLm8#q`n"; stderr = ''; interrupted = $false; isImage = $false } }
    $res = Hook 'post-tool-use' $remote
    $seen = if ($res.Trim()) { ($res | ConvertFrom-Json).hookSpecificOutput.updatedToolOutput.stdout } else { '' }
    Check ($seen.Contains('REMOTE_PASSWORD=[masqué:REMOTE_PASSWORD]') -and $seen.Contains('DB_HOST=db') -and -not $res.Contains('Zr4!pLm8#q')) '.env distant : mot de passe inconnu du coffre masqué'

    $env:LOCAL_SECRETS_OUTPUT_MASKING = 'off'
    $res = Hook 'post-tool-use' $remote
    Check ($res.Trim().Length -eq 0) 'interrupteur LOCAL_SECRETS_OUTPUT_MASKING=off : masquage générique coupé'
    $res = Hook 'post-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'x' }; tool_response = @{ stdout = 'PASSWORD=Winter2025!'; stderr = ''; interrupted = $false; isImage = $false } }
    Check ($res.Contains('[secret:monprojet/SSH_PASS]')) 'interrupteur coupé : les valeurs du coffre restent masquées'
    Remove-Item Env:LOCAL_SECRETS_OUTPUT_MASKING

    $config = Join-Path $env:LOCAL_SECRETS_HOME 'config.json'
    @{ outputMasking = $true; outputMaskingOffIn = @($proj); neverMask = @() } | ConvertTo-Json | Set-Content $config
    $res = Hook 'post-tool-use' $remote
    Check ($res.Trim().Length -eq 0) 'masquage coupé pour ce dossier (secret config masking off --here)'
    Remove-Item $config

    $out = & $Exe config masking off 2>&1 | Out-String
    Check ($LASTEXITCODE -ne 0 -and -not (Test-Path $config)) 'secret config masking off : refusé hors terminal interactif'
    $res = Hook 'pre-tool-use' @{ tool_name = 'PowerShell'; tool_input = @{ command = 'secret config masking off --here' } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'Claude ne peut pas couper le masquage'
    $state = & $Exe config | Out-String
    Check ($state.Contains('ici : actif')) 'secret config : état affiché'

    $res = Hook 'pre-tool-use' @{ tool_name = 'Write'; tool_input = @{ file_path = (Join-Path $proj 'app.yml'); content = "db:`n  password: [masqué:password]`n" } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'Write contenant un masque : refusé'
    $doc = Join-Path $proj 'NOTES.md'
    [IO.File]::WriteAllText($doc, "Une sortie masquée ressemble à [masqué:DB_PASSWORD].`n")
    $res = Hook 'pre-tool-use' @{ tool_name = 'Edit'; tool_input = @{ file_path = $doc; old_string = 'Une sortie'; new_string = "Une sortie masquée ressemble à [masqué:DB_PASSWORD], voir aussi" } }
    Check ($res.Trim().Length -eq 0) 'Edit d''un masque déjà présent dans le fichier (doc) : autorisé'

    'Terminal, fenêtre d''affichage, import depuis un serveur, WSL, exclusion'
    $tproj = Join-Path $root 'terminal-projet'
    New-Item -ItemType Directory -Force (Join-Path $tproj 'src') | Out-Null
    $outside = Join-Path $root 'ailleurs'; New-Item -ItemType Directory -Force $outside | Out-Null
    [IO.File]::WriteAllText((Join-Path $tproj '.env'), "DB_HOST=db`nDB_PASSWORD=Ph5!kd8#Wq2`nPREEXISTING_TOKEN=Mz3!rT8#qL5`n")
    $resultFile = Join-Path $root 'probe.txt'
    $bin = Split-Path $Exe
    & $Exe import $tproj | Out-Null   # le terminal ne convertit plus rien de lui-même
    Start-Process pwsh -WindowStyle Hidden -Wait -ArgumentList @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'console-probe.ps1'),
        '-Project', $tproj, '-Outside', $outside, '-Result', $resultFile, '-Expected', 'Ph5!kd8#Wq2', '-Bin', $bin)
    $probe = if (Test-Path $resultFile) { Get-Content $resultFile } else { @() }
    Check ($probe -contains 'loaded=True') 'profil PowerShell : secrets chargés en entrant dans le projet'
    Check ($probe -contains 'overridden=True') 'profil PowerShell : variable existante remplacée pendant le projet'
    Check ($probe -contains 'subdir=True') 'profil PowerShell : toujours chargés dans un sous-dossier'
    Check ($probe -contains 'removed=True') 'profil PowerShell : retirés en sortant du projet'
    Check ($probe -contains 'restored=True') 'profil PowerShell : valeur d''avant rétablie en sortant'
    Check ($probe -contains 'shared-console-refused=True') 'secret show --window dans un terminal partagé : refusé'

    $out = & $Exe env --dir $tproj 2>&1 | Out-String
    Check ($LASTEXITCODE -ne 0 -and -not $out.Contains('Ph5!kd8#Wq2')) 'secret env depuis Claude Code : refusé'

    Push-Location $tproj
    $env:LOCAL_SECRETS_NO_WINDOW = '1'
    $out = & $Exe show | Out-String
    Remove-Item Env:LOCAL_SECRETS_NO_WINDOW
    Check ($out.Contains('fenêtre non ouverte : 2 valeur(s)') -and -not $out.Contains('Ph5!kd8#Wq2')) 'secret show depuis Claude : fenêtre demandée, aucune valeur dans la sortie'
    $out = & $Exe show --window 2>&1 | Out-String
    Check ($LASTEXITCODE -ne 0 -and -not $out.Contains('Ph5!kd8#Wq2')) 'secret show --window avec sortie redirigée : refusé'
    $display = Join-Path $env:LOCAL_SECRETS_HOME 'display.json'
    $win = Start-Process $Exe -ArgumentList 'show', '--window' -WorkingDirectory $tproj -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 1500
    $opened = (Test-Path $display) -and ((Get-Content $display -Raw) -match '"opened"') -and -not $win.HasExited
    Check $opened 'secret show --window dans une console dédiée : accepté, attend la confirmation'
    $res = Hook 'pre-tool-use' @{ tool_name = 'mcp__computer-use__screenshot'; tool_input = @{} }
    Check ($res.Contains('"permissionDecision":"deny"')) 'pendant l''affichage : capture d''écran bloquée'
    $res = Hook 'pre-tool-use' @{ tool_name = 'PowerShell'; tool_input = @{ command = 'Get-Clipboard' } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'pendant l''affichage : Get-Clipboard bloqué'
    Stop-Process -Id $win.Id -Force
    '{"pid":1,"closed":"' + [DateTime]::UtcNow.ToString('o') + '"}' | Set-Content $display
    $res = Hook 'pre-tool-use' @{ tool_name = 'mcp__computer-use__screenshot'; tool_input = @{} }
    Check ($res.Trim().Length -eq 0) 'après fermeture : capture d''écran de nouveau permise'
    $res = Hook 'pre-tool-use' @{ tool_name = 'mcp__computer-use__read_clipboard'; tool_input = @{} }
    Check ($res.Contains('"permissionDecision":"deny"')) 'après fermeture : presse-papiers encore bloqué dix minutes'
    Remove-Item $display
    Pop-Location

    $import = Join-Path $root 'import-projet'
    New-Item -ItemType Directory -Force $import | Out-Null
    [IO.File]::WriteAllText((Join-Path $import '.env'), "COMPOSE_PROJECT_NAME=app`n")
    Push-Location $import
    $out = "DB_HOST=db.interne`nDB_PASSWORD=""Qv4!ns 9#Lx""`nAUTRE=1`n" | & $Exe import --stdin --only DB_PASSWORD,DB_HOST | Out-String
    $content = [IO.File]::ReadAllText((Join-Path $import '.env'))
    Check ($content.Contains('DB_PASSWORD=secret://import-projet/DB_PASSWORD') -and $content.Contains('DB_HOST=db.interne') -and -not $content.Contains('AUTRE')) 'import --stdin : secret chiffré, clé en clair reprise, --only respecté'
    Check (-not $out.Contains('Qv4!ns')) 'import --stdin : aucune valeur dans la sortie'
    $same = & $Exe run -- cmd /c 'if "%DB_PASSWORD%"=="Qv4!ns 9#Lx" (echo identique) else (echo differente)' | Out-String
    Check ($same.Contains('identique')) 'import --stdin : valeur entre guillemets reprise sans les guillemets'
    $wsl = Get-Command "$env:SystemRoot\System32\wsl.exe" -ErrorAction SilentlyContinue
    if ($wsl) {
        $len = & $Exe run -- "$env:SystemRoot\System32\wsl.exe" -e sh -c 'echo len=${#DB_PASSWORD}' 2>$null | Out-String
        Check ($len.Contains('len=11')) "WSL : variables transmises ($($len.Trim()))"
    }
    Pop-Location

    $excluded = Join-Path $root 'exclu'
    New-Item -ItemType Directory -Force $excluded | Out-Null
    [IO.File]::WriteAllText((Join-Path $excluded '.env'), "SECRET_KEY=Lp9!wx2#Rt6`n")
    [IO.File]::WriteAllText((Join-Path $excluded 'public.env'), "PORT=8080`n")
    @{ conversionOffIn = @($excluded) } | ConvertTo-Json | Set-Content (Join-Path $env:LOCAL_SECRETS_HOME 'config.json')
    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = (Join-Path $excluded '.env') } }
    Check ($res.Contains('"permissionDecision":"deny"') -and [IO.File]::ReadAllText((Join-Path $excluded '.env')).Contains('Lp9!')) 'dossier exclu : fichier non modifié, lecture par Claude bloquée'
    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = (Join-Path $excluded 'public.env') } }
    Check ($res.Trim().Length -eq 0) 'dossier exclu : un .env sans secret reste lisible'
    Remove-Item (Join-Path $env:LOCAL_SECRETS_HOME 'config.json')

    $env:DB_PASSWORD = 'deja-injecte'; $env:PREEXISTING_TOKEN = 'deja-injecte'
    $hookIn = @{ tool_name = 'Bash'; cwd = $tproj; session_id = 'e2e'; tool_input = @{ command = 'docker compose up -d' } } | ConvertTo-Json -Compress
    $res = $hookIn | & $Exe hook pre-tool-use | Out-String
    Remove-Item Env:DB_PASSWORD, Env:PREEXISTING_TOKEN
    Check ($res.Trim().Length -eq 0) 'secrets déjà chargés par le terminal : docker compose sans secret run autorisé'

    'Format clé:valeur dans un .env'
    $colonDir = Join-Path $root 'vm-projet'
    New-Item -ItemType Directory -Force $colonDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $colonDir '.env'), "ssh_user:shay`nssh_password:Zq8!rT4#pLm`nAPI_URL=https://api.client.ch`n")
    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; cwd = $colonDir; tool_input = @{ file_path = (Join-Path $colonDir '.env') } }
    $content = [IO.File]::ReadAllText((Join-Path $colonDir '.env'))
    Check ($content.Contains('ssh_password:secret://vm-projet/ssh_password') -and $content.Contains('ssh_user:shay') -and -not $content.Contains('Zq8!')) '.env au format clé:valeur : mot de passe chiffré avant lecture, format conservé'
    Push-Location $colonDir
    $same = & $Exe run -- cmd /c 'if "%ssh_password%"=="Zq8!rT4#pLm" (echo identique) else (echo differente)' | Out-String
    Pop-Location
    Check ($same.Contains('identique')) '.env au format clé:valeur : valeur injectée par secret run'

    '0.1.3 : périmètre des conversions, annulation, fusion des coffres, valeurs faibles'
    $grepDir = Join-Path $proj 'recherche'
    New-Item -ItemType Directory -Force $grepDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $grepDir '.env'), "GREP_PASSWORD=Gq7!mz2#Lp4`n")
    $res = Hook 'pre-tool-use' @{ tool_name = 'Grep'; tool_input = @{ pattern = 'PASSWORD'; path = $proj } }
    Check (-not [IO.File]::ReadAllText((Join-Path $grepDir '.env')).Contains('secret://')) 'recherche dans un dossier : aucun .env converti'

    $other = Join-Path $root 'autre-depot'
    New-Item -ItemType Directory -Force (Join-Path $other '.git') | Out-Null
    [IO.File]::WriteAllText((Join-Path $other '.env'), "OTHER_PASSWORD=Ot5!kw8#Rz1`n")
    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; cwd = $root; tool_input = @{ file_path = (Join-Path $other '.env') } }
    Check ($res.Contains('"permissionDecision":"deny"') -and -not [IO.File]::ReadAllText((Join-Path $other '.env')).Contains('secret://')) '.env d''un autre dépôt sous la racine : non converti, lecture bloquée'

    $deploy = Join-Path $proj 'deploy'
    New-Item -ItemType Directory -Force $deploy | Out-Null
    [IO.File]::WriteAllText((Join-Path $deploy 'kb.env'), "# local-secrets: ignore`nKB_SQL_DSN=postgres://kb:Kb4!sq9#Xt2@db/kb`n")
    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = (Join-Path $deploy 'kb.env') } }
    Check ($res.Contains('"permissionDecision":"deny"') -and -not [IO.File]::ReadAllText((Join-Path $deploy 'kb.env')).Contains('secret://')) 'marqueur ignore : fichier jamais converti, lecture bloquée'

    $out = & $Exe undo --under $root --dry-run 2>&1 | Out-String
    Check ($LASTEXITCODE -eq 0 -and $out.Contains('à restaurer') -and $out.Contains('Simulation')) 'undo --under --dry-run : fichiers convertis listés, rien modifié'
    $out = & $Exe undo --under $root 2>&1 | Out-String
    Check ($LASTEXITCODE -ne 0) 'undo réel : refusé hors terminal interactif'

    $res = Hook 'pre-tool-use' @{ tool_name = 'mcp__ccd_turn__update_plan'; tool_input = @{ items = @(@{ content = 'Annuler avec secret undo --under'; status = 'pending' }) } }
    Check ($res.Trim().Length -eq 0) 'outil MCP qui n''exécute rien : texte « secret undo » accepté'
    $res = Hook 'pre-tool-use' @{ tool_name = 'mcp__terminal__run_in_terminal'; tool_input = @{ command = 'secret undo --under C:\tools' } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'terminal MCP : secret undo refusé'

    'guest' | & $Exe set weak/RABBITMQ_DEFAULT_PASS | Out-Null
    $res = Hook 'post-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'docker logs mq' }; tool_response = @{ stdout = "user guest connected`nRABBITMQ_DEFAULT_PASS=guest`n"; stderr = ''; interrupted = $false; isImage = $false } }
    $seen = if ($res.Trim()) { ($res | ConvertFrom-Json).hookSpecificOutput.updatedToolOutput.stdout } else { '' }
    Check ($seen.Contains('user guest connected') -and $seen -match 'RABBITMQ_DEFAULT_PASS=\[secret:weak/' -and -not $seen.Contains('PASS=guest')) 'valeur faible : mot courant intact, masquée à côté de son nom'
    $res = Hook 'user-prompt-submit' @{ prompt = 'le compte guest de RabbitMQ ne marche plus' }
    Check ($res.Trim().Length -eq 0) 'valeur faible : message contenant ce mot envoyé'

    $savedHome = $env:LOCAL_SECRETS_HOME
    $legacyA = Join-Path $root 'ancien-a'; $legacyB = Join-Path $root 'ancien-b'; $unified = Join-Path $root 'coffre-unique'
    $env:LOCAL_SECRETS_HOME = $legacyA
    'ValeurA-111!x' | & $Exe set mig/ONLY_A | Out-Null
    'Commune-Ancienne1!' | & $Exe set mig/COMMON | Out-Null
    Start-Sleep -Milliseconds 1200
    $env:LOCAL_SECRETS_HOME = $legacyB
    'ValeurB-222!y' | & $Exe set mig/ONLY_B | Out-Null
    'Commune-Recente2!' | & $Exe set mig/COMMON | Out-Null
    $env:LOCAL_SECRETS_HOME = $unified
    $env:LOCAL_SECRETS_LEGACY_DIRS = "$legacyA;$legacyB"
    $names = & $Exe list 2>&1 | Where-Object { $_ -match '^mig/' } | ForEach-Object { ($_ -split '\s+')[0] }
    Check (@($names).Count -eq 3) "fusion des anciens coffres : 3 secrets réunis ($(@($names) -join ', '))"
    $same = & $Exe run -s mig/COMMON=COMMON -- cmd /c 'if "%COMMON%"=="Commune-Recente2!" (echo recente) else (echo ancienne)' | Out-String
    Check ($same.Contains('recente')) 'fusion : en cas de conflit, la valeur la plus récente gagne'
    & $Exe migrate 2>&1 | Out-Null
    $names = & $Exe list 2>&1 | Where-Object { $_ -match '^mig/' }
    Check (@($names).Count -eq 3 -and (Test-Path (Join-Path $legacyA 'vault.json'))) 'fusion répétée : rien en double, anciens coffres laissés intacts'
    Remove-Item Env:LOCAL_SECRETS_LEGACY_DIRS
    $env:LOCAL_SECRETS_HOME = $savedHome

    '0.1.4 : generate, setenv, fichiers marqués, fichiers d''identifiants, désinstallation, rappel de sauvegarde'
    $out = & $Exe generate GEN_PASSWORD | Out-String
    $len = & $Exe run -- pwsh -NoProfile -Command '$env:GEN_PASSWORD.Length' | Out-String
    Check ($LASTEXITCODE -eq 0 -and [IO.File]::ReadAllText($envPath).Contains('GEN_PASSWORD=secret://monprojet/GEN_PASSWORD') -and $len.Trim() -eq '32') 'generate : valeur de 32 caractères au coffre, référence dans le .env'
    Check ($out -notmatch '[A-Za-z0-9]{32}') 'generate : valeur jamais affichée'

    $kb = Join-Path $deploy 'kb.env'
    $before = [IO.File]::ReadAllText($kb)
    $out = & $Exe generate KB_API_TOKEN --env $kb 2>&1 | Out-String
    Check ($LASTEXITCODE -ne 0 -and [IO.File]::ReadAllText($kb) -eq $before) 'generate sur un fichier marqué ignore : refusé sans --clear'
    $out = & $Exe generate KB_API_TOKEN --env $kb --clear 2>&1 | Out-String
    $after = [IO.File]::ReadAllText($kb)
    Check ($LASTEXITCODE -eq 0 -and $after -match 'KB_API_TOKEN=[A-Za-z0-9]{32}' -and -not $after.Contains('secret://') -and $out -notmatch '[A-Za-z0-9]{32}') 'generate --clear : valeur écrite en clair dans le fichier marqué, jamais affichée'
    & $Exe setenv $kb KB_PORT 5433 | Out-Null
    Check ([IO.File]::ReadAllText($kb).Contains('KB_PORT=5433')) 'setenv : valeur publique écrite dans le fichier marqué'
    & $Exe setenv $kb KB_PASSWORD 'Zq8!rT4#pLm' 2>&1 | Out-Null
    Check ($LASTEXITCODE -ne 0 -and -not [IO.File]::ReadAllText($kb).Contains('KB_PASSWORD')) 'setenv : valeur sensible refusée'
    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = "secret status '$kb'" } }
    Check ($res.Trim().Length -eq 0) 'secret status sur un fichier marqué : autorisé'
    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = "cat '$kb'" } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'cat sur un fichier marqué avec secrets en clair : refusé'

    $pgpass = Join-Path $proj '.pgpass'
    [IO.File]::WriteAllText($pgpass, "db.local:5432:app:appuser:Zq8rT4pLmX9`n")
    $res = Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = $pgpass } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'Read d''un .pgpass : refusé'
    $res = Hook 'post-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'cat ~/.pgpass' }; tool_response = @{ stdout = "db.local:5432:app:appuser:Zq8rT4pLmX9`n"; stderr = ''; interrupted = $false; isImage = $false } }
    Check ($res.Contains('updatedToolOutput') -and -not $res.Contains('Zq8rT4pLmX9')) 'sortie d''un .pgpass : mot de passe masqué'

    $out = & $Exe unprotect --all --dry-run 2>&1 | Out-String
    Check ($LASTEXITCODE -eq 0 -and $out.Contains('Simulation') -and $out.Contains('monprojet')) 'unprotect --all --dry-run : fichiers listés, rien modifié'
    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'secret unprotect --all --dry-run' } }
    Check ($res.Trim().Length -eq 0) 'unprotect --all --dry-run : autorisé pour Claude'
    $res = Hook 'pre-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'secret unprotect --all --dry-run; secret unprotect --all' } }
    Check ($res.Contains('"permissionDecision":"deny"')) 'dry-run suivi de la vraie commande : refusé'

    $nobin = Join-Path $root 'sans-exe'
    New-Item -ItemType Directory -Force $nobin | Out-Null
    Copy-Item (Join-Path (Split-Path $Exe) 'hook.cmd') $nobin
    $cmdHook = Join-Path $nobin 'hook.cmd'
    '{"tool_name":"Read","tool_input":{"file_path":"C:\\p\\.env"}}' | cmd /d /c $cmdHook pre-tool-use 2>$null | Out-Null
    Check ($LASTEXITCODE -eq 2) 'secret.exe absent : lecture d''un .env bloquée par hook.cmd'
    '{"tool_name":"Read","tool_input":{"file_path":"C:\\p\\README.md"}}' | cmd /d /c $cmdHook pre-tool-use 2>$null | Out-Null
    Check ($LASTEXITCODE -eq 0) 'secret.exe absent : le reste passe'
    $warn = '{}' | cmd /d /c $cmdHook session-start | Out-String
    Check ($warn.Contains('systemMessage')) 'secret.exe absent : avertissement au démarrage de session'

    $savedHome = $env:LOCAL_SECRETS_HOME
    $env:LOCAL_SECRETS_HOME = Join-Path $root 'rappel'
    $empty = Join-Path $root 'vide'; New-Item -ItemType Directory -Force $empty | Out-Null
    'Valeur-Rappel-9!x' | & $Exe set rappel/TOKEN | Out-Null
    $r1 = Hook 'session-start' @{ source = 'startup'; cwd = $empty }
    $r2 = Hook 'session-start' @{ source = 'startup'; cwd = $empty }
    Check ($r1.Contains('secret backup') -and -not $r2.Contains('secret backup')) 'rappel de sauvegarde : affiché une fois, pas à chaque session'
    $env:LOCAL_SECRETS_HOME = $savedHome

    'Non-régression : faux positifs du masquage générique'
    $hooksJson = Get-Content -Raw (Join-Path $PSScriptRoot '..\plugins\local-secrets\hooks\hooks.json')
    $res = Hook 'post-tool-use' @{ tool_name = 'Bash'; tool_input = @{ command = 'cat hooks.json' }; tool_response = @{ stdout = $hooksJson; stderr = ''; interrupted = $false; isImage = $false } }
    Check ($res.Trim().Length -eq 0) 'hooks.json du plugin : rien de masqué (matcher, commandes, chemins)'
    $res = Hook 'post-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = 'package-lock.json' }; tool_response = @{ type = 'text'; file = @{ content = '"integrity": "sha512-Q2hhbmdlTWVQbGVhc2UxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==", "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"' } } }
    Check ($res.Trim().Length -eq 0) 'empreintes d''un package-lock : rien de masqué'
    $res = Hook 'user-prompt-submit' @{ prompt = 'regarde ce hooks.json : { "matcher": "Read|Edit|Grep|Bash|PowerShell|mcp__.*", "type": "command" }' }
    Check ($res.Trim().Length -eq 0) 'config JSON collée dans le chat, sans secret : message envoyé'

    $time = (Measure-Command { Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = (Join-Path $proj 'README.md') } } }).TotalMilliseconds
    "  info   temps d'un hook sans rien à faire : {0:N0} ms" -f $time
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
    Remove-Item Env:LOCAL_SECRETS_HOME -ErrorAction SilentlyContinue
}

if ($script:failures -eq 0) { 'Tous les tests de bout en bout passent.' } else { "$($script:failures) test(s) en échec."; exit 1 }
