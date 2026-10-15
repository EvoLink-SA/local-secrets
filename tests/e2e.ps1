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

function Hook([string]$event, [hashtable]$payload) {
    $payload.cwd = $proj
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
    Check ($res.Contains('additionalContext') -and $res.Contains('POSTGRES_PASSWORD') -and [IO.File]::ReadAllText($fresh).Contains('secret://')) 'SessionStart : projet converti, clés listées pour Claude'
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
    [IO.File]::WriteAllText((Join-Path $tproj '.env'), "DB_HOST=db`nDB_PASSWORD=Ph5!kd8#Wq2`nPREEXISTING=Mz3!rT8#qL5`n")
    $resultFile = Join-Path $root 'probe.txt'
    $bin = Split-Path $Exe
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

    $env:DB_PASSWORD = 'deja-injecte'; $env:PREEXISTING = 'deja-injecte'
    $hookIn = @{ tool_name = 'Bash'; cwd = $tproj; session_id = 'e2e'; tool_input = @{ command = 'docker compose up -d' } } | ConvertTo-Json -Compress
    $res = $hookIn | & $Exe hook pre-tool-use | Out-String
    Remove-Item Env:DB_PASSWORD, Env:PREEXISTING
    Check ($res.Trim().Length -eq 0) 'secrets déjà chargés par le terminal : docker compose sans secret run autorisé'

    $time = (Measure-Command { Hook 'pre-tool-use' @{ tool_name = 'Read'; tool_input = @{ file_path = (Join-Path $proj 'README.md') } } }).TotalMilliseconds
    "  info   temps d'un hook sans rien à faire : {0:N0} ms" -f $time
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
    Remove-Item Env:LOCAL_SECRETS_HOME -ErrorAction SilentlyContinue
}

if ($script:failures -eq 0) { 'Tous les tests de bout en bout passent.' } else { "$($script:failures) test(s) en échec."; exit 1 }
