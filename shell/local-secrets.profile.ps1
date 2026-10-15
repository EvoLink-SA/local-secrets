# local-secrets : chargement automatique des secrets d'un projet dans ce terminal PowerShell.
#
# En entrant dans un dossier dont le .env (ou celui d'un dossier parent) contient des références
# secret://, les vraies valeurs sont placées en mémoire, dans les variables d'environnement de cette
# session. Elles sont retirées en sortant du projet, et les valeurs d'avant sont rétablies.
# docker compose, npm, python ou un VS Code lancé d'ici les reçoivent sans « secret run ».
# Rien n'est écrit sur le disque. Ligne ajoutée au profil par install.ps1.
#
# Update-LocalSecrets -Force  recharge après un « secret set » (sinon, au prochain changement de dossier).

if ($env:CLAUDECODE -eq '1') { return }   # jamais dans les shells des outils de Claude Code
if (-not (Get-Command secret -CommandType Application -ErrorAction SilentlyContinue)) { return }

$global:LocalSecretsState = @{ Dir = $null; Stamp = $null; Saved = @{} }

function global:Update-LocalSecrets {
    [CmdletBinding()]
    param([switch]$Force)

    $location = Get-Location
    if ($location.Provider.Name -ne 'FileSystem') { return }
    $state = $global:LocalSecretsState

    # Raccourci : sans .env dans ce dossier ni ses parents, rien à lancer.
    $probe = $location.ProviderPath
    $found = $false
    for ($i = 0; $i -lt 8 -and $probe; $i++) {
        if (Test-Path -LiteralPath (Join-Path $probe '.env') -PathType Leaf) { $found = $true; break }
        $probe = Split-Path -Parent $probe
    }
    if (-not $found -and -not $state.Dir -and -not $Force) { return }

    $data = $null
    if ($found) {
        $json = & secret env --dir $location.ProviderPath 2>$null
        if ($LASTEXITCODE -eq 0 -and $json) { $data = ($json -join '') | ConvertFrom-Json }
    }
    if (-not $Force -and $data -and $data.dir -eq $state.Dir -and $data.stamp -eq $state.Stamp) { return }
    if (-not $data -and -not $state.Dir) { return }

    $previousDir = $state.Dir
    foreach ($name in @($state.Saved.Keys)) {
        $before = $state.Saved[$name]
        if ($null -eq $before) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
        else { Set-Item -LiteralPath "Env:$name" -Value $before }
    }
    $state.Saved = @{}
    $state.Dir = $null
    $state.Stamp = $null

    if ($data) {
        foreach ($p in $data.vars.PSObject.Properties) {
            $state.Saved[$p.Name] = [Environment]::GetEnvironmentVariable($p.Name)
            Set-Item -LiteralPath "Env:$($p.Name)" -Value $p.Value
        }
        $state.Dir = $data.dir
        $state.Stamp = $data.stamp
        if ($data.dir -ne $previousDir -or $Force) {
            Write-Host "local-secrets : $($state.Saved.Count) secret(s) chargé(s) pour $($data.dir)" -ForegroundColor DarkGray
        }
    }
    elseif ($previousDir) {
        Write-Host "local-secrets : secrets de $previousDir retirés" -ForegroundColor DarkGray
    }
}

$global:LocalSecretsPreviousAction = $ExecutionContext.SessionState.InvokeCommand.LocationChangedAction
$ExecutionContext.SessionState.InvokeCommand.LocationChangedAction = {
    param($sender, $eventArgs)
    if ($global:LocalSecretsPreviousAction) { & $global:LocalSecretsPreviousAction $sender $eventArgs }
    Update-LocalSecrets
}
Update-LocalSecrets
