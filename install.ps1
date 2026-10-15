#requires -Version 7
# Installe local-secrets pour l'utilisateur courant, sans droits administrateur :
# compile secret.exe, l'ajoute au PATH utilisateur, branche le chargement automatique dans le
# profil PowerShell 7, installe le plugin Claude Code.
param(
    [switch]$NoBuild,
    [switch]$NoShellIntegration
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$bin = Join-Path $root 'plugins\local-secrets\bin'
$exe = Join-Path $bin 'secret.exe'
$profileScript = Join-Path $root 'shell\local-secrets.profile.ps1'

if (-not $NoBuild -or -not (Test-Path $exe)) { & (Join-Path $root 'build.ps1') }

'1. PATH utilisateur'
$entries = @(([Environment]::GetEnvironmentVariable('Path', 'User') ?? '') -split ';' | Where-Object { $_ })
if ($entries -notcontains $bin) {
    [Environment]::SetEnvironmentVariable('Path', (($entries + $bin) -join ';'), 'User')
    "   $bin ajouté. Les terminaux et applications lancés à partir de maintenant le verront."
}
else {
    '   déjà en place.'
}
if (($env:Path -split ';') -notcontains $bin) { $env:Path = "$env:Path;$bin" }

'2. Chargement automatique dans PowerShell 7'
if ($NoShellIntegration) {
    '   ignoré (-NoShellIntegration).'
}
else {
    $profilePath = $PROFILE.CurrentUserAllHosts
    $line = ". '$profileScript'  # local-secrets"
    $current = if (Test-Path $profilePath) { Get-Content -Raw $profilePath } else { '' }
    if ($current -match [regex]::Escape('# local-secrets')) {
        '   déjà en place.'
    }
    else {
        New-Item -ItemType Directory -Force (Split-Path $profilePath) | Out-Null
        Add-Content -Path $profilePath -Value "`n$line"
        "   ligne ajoutée à $profilePath"
    }
}

'3. Plugin Claude Code'
$markets = claude plugin marketplace list 2>&1 | Out-String
if ($markets -match 'local-secrets') { claude plugin marketplace update local-secrets }
else { claude plugin marketplace add $root }
if ($LASTEXITCODE) { throw 'ajout de la marketplace locale impossible' }

$plugins = claude plugin list 2>&1 | Out-String
if ($plugins -match 'local-secrets@local-secrets') { claude plugin update local-secrets@local-secrets }
else { claude plugin install local-secrets@local-secrets --scope user }
if ($LASTEXITCODE) { throw 'installation du plugin impossible' }

'4. Vérification'
& $exe doctor
''
'Relance tes terminaux, Claude Code et Claude Desktop pour activer le PATH, le profil et les hooks.'
