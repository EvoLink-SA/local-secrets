#requires -Version 7
# Installe local-secrets pour l'utilisateur courant, sans droits administrateur :
# vérifie secret.exe (livré compilé, ou recompilé avec -Build), l'ajoute au PATH utilisateur,
# branche le chargement automatique dans le profil PowerShell 7, installe le plugin Claude Code.
# Désinstallation : uninstall.ps1.
param(
    [switch]$Build,
    [switch]$NoBuild,   # ancien nom, sans effet : c'est le comportement par défaut
    [switch]$NoShellIntegration
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$bin = Join-Path $root 'plugins\local-secrets\tools'
$exe = Join-Path $bin 'secret.exe'
$profileScript = Join-Path $root 'shell\local-secrets.profile.ps1'

# L'exe versionné est natif (Native AOT) : ni SDK ni runtime .NET nécessaires pour l'installer.
if ($Build -or -not (Test-Path $exe)) { & (Join-Path $root 'build.ps1') }
else {
    & $exe selftest | Select-Object -Last 1
    if ($LASTEXITCODE) { throw 'tests internes en échec : lance « secret selftest » pour le détail' }
}

'1. PATH utilisateur'
$entries = @(([Environment]::GetEnvironmentVariable('Path', 'User') ?? '') -split ';' | Where-Object { $_ })
# Jusqu'à la 0.2.1, les exécutables étaient dans bin\, dossier que claude.ai refuse dans un plugin.
$oldBin = Join-Path $root 'plugins\local-secrets\bin'
if ($entries -contains $oldBin) {
    $entries = @($entries | Where-Object { $_ -ne $oldBin })
    [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User')
    "   ancien dossier retiré : $oldBin"
}
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
    # Ligne protégée par Test-Path : un profil synchronisé (OneDrive) sur un PC sans l'outil ne casse rien.
    $profilePath = $PROFILE.CurrentUserAllHosts
    $line = "if (Test-Path '$profileScript') { . '$profileScript' }  # local-secrets"
    $current = if (Test-Path $profilePath) { Get-Content -Raw $profilePath } else { '' }
    $existing = [regex]::Match($current, '(?m)^.*# local-secrets\s*$')
    if ($existing.Success -and $existing.Value.Trim() -eq $line) {
        '   déjà en place.'
    }
    elseif ($existing.Success) {
        Set-Content -Path $profilePath -Value ($current.Replace($existing.Value, $line)) -NoNewline
        "   ligne mise à jour dans $profilePath"
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
