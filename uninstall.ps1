#requires -Version 7
# Désinstalle local-secrets pour l'utilisateur courant. À lancer dans un terminal, pas depuis Claude.
# Ordre : remettre les valeurs en clair dans les .env (sinon les références secret:// restent
# sans personne pour les résoudre), puis retirer le plugin, le profil et le PATH.
# Le coffre (%USERPROFILE%\.local-secrets) n'est jamais supprimé par ce script.
param([switch]$KeepEnvFiles)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$bin = Join-Path $root 'plugins\local-secrets\tools'
$exe = Join-Path $bin 'secret.exe'

'1. Fichiers .env'
if ($KeepEnvFiles) {
    '   laissés tels quels (-KeepEnvFiles) : les références secret:// ne seront plus résolues.'
}
elseif (Test-Path $exe) {
    & $exe unprotect --all --dry-run
    $answer = Read-Host '   Remettre ces valeurs en clair dans les fichiers ? (o/N)'
    if ($answer -match '^[oOyY]') {
        & $exe unprotect --all
        if ($LASTEXITCODE) { throw 'remise en clair interrompue : rien d''autre n''a été retiré' }
    }
    else {
        '   ignoré : les fichiers gardent leurs références secret://.'
    }
}
else {
    "   secret.exe introuvable ($exe) : étape ignorée."
}

'2. Plugin Claude Code'
$plugins = claude plugin list 2>&1 | Out-String
if ($plugins -match 'local-secrets@local-secrets') { claude plugin uninstall local-secrets@local-secrets }
else { '   plugin absent.' }
$markets = claude plugin marketplace list 2>&1 | Out-String
if ($markets -match 'local-secrets') { claude plugin marketplace remove local-secrets }
else { '   marketplace absente.' }

'3. Profil PowerShell 7'
$profilePath = $PROFILE.CurrentUserAllHosts
if (Test-Path $profilePath) {
    $current = Get-Content -Raw $profilePath
    $cleaned = [regex]::Replace($current, '(?m)^.*# local-secrets[ \t]*\r?\n?', '')
    if ($cleaned -ne $current) {
        Set-Content -Path $profilePath -Value $cleaned -NoNewline
        "   ligne retirée de $profilePath"
    }
    else { '   aucune ligne local-secrets.' }
}
else { '   pas de profil.' }

'4. PATH utilisateur'
$entries = @(([Environment]::GetEnvironmentVariable('Path', 'User') ?? '') -split ';' | Where-Object { $_ })
$oldBin = Join-Path $root 'plugins\local-secrets\bin'   # emplacement jusqu'à la 0.2.1
if ($entries -contains $bin -or $entries -contains $oldBin) {
    [Environment]::SetEnvironmentVariable('Path', (($entries | Where-Object { $_ -ne $bin -and $_ -ne $oldBin }) -join ';'), 'User')
    "   $bin retiré."
}
else { '   déjà absent.' }

''
"Le coffre reste dans $env:USERPROFILE\.local-secrets (secrets chiffrés et copies des .env d'origine)."
'Supprime ce dossier toi-même quand tu es sûr de ne plus en avoir besoin.'
'Relance tes terminaux, Claude Code et Claude Desktop pour finir.'
