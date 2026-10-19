# Lancé par e2e.ps1 dans une console PowerShell masquée, comme un vrai terminal de l'utilisateur.
# N'écrit que des booléens dans le fichier résultat, jamais de valeur.
param([string]$Project, [string]$Outside, [string]$Result, [string]$Expected, [string]$Bin)

Remove-Item Env:CLAUDECODE -ErrorAction SilentlyContinue
$env:Path = "$Bin;$env:Path"
$env:PREEXISTING_TOKEN = 'garde-moi'
$lines = @()
. (Join-Path $PSScriptRoot '..\shell\local-secrets.profile.ps1')

Set-Location -LiteralPath $Project
$lines += "loaded=$($env:DB_PASSWORD -eq $Expected)"
$lines += "overridden=$($env:PREEXISTING_TOKEN -ne 'garde-moi' -and $env:PREEXISTING_TOKEN.Length -gt 0)"
Set-Location -LiteralPath (Join-Path $Project 'src')
$lines += "subdir=$($env:DB_PASSWORD -eq $Expected)"

# secret show --window lancé depuis ce shell, sans redirection : la console est partagée avec
# PowerShell, l'affichage doit être refusé tout de suite (sinon il attendrait une touche).
$show = Start-Process (Get-Command secret).Source -ArgumentList 'show', '--window' -NoNewWindow -PassThru
$exited = $show.WaitForExit(3000)
if (-not $exited) { $show.Kill() }
$lines += "shared-console-refused=$($exited -and $show.ExitCode -ne 0)"

Set-Location -LiteralPath $Outside
$lines += "removed=$([string]::IsNullOrEmpty($env:DB_PASSWORD))"
$lines += "restored=$($env:PREEXISTING_TOKEN -eq 'garde-moi')"

$lines | Set-Content -LiteralPath $Result
