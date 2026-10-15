#requires -Version 7
# Compile secret.exe dans plugins\local-secrets\bin puis lance les tests internes.
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'src\LocalSecrets\LocalSecrets.csproj'
$bin = Join-Path $PSScriptRoot 'plugins\local-secrets\bin'

dotnet publish $project -c Release -nologo -v q -o $bin
if ($LASTEXITCODE) { throw 'échec de la compilation' }

& (Join-Path $bin 'secret.exe') selftest | Select-Object -Last 1
if ($LASTEXITCODE) { throw 'tests internes en échec : lance « secret selftest » pour le détail' }
"secret.exe prêt : $bin"
