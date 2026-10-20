#requires -Version 7
# Compile secret.exe (Native AOT) dans plugins\local-secrets\bin puis lance les tests internes.
# Native AOT demande les outils C++ de Visual Studio (charge « Développement Desktop en C++ »).
# Sans eux : -FrameworkDependent produit un exe qui exige le runtime .NET 10 sur le poste.
param([switch]$FrameworkDependent)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'src\LocalSecrets\LocalSecrets.csproj'
$bin = Join-Path $PSScriptRoot 'plugins\local-secrets\bin'

# Le script de détection du linker appelle vswhere.exe sans chemin complet.
$installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
if (Test-Path (Join-Path $installer 'vswhere.exe')) { $env:PATH = "$installer;$env:PATH" }

$extra = if ($FrameworkDependent) { @('-p:PublishAot=false', '-p:SelfContained=false', '-p:PublishSingleFile=true') } else { @() }
dotnet publish $project -c Release -nologo -v q -o $bin @extra
if ($LASTEXITCODE) {
    throw 'échec de la compilation (pour Native AOT, il faut les outils C++ de Visual Studio ; sinon relance avec -FrameworkDependent)'
}

& (Join-Path $bin 'secret.exe') selftest | Select-Object -Last 1
if ($LASTEXITCODE) { throw 'tests internes en échec : lance « secret selftest » pour le détail' }
"secret.exe prêt : $bin"
