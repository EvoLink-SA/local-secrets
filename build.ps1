#requires -Version 7
# Compile secret.exe (Native AOT) dans plugins\local-secrets\tools puis lance les tests internes.
# Native AOT demande les outils C++ de Visual Studio (charge « Développement Desktop en C++ »).
# Sans eux : -FrameworkDependent produit un exe qui exige le runtime .NET 10 sur le poste.
# -Linux : compile plutôt le binaire linux-x64 (plugins\local-secrets-linux\tools\secret) dans Docker,
# Native AOT ne sachant pas compiler pour Linux depuis Windows.
param([switch]$FrameworkDependent, [switch]$Linux)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'src\LocalSecrets\LocalSecrets.csproj'
$bin = Join-Path $PSScriptRoot 'plugins\local-secrets\tools'

# Le skill est commun aux deux variantes du plugin : la source est celle de Windows.
$skills = Join-Path $PSScriptRoot 'plugins\local-secrets-linux\skills'
New-Item -ItemType Directory -Force $skills | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'plugins\local-secrets\skills\*') $skills -Recurse -Force

if ($Linux) {
    # Image de compilation gardée en cache : SDK .NET 10, plus clang et zlib pour Native AOT.
    $image = 'local-secrets-build:10.0'
    docker image inspect $image *> $null
    if ($LASTEXITCODE) {
        @'
FROM mcr.microsoft.com/dotnet/sdk:10.0
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends clang zlib1g-dev && rm -rf /var/lib/apt/lists/*
'@ | docker build -q -t $image -
        if ($LASTEXITCODE) { throw 'construction de l''image de compilation impossible (Docker Desktop est-il lancé ?)' }
    }
    $out = Join-Path $PSScriptRoot 'plugins\local-secrets-linux\tools'
    New-Item -ItemType Directory -Force $out | Out-Null
    # Les sources sont copiées sans bin\ ni obj\ : ceux de la compilation Windows ne doivent pas s'y mêler.
    $script = 'set -e; mkdir -p /build; cp -r /src/src/LocalSecrets /build/; rm -rf /build/LocalSecrets/bin /build/LocalSecrets/obj; ' +
              'dotnet publish /build/LocalSecrets/LocalSecrets.csproj -c Release -r linux-x64 -nologo -v q -o /out; ' +
              'cp /out/secret /src/plugins/local-secrets-linux/tools/secret; chmod 755 /src/plugins/local-secrets-linux/tools/secret'
    docker run --rm -v "${PSScriptRoot}:/src" -v local-secrets-nuget:/root/.nuget/packages $image bash -c $script
    if ($LASTEXITCODE) { throw 'échec de la compilation Linux' }
    "secret (linux-x64) prêt : $out"
    return
}

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
