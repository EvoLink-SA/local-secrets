#requires -Version 7
# Lance tests/secret-service.sh dans un conteneur Ubuntu avec GNOME Keyring (Secret Service) :
# le trousseau de session d'un bureau Linux ne se teste pas dans WSL sans bureau.
# seccomp=unconfined : le profil par défaut de Docker bloque le trousseau noyau (keyctl).
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$image = 'local-secrets-keyring:24.04'
docker image inspect $image *> $null
if ($LASTEXITCODE) {
    @'
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends gnome-keyring libsecret-tools dbus libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
'@ | docker build -q -t $image -
    if ($LASTEXITCODE) { throw 'construction de l''image de test impossible (Docker Desktop est-il lancé ?)' }
}
docker run --rm --security-opt seccomp=unconfined -v "${root}:/repo:ro" $image dbus-run-session -- bash /repo/tests/secret-service.sh
if ($LASTEXITCODE) { throw 'tests du trousseau de session en échec' }
