#!/usr/bin/env bash
# Test du trousseau de session (Secret Service, GNOME Keyring) pour « secret unlock --remember »,
# lancé dans un conteneur par tests/secret-service.ps1. Coffre jetable, valeurs factices.
set -u
exe=/repo/plugins/local-secrets-linux/tools/secret
export LOCAL_SECRETS_HOME=/tmp/home
failures=0
check() {
    if eval "$1"; then echo "  OK     $2"; else echo "  ÉCHEC  $2"; failures=$((failures + 1)); fi
}

# Trousseau « login » créé et ouvert sans interface, comme à l'ouverture d'une session de bureau.
eval "$(printf 'mot de passe du trousseau' | gnome-keyring-daemon --unlock --components=secrets --daemonize)"
export GNOME_KEYRING_CONTROL

echo 'Trousseau de session'
printf '%s\n' 'phrase de passe de test ss' | "$exe" init --stdin --no-unlock > /dev/null
printf '%s\n' 'phrase de passe de test ss' | "$exe" unlock --stdin --remember > /tmp/out 2>&1
check 'grep -q "trousseau de session" /tmp/out && grep -q "secret-service" "$LOCAL_SECRETS_HOME/key.json"' 'unlock --remember : clé confiée au trousseau de session'
check '! grep -q "privateKey\"[^{]*\"[A-Za-z0-9+/=]\{100,\}\"" "$LOCAL_SECRETS_HOME/key.json"' 'key.json : pas de clé privée en clair'
printf 'Valeur-Factice-SS-1' | "$exe" set test/VALEUR > /dev/null
"$exe" lock > /dev/null
"$exe" run -s test/VALEUR=V -- true 2> /dev/null
check '[ $? -ne 0 ]' 'lock : pas de réouverture automatique après un verrouillage volontaire'
rm -f "$LOCAL_SECRETS_HOME/locked"
"$exe" run -s test/VALEUR=V -- sh -c '[ "$V" = Valeur-Factice-SS-1 ]'
check '[ $? -eq 0 ]' 'réouverture automatique depuis le trousseau, sans phrase de passe'
"$exe" doctor > /tmp/out 2>&1
check 'grep -q "clé mémorisée par : trousseau de session" /tmp/out' 'doctor : clé mémorisée signalée'
"$exe" lock --forget > /dev/null
rm -f "$LOCAL_SECRETS_HOME/locked"
check '[ -z "$(secret-tool lookup application local-secrets 2> /dev/null)" ]' 'lock --forget : clé retirée du trousseau'
"$exe" run -s test/VALEUR=V -- true 2> /dev/null
check '[ $? -ne 0 ]' 'lock --forget : plus de réouverture automatique'

if [ "$failures" -eq 0 ]; then echo 'Tous les tests du trousseau de session passent.'; else echo "$failures test(s) en échec."; exit 1; fi
