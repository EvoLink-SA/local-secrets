#!/usr/bin/env bash
# Tests de bout en bout de secret sous Linux : clé du coffre, CLI, verrouillage et hooks, dans un
# coffre et un projet temporaires. Les valeurs ci-dessous sont factices.
# Usage : tests/e2e.sh [CHEMIN_DU_BINAIRE]   (défaut : plugins/local-secrets-linux/bin/secret)
set -u

here=$(cd "$(dirname "$0")" && pwd)
exe=${1:-$here/../plugins/local-secrets-linux/bin/secret}
root=$(mktemp -d /tmp/local-secrets-e2e-XXXXXXXX)
work="$root/bin"
mkdir -p "$work"
cp "$exe" "$work/secret" && chmod 755 "$work/secret"
exe="$work/secret"
export LOCAL_SECRETS_HOME="$root/home"
unset CLAUDECODE CLAUDE_PROJECT_DIR LOCAL_SECRETS_LEGACY_DIRS
proj="$root/monprojet"
mkdir -p "$proj/sub"
failures=0
pass='phrase de passe de test e2e'

check() {
    if eval "$1"; then echo "  OK     $2"; else echo "  ÉCHEC  $2"; failures=$((failures + 1)); fi
}

# Événement de hook : JSON sur l'entrée standard, comme Claude Code.
hook() {
    printf '%s' "$2" | "$exe" hook "$1"
}

# Masque attendu dans une sortie, construit ici pour que ce fichier n'en contienne aucun tel quel.
mask() {
    printf '[%s:%s]' secret "$1"
}

pg='Xk9#mP2vL!q'
ssh='Zq8!rT4#pLm'
token="tok_a8F3kL9mN2pQ7rS4tU6vW"
cat > "$proj/.env" <<EOF
SERVER_IP=192.168.10.25
FQDN=app.client.ch
POSTGRES_USER=appuser
POSTGRES_PASSWORD=$pg
API_TOKEN=$token
SSH_USER=root
SSH_PASS=$ssh
DEBUG=false
EOF

cd "$proj" || exit 1

echo 'Clé du coffre'
out=$(printf '%s\n' "short" | "$exe" init --stdin 2>&1)
check '[ $? -ne 0 ] && [ ! -f "$LOCAL_SECRETS_HOME/key.json" ]' 'init : phrase trop courte refusée'
out=$(CLAUDECODE=1 "$exe" init --stdin < /dev/null 2>&1)
check '[ $? -ne 0 ] && printf "%s" "$out" | grep -q "réservé à l"' 'init : refusé depuis Claude'
printf '%s\n' "$pass" | "$exe" init --stdin --for 10m > /dev/null
check '[ -f "$LOCAL_SECRETS_HOME/key.json" ]' 'init : clé créée'
check '[ "$(stat -c %a "$LOCAL_SECRETS_HOME")" = 700 ] && [ "$(stat -c %a "$LOCAL_SECRETS_HOME/key.json")" = 600 ]' 'init : dossier en 700, key.json en 600'
check '! grep -qF "$pass" "$LOCAL_SECRETS_HOME/key.json"' 'init : la phrase de passe absente de key.json'
out=$("$exe" doctor 2>&1)
check 'printf "%s" "$out" | grep -q "coffre déverrouillé"' 'doctor : coffre déverrouillé après init'

echo 'CLI'
out=$("$exe" status)
check '[ "$(printf "%s" "$out" | grep -c "à chiffrer")" -eq 3 ]' 'status : 3 valeurs à chiffrer avant conversion'
"$exe" import > /dev/null
check '! grep -qF "$pg" .env && ! grep -qF "$ssh" .env && ! grep -qF "$token" .env' 'import : plus aucune valeur sensible en clair'
check 'grep -q "^POSTGRES_PASSWORD=secret://monprojet/POSTGRES_PASSWORD$" .env && grep -q "^SERVER_IP=192.168.10.25$" .env' 'import : références écrites, IP laissée en clair'
check '[ "$(stat -c %a "$LOCAL_SECRETS_HOME/vault.json")" = 600 ] && [ "$(stat -c %a "$LOCAL_SECRETS_HOME/backups")" = 700 ]' 'import : vault.json en 600, backups en 700'
check 'grep -q "\"protection\": \"ecies-p256\"" "$LOCAL_SECRETS_HOME/vault.json"' 'import : coffre marqué ecies-p256'

"$exe" run -- sh -c '[ "$POSTGRES_PASSWORD" = "'"$pg"'" ] && [ "$SERVER_IP" = 192.168.10.25 ]'
check '[ $? -eq 0 ]' 'run : vraies valeurs injectées'
out=$("$exe" run -- sh -c 'echo "pw=$POSTGRES_PASSWORD"')
check '[ "$out" = "pw=$(mask monprojet/POSTGRES_PASSWORD)" ]' 'run : valeur masquée dans la sortie'
out=$("$exe" run -- echo secret://SSH_PASS)
check '[ "$out" = "$(mask monprojet/SSH_PASS)" ]' 'run : secret:// remplacé dans les arguments puis masqué'
"$exe" run -- sh -c 'exit 3'
check '[ $? -eq 3 ]' 'run : code de sortie transmis'
printf 'Valeur-Par-Stdin-42' | "$exe" set EXTRA_PASSWORD > /dev/null
check 'grep -q "^EXTRA_PASSWORD=secret://monprojet/EXTRA_PASSWORD$" .env' 'set : secret enregistré, référence ajoutée'

echo 'Verrouillage'
"$exe" lock > /dev/null
out=$("$exe" run -- true 2>&1)
check '[ $? -ne 0 ] && printf "%s" "$out" | grep -q "coffre verrouillé"' 'run : refusé coffre verrouillé, avec la marche à suivre'
printf 'NEW_TOKEN=%s\n' "$token" > sub/.env
"$exe" import sub > /dev/null
check 'grep -q "^NEW_TOKEN=secret://" sub/.env && ! grep -qF "$token" sub/.env' 'import : conversion possible coffre verrouillé (clé publique)'
out=$(printf '%s\n' "mauvaise phrase de passe" | "$exe" unlock --stdin 2>&1)
check '[ $? -ne 0 ]' 'unlock : mauvaise phrase refusée'
printf '%s\n' "$pass" | "$exe" unlock --stdin --for 5m > /dev/null
(cd sub && "$exe" run -- sh -c '[ "$NEW_TOKEN" = "'"$token"'" ]')
check '[ $? -eq 0 ]' 'unlock : valeur chiffrée pendant le verrouillage relisible'
printf '%s\n%s\n' "$pass" "nouvelle phrase de passe e2e" | "$exe" passwd --stdin > /dev/null
"$exe" lock > /dev/null
out=$(printf '%s\n' "$pass" | "$exe" unlock --stdin 2>&1)
check '[ $? -ne 0 ]' 'passwd : ancienne phrase refusée'
printf '%s\n' "nouvelle phrase de passe e2e" | "$exe" unlock --stdin > /dev/null
check '[ $? -eq 0 ]' 'passwd : nouvelle phrase acceptée'

echo 'Verrou du coffre'
for i in 1 2 3 4 5 6; do printf 'Parallele-%s-xY9!' "$i" | "$exe" set "par/K$i" > /dev/null & done
wait
check '[ "$("$exe" list --ns par | grep -c "^par/K")" -eq 6 ]' 'six écritures parallèles : aucune perdue'

echo 'Hooks'
printf 'HOOK_PASSWORD=%s\n' "$ssh" > sub/hook.env
out=$(hook pre-tool-use "{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"$proj/sub/hook.env\"},\"cwd\":\"$proj\",\"session_id\":\"e2e\"}")
check 'grep -q "^HOOK_PASSWORD=secret://" sub/hook.env && printf "%s" "$out" | grep -q additionalContext' 'Read d un .env : converti avant lecture'
out=$(hook pre-tool-use "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cat /proc/1/environ\"},\"cwd\":\"$proj\",\"session_id\":\"e2e\"}")
check 'printf "%s" "$out" | grep -q "\"permissionDecision\":\"deny\""' 'Bash cat /proc/PID/environ : refusé'
out=$(hook pre-tool-use "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"secret unlock --stdin\"},\"cwd\":\"$proj\",\"session_id\":\"e2e\"}")
check 'printf "%s" "$out" | grep -q "\"permissionDecision\":\"deny\""' 'Bash secret unlock : refusé'
out=$(hook pre-tool-use "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cat ~/.local-secrets/key.json\"},\"cwd\":\"$proj\",\"session_id\":\"e2e\"}")
check 'printf "%s" "$out" | grep -q "\"permissionDecision\":\"deny\""' 'Bash lecture de key.json : refusé'
out=$(hook post-tool-use "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"x\"},\"tool_response\":{\"stdout\":\"valeur: $pg\",\"stderr\":\"\"},\"cwd\":\"$proj\",\"session_id\":\"e2e\"}")
check 'printf "%s" "$out" | grep -q "secret:monprojet/POSTGRES_PASSWORD" && ! printf "%s" "$out" | grep -qF "$pg"' 'sortie d un outil : valeur du coffre masquée'
"$exe" lock > /dev/null
payload="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"x\"},\"tool_response\":{\"stdout\":\"rien\",\"stderr\":\"\"},\"cwd\":\"$proj\",\"session_id\":\"e2e-verrou\"}"
first=$(hook post-tool-use "$payload")
second=$(hook post-tool-use "$payload")
check 'printf "%s" "$first" | grep -q "illisible" && [ -z "$second" ]' 'coffre verrouillé : signalé une fois par session'
out=$(hook pre-tool-use "{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"$proj/.env\"},\"cwd\":\"$proj\",\"session_id\":\"e2e\"}")
check '[ -z "$out" ]' 'Read d un .env déjà protégé, coffre verrouillé : rien à signaler'

echo 'Protection du coffre'
other="$root/autre"
mkdir -p "$other"
printf '{"version":1,"protection":"dpapi","namespaces":{},"secrets":{"x/A":{"data":"AAAA"}}}' > "$other/vault.json"
out=$(printf 'Valeur-Test-9!' | LOCAL_SECRETS_HOME=$other "$exe" set x/B 2>&1)
check '[ $? -ne 0 ] && printf "%s" "$out" | grep -q "secret restore"' 'coffre DPAPI copié sous Linux : écriture refusée, migration expliquée'

cd / && rm -rf "$root"
if [ "$failures" -eq 0 ]; then echo 'Tous les tests de bout en bout passent.'; else echo "$failures test(s) de bout en bout en échec."; exit 1; fi
