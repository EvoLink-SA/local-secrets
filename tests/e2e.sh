#!/usr/bin/env bash
# Tests de bout en bout de secret sous Linux : clé du coffre, CLI, verrouillage et hooks, dans un
# coffre et un projet temporaires. Les valeurs ci-dessous sont factices.
# Usage : tests/e2e.sh [CHEMIN_DU_BINAIRE]   (défaut : plugins/local-secrets-linux/tools/secret)
set -u

here=$(cd "$(dirname "$0")" && pwd)
exe=${1:-$here/../plugins/local-secrets-linux/tools/secret}
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
err=$("$exe" import sub 2>&1 > /dev/null)
rc=$?
check '[ $rc -eq 0 ] && [ -z "$err" ] && grep -q "^NEW_TOKEN=secret://" sub/.env && ! grep -qF "$token" sub/.env' 'import : conversion sans erreur coffre verrouillé (clé publique)'
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

winexe="$here/../plugins/local-secrets/tools/secret.exe"
if [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] && [ -f "$winexe" ]; then
    echo 'Pont DPAPI (WSL)'
    export LOCAL_SECRETS_WINDOWS_EXE="$winexe"
    out=$(printf '%s\n' "nouvelle phrase de passe e2e" | "$exe" unlock --stdin --remember 2>&1)
    check 'printf "%s" "$out" | grep -q "DPAPI de Windows" && grep -q "wsl-dpapi" "$LOCAL_SECRETS_HOME/key.json"' 'unlock --remember : clé confiée à la DPAPI de Windows'
    "$exe" lock > /dev/null
    out=$("$exe" run -- true 2>&1)
    check '[ $? -ne 0 ]' 'lock : pas de réouverture automatique après un verrouillage volontaire'
    rm -f "$LOCAL_SECRETS_HOME/locked"   # comme après un redémarrage : trousseau vide, pas de verrouillage volontaire
    "$exe" run -- sh -c '[ "$POSTGRES_PASSWORD" = "'"$pg"'" ]'
    check '[ $? -eq 0 ]' 'réouverture automatique par le pont, sans phrase de passe'
    out=$("$exe" doctor 2>&1)
    check 'printf "%s" "$out" | grep -q "clé mémorisée par : DPAPI de Windows"' 'doctor : clé mémorisée signalée'
    out=$(printf '{"blob":"AAAA","point":"AAAA"}' | "$winexe" wsl-key unwrap 2>&1)
    check '[ $? -ne 0 ]' 'wsl-key : blob étranger refusé'
    out=$(hook pre-tool-use "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$winexe wsl-key unwrap\"},\"cwd\":\"$proj\",\"session_id\":\"e2e\"}")
    check 'printf "%s" "$out" | grep -q "\"permissionDecision\":\"deny\""' 'Bash secret.exe wsl-key : refusé'
    "$exe" lock --forget > /dev/null
    rm -f "$LOCAL_SECRETS_HOME/locked"
    out=$("$exe" run -- true 2>&1)
    check '[ $? -ne 0 ] && ! grep -q "wsl-dpapi" "$LOCAL_SECRETS_HOME/key.json"' 'lock --forget : copie oubliée, plus de réouverture automatique'
    printf '%s\n' "nouvelle phrase de passe e2e" | "$exe" unlock --stdin > /dev/null
    unset LOCAL_SECRETS_WINDOWS_EXE
fi

echo 'Terminal (bash)'
# Vrai terminal (script alloue un pseudo-terminal) : secret env refuse une entrée redirigée.
# Le résultat ne contient que des booléens, jamais de valeur.
cat > "$root/term.sh" <<EOF
export PATH="$work:\$PATH"
export SSH_PASS=avant
cd "$root"
. "$here/../shell/local-secrets.sh"
cd "$proj"; _local_secrets_update
r1=non; [ "\$POSTGRES_PASSWORD" = "\$E2E_PG" ] && r1=oui
r2=non; [ "\$SSH_PASS" = "\$E2E_SSH" ] && r2=oui
cd /; _local_secrets_update
r3=non; [ -z "\${POSTGRES_PASSWORD+x}" ] && [ "\$SSH_PASS" = avant ] && r3=oui
echo "charge=\$r1 remplace=\$r2 retabli=\$r3" > "$root/term.result"
EOF
E2E_PG=$pg E2E_SSH=$ssh script -qec "bash --norc $root/term.sh" /dev/null > /dev/null 2>&1
check 'grep -q "charge=oui" "$root/term.result"' 'chargement auto : secrets du projet chargés en entrant'
check 'grep -q "remplace=oui" "$root/term.result"' 'chargement auto : variable existante remplacée'
check 'grep -q "retabli=oui" "$root/term.result"' 'chargement auto : retirés en sortant, valeur d avant rétablie'

echo 'Terminal (fish)'
if command -v fish > /dev/null 2>&1; then
    # Valeur piège pour les guillemets de fish : apostrophe, barres obliques inverses, $ et fin en \.
    tricky="X'y\\z\\\\\$HOME\"\\"
    printf '%s' "$tricky" | "$exe" set TRICKY_PASSWORD > /dev/null
    cat > "$root/term.fish" <<EOF
set -gx PATH "$work" \$PATH
set -gx SSH_PASS avant
cd "$root"
source "$here/../shell/local-secrets.fish"
cd "$proj"
set r1 non; test "\$POSTGRES_PASSWORD" = "\$E2E_PG"; and set r1 oui
set r2 non; test "\$SSH_PASS" = "\$E2E_SSH"; and set r2 oui
set r4 non; test "\$TRICKY_PASSWORD" = "\$E2E_TRICKY"; and set r4 oui
cd /
set r3 non; not set -q POSTGRES_PASSWORD; and test "\$SSH_PASS" = avant; and set r3 oui
echo "charge=\$r1 remplace=\$r2 retabli=\$r3 guillemets=\$r4" > "$root/fish.result"
EOF
    E2E_PG=$pg E2E_SSH=$ssh E2E_TRICKY=$tricky script -qec "fish --no-config -i -c 'source $root/term.fish'" /dev/null > /dev/null 2>&1
    check 'grep -q "charge=oui" "$root/fish.result"' 'fish : secrets du projet chargés en entrant'
    check 'grep -q "remplace=oui" "$root/fish.result"' 'fish : variable existante remplacée'
    check 'grep -q "guillemets=oui" "$root/fish.result"' 'fish : apostrophe, \ et $ gardés tels quels'
    check 'grep -q "retabli=oui" "$root/fish.result"' 'fish : retirés en sortant, valeur d avant rétablie'
    sed -i "/^TRICKY_PASSWORD=/d" "$proj/.env"
else
    echo '  ignoré : fish absent'
fi

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
printf 'LOCKED_PASSWORD=%s\n' "$pg" > sub/locked.env
out=$(hook pre-tool-use "{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"$proj/sub/locked.env\"},\"cwd\":\"$proj\",\"session_id\":\"e2e\"}")
check 'grep -q "^LOCKED_PASSWORD=secret://" sub/locked.env && ! printf "%s" "$out" | grep -q deny' 'Read d un .env en clair, coffre verrouillé : converti, pas de refus'

echo 'Lanceur des hooks'
cp "$here/../plugins/local-secrets-linux/tools/hook.sh" "$work/hook.sh"
out=$(printf '{"tool_name":"Bash","tool_input":{"command":"cat /proc/1/environ"},"cwd":"/"}' | sh "$work/hook.sh" pre-tool-use)
check 'printf "%s" "$out" | grep -q "\"permissionDecision\":\"deny\""' 'hook.sh : transmet au binaire'
mkdir -p "$root/casse"
cp "$work/hook.sh" "$root/casse/hook.sh"
printf '{"tool_input":{"file_path":"/x/.env"}}' | sh "$root/casse/hook.sh" pre-tool-use 2> /dev/null
check '[ $? -eq 2 ]' 'hook.sh sans binaire : accès à un .env bloqué'
printf '{"tool_input":{"command":"ls"}}' | sh "$root/casse/hook.sh" pre-tool-use 2> /dev/null
check '[ $? -eq 0 ]' 'hook.sh sans binaire : le reste passe'
out=$(sh "$root/casse/hook.sh" session-start < /dev/null)
check 'printf "%s" "$out" | grep -q systemMessage' 'hook.sh sans binaire : avertissement au démarrage'

echo 'Protection du coffre'
other="$root/autre"
mkdir -p "$other"
printf '{"version":1,"protection":"dpapi","namespaces":{},"secrets":{"x/A":{"data":"AAAA"}}}' > "$other/vault.json"
out=$(printf 'Valeur-Test-9!' | LOCAL_SECRETS_HOME=$other "$exe" set x/B 2>&1)
check '[ $? -ne 0 ] && printf "%s" "$out" | grep -q "secret restore"' 'coffre DPAPI copié sous Linux : écriture refusée, migration expliquée'

cd / && rm -rf "$root"
if [ "$failures" -eq 0 ]; then echo 'Tous les tests de bout en bout passent.'; else echo "$failures test(s) de bout en bout en échec."; exit 1; fi
