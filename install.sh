#!/usr/bin/env bash
# Installe local-secrets pour l'utilisateur courant sous Linux ou WSL, sans droits root :
# vérifie le binaire livré, le place dans ~/.local/bin, branche le chargement automatique dans
# ~/.bashrc, ~/.zshrc et la config de fish, installe le plugin Claude Code, puis crée la clé du coffre.
# Désinstallation : uninstall.sh.
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
bin="$root/plugins/local-secrets-linux/tools"
exe="$bin/secret"
profile_script="$root/shell/local-secrets.sh"
fish_script="$root/shell/local-secrets.fish"

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "local-secrets est livré pour Linux x86_64 seulement (ici : $(uname -s) $(uname -m))." >&2
    exit 1
fi
# Le clone garde normalement le bit d'exécution ; sous /mnt/c (WSL), chmod est refusé mais inutile.
chmod 755 "$exe" "$bin/hook.sh" 2> /dev/null || true
if [ ! -x "$exe" ]; then
    echo "$exe n'est pas exécutable : chmod 755 \"$exe\", puis relance." >&2
    exit 1
fi
if ! result=$("$exe" selftest 2>&1); then
    printf '%s\n' "$result" | grep -E 'ÉCHEC|échec' >&2 || true
    echo "tests internes en échec : lance « $exe selftest » pour le détail (OpenSSL est-il installé ?)" >&2
    exit 1
fi
printf '%s\n' "$result" | tail -n 1

echo '1. Commande secret'
mkdir -p "$HOME/.local/bin"
ln -sf "$exe" "$HOME/.local/bin/secret"
echo "   $HOME/.local/bin/secret -> $exe"
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "   ~/.local/bin n'est pas dans le PATH de ce terminal : la plupart des distributions l'ajoutent à la prochaine connexion." ;;
esac

echo '2. Chargement automatique (bash, zsh, fish)'
line="[ -f '$profile_script' ] && . '$profile_script'  # local-secrets"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ "$rc" = "$HOME/.zshrc" ] && [ ! -f "$rc" ]; then continue; fi
    touch "$rc"
    if grep -qxF "$line" "$rc"; then
        echo "   $rc : déjà en place."
    elif grep -q '# local-secrets$' "$rc"; then
        tmp=$(mktemp)
        grep -v '# local-secrets$' "$rc" > "$tmp" || true
        printf '%s\n' "$line" >> "$tmp"
        cat "$tmp" > "$rc" && rm -f "$tmp"
        echo "   $rc : ligne mise à jour."
    else
        printf '\n%s\n' "$line" >> "$rc"
        echo "   $rc : ligne ajoutée."
    fi
done
# fish lit tout seul les fichiers de conf.d : un fichier à nous, réécrit à chaque installation.
fish_conf="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d"
if command -v fish > /dev/null 2>&1 || [ -d "$fish_conf" ]; then
    mkdir -p "$fish_conf"
    printf "test -f '%s'; and source '%s'  # local-secrets\n" "$fish_script" "$fish_script" > "$fish_conf/local-secrets.fish"
    echo "   $fish_conf/local-secrets.fish : en place."
fi

echo '3. Plugin Claude Code'
claude_path=$(command -v claude 2> /dev/null || true)
case "$claude_path" in
    # Sous WSL, le PATH de Windows peut fournir le claude de Windows : il gère sa propre installation.
    /mnt/*)
        echo "   $claude_path est le Claude Code de Windows : installe celui de Linux" \
             "(curl -fsSL https://claude.ai/install.sh | bash), ouvre un nouveau terminal, puis relance ce script."
        claude_path=windows
        ;;
esac
if [ "$claude_path" = windows ]; then
    :
elif [ -n "$claude_path" ]; then
    if "$claude_path" plugin marketplace list 2>&1 | grep -q 'local-secrets'; then
        "$claude_path" plugin marketplace update local-secrets
    else
        "$claude_path" plugin marketplace add "$root"
    fi
    if "$claude_path" plugin list 2>&1 | grep -q 'local-secrets-linux@local-secrets'; then
        "$claude_path" plugin update local-secrets-linux@local-secrets
    else
        "$claude_path" plugin install local-secrets-linux@local-secrets --scope user
    fi
else
    echo "   claude introuvable : installe Claude Code, puis relance ce script (ou : claude plugin marketplace add $root" \
         "&& claude plugin install local-secrets-linux@local-secrets)."
fi

echo '4. Clé du coffre'
if [ -f "${LOCAL_SECRETS_HOME:-$HOME/.local-secrets}/key.json" ]; then
    echo '   déjà créée.'
else
    echo '   Choisis une phrase de passe (12 caractères minimum). Elle te sera demandée par « secret unlock »,'
    echo '   une fois après chaque démarrage. Garde-la à part : sans elle, les secrets sont illisibles.'
    "$exe" init
fi

echo '5. Vérification'
"$exe" doctor || true
echo
echo 'Ouvre un nouveau terminal et relance Claude Code pour activer le PATH, le chargement automatique et les hooks.'
