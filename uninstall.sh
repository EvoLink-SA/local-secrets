#!/usr/bin/env bash
# Désinstalle local-secrets pour l'utilisateur courant sous Linux ou WSL. À lancer dans un terminal,
# pas depuis Claude. Ordre : remettre les valeurs en clair dans les .env (sinon les références
# secret:// restent sans personne pour les résoudre), puis retirer le plugin, le profil et la commande.
# Le coffre (~/.local-secrets) n'est jamais supprimé par ce script.
# --keep-env-files : laisse les .env tels quels.
set -uo pipefail

root=$(cd "$(dirname "$0")" && pwd)
exe="$root/plugins/local-secrets-linux/bin/secret"

echo '1. Fichiers .env'
if [ "${1:-}" = --keep-env-files ]; then
    echo '   laissés tels quels (--keep-env-files) : les références secret:// ne seront plus résolues.'
elif [ -x "$exe" ]; then
    "$exe" unprotect --all --dry-run
    read -r -p '   Remettre ces valeurs en clair dans les fichiers ? (o/N) ' answer
    case "$answer" in
        [oOyY]*)
            if ! "$exe" unprotect --all; then
                echo "remise en clair interrompue (coffre verrouillé ? « secret unlock ») : rien d'autre n'a été retiré" >&2
                exit 1
            fi
            ;;
        *) echo '   ignoré : les fichiers gardent leurs références secret://.' ;;
    esac
else
    echo "   secret introuvable ($exe) : étape ignorée."
fi

echo '2. Plugin Claude Code'
if command -v claude > /dev/null 2>&1; then
    if claude plugin list 2>&1 | grep -q 'local-secrets-linux@local-secrets'; then
        claude plugin uninstall local-secrets-linux@local-secrets
    else
        echo '   plugin absent.'
    fi
    if claude plugin marketplace list 2>&1 | grep -q 'local-secrets'; then
        claude plugin marketplace remove local-secrets
    else
        echo '   marketplace absente.'
    fi
else
    echo '   claude introuvable : étape ignorée.'
fi

echo '3. Chargement automatique'
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && grep -q '# local-secrets$' "$rc"; then
        tmp=$(mktemp)
        grep -v '# local-secrets$' "$rc" > "$tmp" || true
        cat "$tmp" > "$rc" && rm -f "$tmp"
        echo "   ligne retirée de $rc"
    fi
done

echo '4. Commande secret'
if [ -L "$HOME/.local/bin/secret" ]; then
    rm -f "$HOME/.local/bin/secret"
    echo "   $HOME/.local/bin/secret retiré."
else
    echo '   déjà absente.'
fi
[ -x "$exe" ] && "$exe" lock > /dev/null 2>&1

echo
echo "Le coffre reste dans ${LOCAL_SECRETS_HOME:-$HOME/.local-secrets} (secrets chiffrés, clé et copies des .env d'origine)."
echo 'Supprime ce dossier toi-même quand tu es sûr de ne plus en avoir besoin.'
echo 'Ouvre un nouveau terminal et relance Claude Code pour finir.'
