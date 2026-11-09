# local-secrets : chargement automatique des secrets d'un projet dans ce terminal (bash, zsh).
#
# En entrant dans un dossier dont le .env (ou celui d'un dossier parent) contient des références
# secret://, les vraies valeurs sont placées en mémoire, dans les variables d'environnement de ce
# shell. Elles sont retirées en sortant du projet, et les valeurs d'avant sont rétablies.
# docker compose, npm, python ou un éditeur lancé d'ici les reçoivent sans « secret run ».
# Rien n'est écrit sur le disque. Ligne ajoutée à ~/.bashrc et ~/.zshrc par install.sh.
#
# local_secrets_reload  recharge après un « secret set » ou un « secret unlock »
#                       (sinon, au prochain changement de dossier).

[ "${CLAUDECODE:-}" = 1 ] && return 0   # jamais dans les shells des outils de Claude Code
command -v secret > /dev/null 2>&1 || return 0

_LS_DIR=
_LS_STAMP=
_LS_VARS=
_LS_PWD=

# Rétablit les variables d'avant le chargement.
_local_secrets_restore() {
    for _ls_k in $(printf '%s' "$_LS_VARS"); do
        eval "if [ -n \"\${_ls_had_$_ls_k-}\" ]; then export $_ls_k=\"\${_ls_saved_$_ls_k}\"; else unset $_ls_k; fi; unset _ls_had_$_ls_k _ls_saved_$_ls_k"
    done
    unset _ls_k
    _LS_VARS=
    _LS_DIR=
    _LS_STAMP=
}

_local_secrets_update() {
    [ "${1:-}" != force ] && [ "$PWD" = "$_LS_PWD" ] && return 0
    _LS_PWD=$PWD

    # Raccourci : sans .env dans ce dossier ni ses parents, rien à lancer.
    _ls_probe=$PWD
    _ls_found=
    _ls_i=0
    while [ "$_ls_i" -lt 8 ] && [ -n "$_ls_probe" ]; do
        if [ -f "$_ls_probe/.env" ]; then _ls_found=1; break; fi
        [ "$_ls_probe" = / ] && break
        _ls_probe=${_ls_probe%/*}
        [ -z "$_ls_probe" ] && _ls_probe=/
        _ls_i=$((_ls_i + 1))
    done
    unset _ls_probe _ls_i
    if [ -z "$_ls_found" ] && [ -z "$_LS_DIR" ] && [ "${1:-}" != force ]; then unset _ls_found; return 0; fi

    _LS_NEW_DIR=
    _LS_NEW_STAMP=
    _LS_NEW_VARS=
    _LS_SKIPPED=
    if [ -n "$_ls_found" ]; then
        _ls_out=$(command secret env --format sh --dir "$PWD" 2> /dev/null)
        if [ $? -ne 0 ]; then
            printf 'local-secrets : secrets du projet non chargés (coffre verrouillé ? « secret unlock » puis local_secrets_reload)\n' >&2
        elif [ -n "$_ls_out" ]; then
            eval "$_ls_out"
        fi
        unset _ls_out
    fi
    unset _ls_found

    if [ "${1:-}" != force ] && [ -n "$_LS_NEW_DIR" ] && [ "$_LS_NEW_DIR" = "$_LS_DIR" ] && [ "$_LS_NEW_STAMP" = "$_LS_STAMP" ]; then
        for _ls_k in $(printf '%s' "$_LS_NEW_VARS"); do unset "_ls_val_$_ls_k"; done
        unset _ls_k _LS_NEW_DIR _LS_NEW_STAMP _LS_NEW_VARS _LS_SKIPPED
        return 0
    fi

    _ls_previous=$_LS_DIR
    _local_secrets_restore
    if [ -n "$_LS_NEW_DIR" ]; then
        _ls_count=0
        for _ls_k in $(printf '%s' "$_LS_NEW_VARS"); do
            eval "if [ -n \"\${$_ls_k+x}\" ]; then _ls_had_$_ls_k=1; _ls_saved_$_ls_k=\"\$$_ls_k\"; fi; export $_ls_k=\"\$_ls_val_$_ls_k\"; unset _ls_val_$_ls_k"
            _ls_count=$((_ls_count + 1))
        done
        _LS_VARS=$_LS_NEW_VARS
        _LS_DIR=$_LS_NEW_DIR
        _LS_STAMP=$_LS_NEW_STAMP
        if [ "$_LS_DIR" != "$_ls_previous" ] || [ "${1:-}" = force ]; then
            printf 'local-secrets : %s secret(s) chargé(s) pour %s\n' "$_ls_count" "$_LS_DIR" >&2
            [ -n "$_LS_SKIPPED" ] && printf 'local-secrets : noms invalides pour le shell, non chargés : %s (utilise secret run)\n' "$_LS_SKIPPED" >&2
        fi
        unset _ls_k _ls_count
    elif [ -n "$_ls_previous" ]; then
        printf 'local-secrets : secrets de %s retirés\n' "$_ls_previous" >&2
    fi
    unset _ls_previous _LS_NEW_DIR _LS_NEW_STAMP _LS_NEW_VARS _LS_SKIPPED
}

local_secrets_reload() { _local_secrets_update force; }

if [ -n "${ZSH_VERSION:-}" ]; then
    autoload -Uz add-zsh-hook
    add-zsh-hook chpwd _local_secrets_update
elif [ -n "${BASH_VERSION:-}" ]; then
    case ";${PROMPT_COMMAND:-};" in
        *";_local_secrets_update;"*) ;;
        *) PROMPT_COMMAND="_local_secrets_update${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
    esac
fi
_local_secrets_update
