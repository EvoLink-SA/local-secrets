# local-secrets : chargement automatique des secrets d'un projet dans ce terminal (fish).
#
# Même rôle que local-secrets.sh pour bash et zsh : en entrant dans un dossier dont le .env (ou celui
# d'un dossier parent) contient des références secret://, les vraies valeurs sont placées en mémoire,
# dans les variables d'environnement de ce shell, puis retirées en sortant du projet.
# Rien n'est écrit sur le disque. Chargé par ~/.config/fish/conf.d/local-secrets.fish (install.sh).
#
# local_secrets_reload  recharge après un « secret set » ou un « secret unlock »
#                       (sinon, au prochain changement de dossier).

status is-interactive; or return 0
test "$CLAUDECODE" = 1; and return 0   # jamais dans les shells des outils de Claude Code
command -q secret; or return 0

set -g _LS_DIR
set -g _LS_STAMP
set -g _LS_VARS

# Rétablit les variables d'avant le chargement.
function _local_secrets_restore
    for k in $_LS_VARS
        set -l saved _ls_saved_$k
        if set -q _ls_had_$k
            set -gx $k $$saved
        else
            set -e $k
        end
        set -e _ls_had_$k $saved
    end
    set -g _LS_VARS
    set -g _LS_DIR
    set -g _LS_STAMP
end

function _local_secrets_update --on-variable PWD
    set -l force (test "$argv[1]" = force; and echo 1)

    # Raccourci : sans .env dans ce dossier ni ses parents, rien à lancer.
    set -l probe $PWD
    set -l found
    for i in (seq 8)
        if test -f "$probe/.env"
            set found 1
            break
        end
        test "$probe" = /; and break
        set probe (string replace -r '/[^/]*$' '' -- $probe)
        test -z "$probe"; and set probe /
    end
    if test -z "$found" -a -z "$_LS_DIR" -a -z "$force"
        return 0
    end

    set -e _LS_NEW_DIR _LS_NEW_STAMP _LS_NEW_VARS _LS_SKIPPED
    if test -n "$found"
        # Les valeurs passent par un tube vers source, jamais par l'écran ni le disque.
        command secret env --format fish --dir $PWD 2>/dev/null | source
        if test $pipestatus[1] -ne 0
            echo 'local-secrets : secrets du projet non chargés (coffre verrouillé ? « secret unlock » puis local_secrets_reload)' >&2
        end
    end
    set -l new_vars (string split -n ' ' -- "$_LS_NEW_VARS")

    if test -z "$force" -a -n "$_LS_NEW_DIR" -a "$_LS_NEW_DIR" = "$_LS_DIR" -a "$_LS_NEW_STAMP" = "$_LS_STAMP"
        for k in $new_vars
            set -e _ls_val_$k
        end
        set -e _LS_NEW_DIR _LS_NEW_STAMP _LS_NEW_VARS _LS_SKIPPED
        return 0
    end

    set -l previous $_LS_DIR
    _local_secrets_restore
    if test -n "$_LS_NEW_DIR"
        for k in $new_vars
            set -l val _ls_val_$k
            if set -q $k
                set -g _ls_had_$k 1
                set -g _ls_saved_$k $$k
            end
            set -gx $k $$val
            set -e $val
        end
        set -g _LS_VARS $new_vars
        set -g _LS_DIR $_LS_NEW_DIR
        set -g _LS_STAMP $_LS_NEW_STAMP
        if test "$_LS_DIR" != "$previous" -o -n "$force"
            printf 'local-secrets : %s secret(s) chargé(s) pour %s\n' (count $new_vars) $_LS_DIR >&2
            test -n "$_LS_SKIPPED"; and printf 'local-secrets : noms invalides pour le shell, non chargés : %s (utilise secret run)\n' $_LS_SKIPPED >&2
        end
    else if test -n "$previous"
        printf 'local-secrets : secrets de %s retirés\n' $previous >&2
    end
    set -e _LS_NEW_DIR _LS_NEW_STAMP _LS_NEW_VARS _LS_SKIPPED
end

function local_secrets_reload
    _local_secrets_update force
end

_local_secrets_update
