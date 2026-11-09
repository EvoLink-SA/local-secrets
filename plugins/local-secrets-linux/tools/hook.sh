#!/bin/sh
# local-secrets : lanceur des hooks sous Linux. Si secret manque ou ne démarre pas (fichier abîmé,
# mise à jour en cours, OpenSSL absent), il le dit clairement et ne bloque que les accès qui visent
# un .env, au lieu de bloquer tous les outils de Claude.
event="$1"
exe="$(dirname "$0")/secret"
# La copie du plugin dans le cache de Claude Code peut perdre le bit d'exécution.
[ -f "$exe" ] && [ ! -x "$exe" ] && chmod u+x "$exe" 2>/dev/null
if [ -x "$exe" ]; then
    "$exe" hook "$event" && exit 0
fi

case "$event" in
    session-start)
        printf '%s\n' '{"systemMessage":"local-secrets : secret est introuvable ou ne démarre pas. La protection des fichiers .env est inactive et Claude ne pourra pas les lire. Lance secret doctor, ou réinstalle le plugin."}'
        ;;
    pre-tool-use)
        if grep -qi '\.env' 2>/dev/null; then
            echo "local-secrets : secret est introuvable ou ne démarre pas. Accès à ce fichier .env bloqué par précaution, pour que ses valeurs ne te soient pas transmises. Demande à l'utilisateur de lancer secret doctor, ou de désactiver le plugin : claude plugin disable local-secrets-linux@local-secrets" >&2
            exit 2
        fi
        ;;
esac
exit 0
