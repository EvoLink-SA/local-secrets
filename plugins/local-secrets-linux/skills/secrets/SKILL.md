---
name: secrets
description: Mode d'emploi des secrets locaux (plugin local-secrets, commande secret, coffre local chiffré, DPAPI sous Windows, clé à phrase de passe sous Linux et WSL). À utiliser dès qu'une tâche a besoin d'un mot de passe, d'une clé d'API, d'un jeton, d'identifiants SSH, Windows, base de données ou SMTP, dès qu'un fichier .env contient des références secret://, dès qu'une sortie affiche [secret:...], quand une commande docker compose, ssh, curl, psql ou PowerShell doit s'authentifier, ou quand l'utilisateur parle de secrets, de coffre, de .env, de chiffrement local ou de « secret run ». Explique comment utiliser les valeurs sans jamais les voir ni les afficher.
---

# Secrets locaux : les utiliser sans les voir

Sur ce poste, les valeurs sensibles des fichiers `.env` sont chiffrées dans un coffre local, lié
au compte de l'utilisateur : DPAPI sous Windows ; sous Linux et WSL, une clé du compte que
l'utilisateur déverrouille par phrase de passe (`secret unlock`). Dans les fichiers, elles sont
remplacées par des références :

```
SERVER_IP=192.168.10.25
POSTGRES_PASSWORD=secret://monprojet/POSTGRES_PASSWORD
```

Tu ne vois jamais les valeurs, et c'est voulu : tout ce que tu lis part vers l'API et s'écrit
en clair dans les transcripts locaux. Tu peux pourtant t'en servir, avec `secret run`.

Les hooks du plugin font le reste tout seuls :
- un `.env` **du projet ouvert** encore en clair est chiffré juste avant que tu le lises ou que tu
  le cites dans une commande. Rien n'est converti au démarrage ni lors d'une recherche dans un
  dossier. Le `.env` d'un autre projet (autre dépôt git, dossier voisin) n'est jamais modifié : il
  t'est simplement refusé s'il contient des secrets en clair ;
- ce que tu écris dans un `.env` du projet est chiffré juste après ;
- une valeur du coffre qui apparaîtrait dans une sortie est remplacée par `[secret:espace/CLÉ]` ;
- toute autre valeur qui ressemble à un secret dans une sortie (`.env` d'un serveur, `docker inspect`,
  `printenv`, réponse d'API, fichier de config) est remplacée par `[masqué:CLÉ]` ;
- un message de l'utilisateur qui contient un mot de passe est bloqué avant l'envoi.

## Les deux masques

| Masque | Ce que c'est | Utilisable ? |
|---|---|---|
| `[secret:espace/CLÉ]` | une valeur du coffre local | oui : `secret://espace/CLÉ` avec `secret run` |
| `[masqué:CLÉ]` | une valeur repérée comme sensible, stockée nulle part | non : demande à l'utilisateur de l'enregistrer avec `secret set` si tu en as besoin |

Un masque n'est jamais la vraie valeur. Ne le recopie jamais dans un fichier ni dans une commande :
le hook refuse, et réécrire un fichier qui contient un masque remplacerait la vraie valeur. Pour
modifier un fichier dont une ligne est masquée, fais un `Edit` ciblé sur les autres lignes. Pour un
mot de passe en dur dans une config, propose de le déplacer dans le `.env`.

Sur un serveur distant (`ssh hôte "..."`), les programmes lisent leurs valeurs eux-mêmes : tu peux
lancer Compose, redémarrer un service ou lire des logs là-bas sans voir les secrets. Le `.env` du
serveur n'est jamais modifié par le plugin.

Si l'utilisateur a besoin de voir ces valeurs pour une automatisation, c'est à lui de couper le
masquage générique (`secret config masking off`, ou `LOCAL_SECRETS_OUTPUT_MASKING=off` au lancement
de Claude Code). Toi, tu ne peux pas le couper.

## La règle

Toute commande qui a besoin d'une valeur passe par `secret run` :

```
secret run -- <commande> [arguments]
```

`secret run` lit le `.env` du dossier courant, injecte toutes ses variables (en clair et
déchiffrées) dans l'environnement du programme lancé, et masque les valeurs du coffre dans
tout ce que le programme affiche. Le code de sortie est celui du programme.

Options :
- `-e FICHIER` : un autre fichier que `.env` (répétable), par exemple `-e .env.prod`.
- `--ns ESPACE` : tout un espace du coffre, sans fichier.
- `-s espace/CLÉ=VARIABLE` : un seul secret, sous le nom de variable voulu.
- `--ssh-pass CLÉ` : fournit ce mot de passe à ssh (voir plus bas).

Dans un argument, `secret://CLÉ` ou `secret://espace/CLÉ` est remplacé par la valeur.

## Le piège des variables

Ton shell développe `$API_TOKEN` (Bash) ou `$env:API_TOKEN` (PowerShell) entre guillemets
doubles **avant** que `secret run` ne démarre : la variable arrive vide. Le hook bloque ce cas.
Trois façons correctes :

```bash
# 1. référence dans l'argument
secret run -- curl -H "Authorization: Bearer secret://API_TOKEN" https://api.example.com/v1/me

# 2. shell interne, guillemets simples
secret run -- bash -c 'curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/v1/me'
```

```powershell
# 3. depuis l'outil PowerShell
secret run -- pwsh -NoProfile -Command 'Invoke-RestMethod https://api.example.com/v1/me -Headers @{ Authorization = "Bearer $env:API_TOKEN" }'
```

## Selon l'outil

- **Bash (Git Bash)** : `secret` est dans le PATH une fois `install.ps1` lancé ; sinon, appelle-le par
  le chemin donné dans le contexte de démarrage. Git Bash convertit en chemin
  tout argument qui commence par `/` : `cmd /c` devient `cmd C:/`. Écris `cmd //c`, ou passe par
  l'outil PowerShell pour les commandes Windows à options `/x`.
- **PowerShell** : `secret` est dans le PATH une fois l'installation faite et l'application
  relancée. Sinon, appelle-le par le chemin complet donné dans le contexte de démarrage :
  `& 'C:\...\tools\secret.exe' run -- <commande>`.
- **Piège WSL** : depuis l'outil PowerShell, `bash` est le Bash de WSL (`C:\Windows\System32\bash.exe`),
  pas Git Bash. `secret run -- bash ...` ou `secret run -- wsl ...` transmet bien les variables à WSL.
  Mais un `bash` WSL lancé autrement ne les reçoit pas : la valeur y arrive **vide, sans erreur**.
  Pour du shell depuis l'outil PowerShell, préfère `pwsh -NoProfile -Command '...'`.
- **Linux et WSL (Claude Code lancé sous Linux)** : `secret` est dans `~/.local/bin`. Pas de
  conversion de chemins, `secret run -- sh -c '...'` fonctionne directement. Si une commande échoue
  avec « coffre verrouillé », c'est à l'utilisateur de lancer `secret unlock` dans son terminal :
  tu ne peux pas le faire, et il ne doit jamais te donner sa phrase de passe. La conversion des
  `.env` fonctionne même coffre verrouillé. Avec `secret unlock --remember`, la clé est confiée à la
  DPAPI de Windows (WSL) ou au trousseau de session (bureau), et le coffre se rouvre ensuite seul.

## Recettes

**Docker Compose**
```
secret run -- docker compose up -d
secret run -- docker compose config
```
Sans `secret run`, Compose prendrait les références `secret://` pour des valeurs : le hook
bloque. Si le compose utilise `env_file: .env`, les conteneurs recevraient les références :
propose à l'utilisateur de passer ces variables par `environment:`, par exemple
`POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}`. Attention, `docker inspect` affiche l'environnement
des conteneurs : c'est masqué dans ta sortie, mais la valeur existe côté Docker.

**Base de données**
```
secret run -s monprojet/POSTGRES_PASSWORD=PGPASSWORD -- psql -h db.local -U appuser -d app -c "select 1"
secret run -s monprojet/DB_PASSWORD=MYSQL_PWD -- mysql -h db.local -u app -e "select 1"
```

**SSH par clé** : l'utilisateur ajoute sa clé une fois à l'agent ssh (`ssh-add`, celui de Windows ou `ssh-agent` sous Linux),
ensuite `ssh` fonctionne directement. Tu ne lis jamais un fichier de clé privée (le hook bloque).

**SSH par mot de passe** (validé avec le ssh de Windows et celui de Git Bash, sans terminal) :
```
secret run --ssh-pass SSH_PASS -- ssh -o StrictHostKeyChecking=accept-new root@192.168.10.25 "uptime"
```
`scp` et `sftp` passent par le même mécanisme (non testés). Le mot de passe passe par SSH_ASKPASS, jamais par ta sortie. Garde
`-o StrictHostKeyChecking=accept-new` pour un premier contact : la question d'empreinte est refusée.
En cas d'échec (`Permission denied`, double authentification, équipement qui demande autre chose
qu'un mot de passe), propose à l'utilisateur de passer en authentification par clé.

**Identifiants Windows** (WinRM, partages, Active Directory) :
```
secret run -- pwsh -NoProfile -Command '$c = [pscredential]::new($env:WIN_USER, (ConvertTo-SecureString $env:WIN_PASS -AsPlainText -Force)); Invoke-Command -ComputerName srv01 -Credential $c { hostname }'
```

**API dans un script** : un script qui lit ses variables d'environnement (`process.env`,
`os.environ`, `$env:`) se lance tel quel : `secret run -- node deploy.js`, `secret run -- python sync.py`.
Les bibliothèques dotenv n'écrasent pas une variable déjà présente, donc la vraie valeur gagne.

## Serveur distant : transférer un secret sans le voir

Une valeur ne doit jamais passer par ce que tu lis. Elle passe par un tuyau (`|`) d'un programme
à l'autre, et seul le message de confirmation te revient.

**Du serveur vers le poste** (par exemple pour le `.env` d'un docker local), avec `import --stdin` :
```bash
ssh root@srv "cat /opt/app/.env" | secret import --stdin --only DB_PASSWORD,DB_HOST
```
Le flux est relu avec le même lecteur que les `.env` locaux (guillemets, commentaires, `export`),
puis trié : les secrets vont au coffre sous forme de références, le reste est écrit en clair dans le
`.env` du dossier courant (`--to FICHIER` pour un autre, `--secret` pour tout chiffrer, sans
`--only` pour tout reprendre). Seuls les noms des clés importées te reviennent. C'est la méthode à
préférer à `grep | cut | secret set`, qui garde les guillemets et chiffre aussi les valeurs anodines.

**Du poste vers le serveur** :
```bash
secret run -- bash -c 'printf "DB_PASSWORD=%s\n" "$DB_PASSWORD" | ssh root@srv "cat >> /opt/app/.env"'
```

Ne fais jamais un `cat` du `.env` distant pour recopier ensuite la valeur : tu ne verrais que
`[masqué:...]`. Pour savoir quelles clés existent, ce `cat` suffit, les noms restent visibles.

## Montrer des valeurs à l'utilisateur

S'il veut voir des valeurs (pour les recopier dans une interface web, par exemple), lance
`secret show` (le `.env` du dossier), `secret show FICHIER` ou `secret show NOM`. Une fenêtre à part
s'ouvre sur son écran ; il confirme, il voit les valeurs, l'écran est effacé à la fermeture. Toi, tu ne
reçois qu'un accusé de réception. Pendant l'affichage et dix minutes après, les captures d'écran et la
lecture du presse-papiers te sont refusées : n'insiste pas. Sous Linux, la fenêtre s'ouvre sous WSL
(console Windows) et sur un bureau (terminal graphique). En SSH, sans écran, `secret show` te répond
qu'il ne peut pas : demande alors à l'utilisateur de le taper dans un autre terminal (pas avec le
préfixe `!`, dont la sortie te reviendrait).

## Quand c'est l'utilisateur qui lance

Après conversion, tout ce qui lit le `.env` directement reçoit les références `secret://` au lieu
des valeurs. C'est la première source d'ennuis. Donc :

- **Son terminal** (PowerShell sous Windows, bash ou zsh sous Linux) charge tout seul les secrets du
  projet quand il entre dans le dossier (si l'intégration est installée : message « secret(s)
  chargé(s) »). Là, `docker compose up -d`, `npm run dev` ou `code .` marchent sans préfixe. Après un
  `secret set` ou un `secret unlock`, il recharge avec `Update-LocalSecrets -Force` (PowerShell) ou
  `local_secrets_reload` (bash, zsh). Sous bash et zsh, une clé dont le nom n'est pas un nom de
  variable shell (`3CX_PASSWORD`) n'est pas chargée : passe par `secret run`. Si Claude Code a été
  lancé depuis ce terminal, tes commandes reçoivent aussi les valeurs (le contexte de démarrage te
  le dit), et leurs sorties restent masquées.
- **Coffre verrouillé (Linux)** : après un redémarrage, ou une fois la durée choisie écoulée, les
  valeurs ne se déchiffrent plus jusqu'au prochain `secret unlock` de l'utilisateur. Dis-le-lui en
  une phrase au lieu de chercher un contournement.
- **Ailleurs** (autre shell, Docker Desktop, bouton « Run » d'un IDE lancé hors de ce terminal),
  toute commande que tu lui donnes passe par `secret run --`, par exemple
  `secret run -- docker compose up -d`. Dans le doute, donne la version avec `secret run`.
- **Premier démarrage d'une base** (Postgres, MariaDB, MySQL, Redis avec mot de passe...) : l'image
  n'utilise le mot de passe qu'à l'initialisation. Lancée une fois sans `secret run`, la base retient
  `secret://...` comme mot de passe, et il faut ensuite supprimer le volume. Préviens-le avant.
- **Lanceurs d'IDE, boutons « Run », Portainer, Docker Desktop** : ils lisent le `.env` eux-mêmes.
  Signale-le, et propose une variable d'environnement ou un lancement via `secret run`.
- **Tâche planifiée, service Windows** : le coffre ne se déchiffre que sous le compte de
  l'utilisateur. Une tâche qui tourne en SYSTEM ou sous un compte de service échouera. Elle doit
  tourner sous son compte et appeler `secret run`. Sous Linux, une tâche cron du même compte
  fonctionne tant que le coffre est déverrouillé, et échoue après un redémarrage.
- **Projet copié sur un autre poste, partagé ou cloné** : les références voyagent, pas les valeurs.
  L'autre poste a besoin d'une restauration (`secret restore`) ou de ses propres valeurs.
- **Conversion** : quand un `.env` vient d'être converti (message « a protégé ces fichiers »),
  dis-le à l'utilisateur en une phrase, avec la conséquence pour ses propres commandes et pour les
  scripts du projet qui lisent ce fichier eux-mêmes (ils doivent lire les variables d'environnement
  et être lancés par `secret run`).
- **Annuler** : pour remettre des `.env` tels qu'avant leur conversion, l'utilisateur lance dans son
  terminal `secret undo FICHIER` ou `secret undo --under DOSSIER --since "AAAA-MM-JJ HH:MM"`. Tu
  peux lancer la même commande avec `--dry-run` pour lui montrer la liste, jamais sans.
- **Fichier hors projet refusé** : le message dit « n'appartient pas au projet ouvert ». Propose
  d'ouvrir Claude dans le projet de ce fichier, ne cherche pas à le lire autrement.
- **Fichier de déploiement** (un `.env` qui doit garder ses vraies valeurs, envoyé tel quel sur un
  serveur) : propose à l'utilisateur d'y ajouter la ligne `# local-secrets: ignore`. Un fichier
  marqué n'est jamais converti et tu ne peux pas le lire s'il contient des secrets en clair, mais
  tu peux le faire évoluer sans le voir : `secret status FICHIER` pour les clés présentes,
  `secret setenv FICHIER CLÉ VALEUR` pour une valeur publique, `secret generate CLÉ --env FICHIER --clear`
  pour un nouveau mot de passe. Ne demande pas à l'utilisateur de retirer le marqueur pour ça.
- **« références absentes du coffre »** : en principe réglé depuis la 0.1.3 (coffre unique). Si ça
  arrive encore, propose à l'utilisateur de lancer `secret migrate` dans son terminal.
- **Message bloqué** : si l'utilisateur dit que son message a été refusé, c'est le détecteur de
  secrets. Il peut le renvoyer avec `[nosecret]`, ou enregistrer la valeur avec `secret set`.
- **SSH** : tu ne peux pas taper de mot de passe. Avec un mot de passe enregistré, utilise
  `secret run --ssh-pass CLÉ -- ssh ...` ; sinon il faut une clé dans `ssh-agent`.
- **Dossier exclu** : si un accès est refusé parce que le dossier est « exclu de la conversion »,
  l'utilisateur a choisi de ne pas faire modifier ces `.env`. Ne contourne pas : propose-lui
  `secret import` sur le fichier, ou `secret config convert on --here`.

## Ce que tu peux faire d'autre

- `secret list` : noms des secrets, jamais les valeurs.
- `secret status [FICHIER]` : pour chaque clé d'un `.env`, chiffrée, en clair ou à chiffrer, et pourquoi.
- `secret import [CHEMIN]` : chiffrer tout de suite les `.env` d'un dossier.
- `secret import --stdin` : importer un `.env` reçu par un tuyau (depuis un serveur).
- `secret show [FICHIER|NOM]` : montrer des valeurs à l'utilisateur, dans une fenêtre à part.
- `secret protect FICHIER CLÉ` : chiffrer une valeur que le tri a laissée en clair à tort.
- `secret generate CLÉ [--env FICHIER] [--length N]` : créer un mot de passe, une clé ou un jeton
  aléatoire (32 caractères par défaut) sans jamais le voir. La valeur va au coffre, la référence
  dans le `.env`. C'est la bonne façon de créer le mot de passe d'une nouvelle base ou d'un
  nouveau service : n'invente jamais une valeur toi-même, elle finirait dans le transcript.
- `secret setenv FICHIER CLÉ VALEUR` : écrire une valeur publique (port, hôte, nom) dans un `.env`
  sans le lire. Refusé pour une valeur qui ressemble à un secret.
- `secret undo ... --dry-run`, `secret unprotect --all --dry-run` : montrer à l'utilisateur ce que
  ces commandes changeraient. Sans `--dry-run`, elles lui sont réservées.
- Ajouter ou modifier une valeur publique dans un `.env` : écris-la normalement. Une valeur
  sensible que l'utilisateur t'a donnée est chiffrée juste après, mais elle reste dans le transcript.

## Ce que tu ne fais jamais

- Afficher une valeur : pas de `echo`, `printenv`, `Get-ChildItem env:`, `docker compose config`
  hors `secret run`, pas de lecture du coffre ni de déchiffrement DPAPI à la main. Sous Linux,
  pas de lecture de `/proc/PID/environ`, de `ps e`, ni des trousseaux (`keyctl`, `secret-tool`) :
  l'environnement des programmes lancés par `secret run` y est lisible (le hook refuse).
- Lire un fichier d'identifiants : clé privée, `.pgpass`, `.netrc`, `.git-credentials`,
  `.aws\credentials` (le hook refuse). Les programmes qui en ont besoin les lisent eux-mêmes.
- Écrire une valeur en clair dans un fichier qui n'est pas un `.env` (config, script, YAML).
  Préfère une variable d'environnement lue au lancement. Si un fichier doit vraiment contenir
  la valeur, demande d'abord à l'utilisateur.
- Lancer `secret reveal`, `secret shell`, `secret env`, `secret unprotect`, `secret undo`,
  `secret rm`, `secret backup`, `secret restore`, `secret init`, `secret unlock`, `secret passwd`,
  `secret config masking off`,
  `secret config convert off` ou `secret config allow` : ces commandes sont réservées à
  l'utilisateur, dans son terminal, et refusées quand c'est toi qui les lances. Pour lui montrer
  des valeurs, c'est `secret show`.
- Demander à l'utilisateur de coller un mot de passe dans le chat. Dis-lui plutôt de taper,
  dans son terminal : `secret set NOM` (saisie masquée). Avec un `.env` dans le dossier
  courant, la référence y est ajoutée automatiquement.
- Lui proposer le préfixe `!` de Claude Code (`! secret unlock`, `! secret show`, `! secret set`) :
  la commande tourne alors dans ta session, et sa sortie comme sa saisie passent par la
  conversation. Ces commandes se tapent dans **un autre terminal**, hors de Claude Code.

## Dépannage

- `[secret:espace/CLÉ]` dans une sortie : la valeur a été masquée, la commande a bien reçu la vraie valeur.
- `[masqué:CLÉ]` sur une valeur manifestement inoffensive : c'est un faux positif du tri. Signale-le ;
  l'utilisateur peut l'exclure avec `secret config allow CLÉ`.
- « références absentes du coffre » : le `.env` cite un secret inconnu ici (projet copié d'un autre
  poste, par exemple). L'utilisateur le recrée avec `secret set espace/CLÉ` ou restaure une sauvegarde.
- Une valeur a été chiffrée alors qu'elle devait rester lisible (une URL, un nom) : l'utilisateur
  lance `secret unprotect FICHIER CLÉ` dans son terminal, elle sera marquée `# @public`.
- « secret introuvable » au démarrage, ou lecture de `.env` refusée « par sécurité » : le
  plugin est cassé ou en cours de mise à jour. Toute lecture de `.env` est bloquée, le reste
  fonctionne. Propose à l'utilisateur de relancer `install.ps1` (Windows) ou `install.sh`
  (Linux), puis Claude Code.
- « aucune clé de coffre » (Linux) : l'utilisateur lance `secret init` dans son terminal.
- Vérifier l'installation : `secret doctor`.
