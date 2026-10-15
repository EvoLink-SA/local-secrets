# local-secrets

Les identifiants d'un projet (mots de passe, clés d'API, SSH, comptes Windows) restent dans ton
`.env` comme d'habitude, mais plus jamais en clair sur le disque, et jamais transmis à l'IA ni
écrits dans un transcript. Claude Code s'en sert sans voir les valeurs, et toi tu continues à
travailler comme avant. Tout est local : chiffrement DPAPI de Windows, aucun service cloud.

## Le principe en une image

```
Tu écris ton .env          Claude ou ton terminal y touche              Le fichier devient
------------------         ------------------------------------------   ------------------------------------------
SERVER_IP=192.168.10.25    un script local trie chaque ligne            SERVER_IP=192.168.10.25
DB_PASSWORD=Xk9#mP2vL!q    -> les secrets partent dans le coffre        DB_PASSWORD=secret://monprojet/DB_PASSWORD
DEBUG=false                   DPAPI, le reste ne bouge pas              DEBUG=false

Ton terminal PowerShell : en entrant dans le projet, les vraies valeurs sont chargées en mémoire.
Claude : secret run -- docker compose up -d  injecte les valeurs et les masque dans la sortie.
```

Ce n'est **pas l'IA qui trie** : pour savoir si une valeur est un mot de passe, elle devrait la
lire, et c'est justement ce qu'on évite. Le tri est fait par `secret.exe`, avant que Claude voie
le fichier.

## Installation

Prérequis : Windows 10 ou 11, PowerShell 7, le SDK .NET 10 (pour compiler), Claude Code.

```powershell
git clone https://github.com/EvoLink-SA/local-secrets.git
cd local-secrets
.\install.ps1
```

Le script, sans droits administrateur :
1. compile `secret.exe` et lance ses tests internes ;
2. ajoute `plugins\local-secrets\bin` au PATH utilisateur ;
3. ajoute une ligne à ton profil PowerShell 7 pour le chargement automatique (`-NoShellIntegration` pour s'en passer) ;
4. déclare la marketplace locale et installe le plugin `local-secrets` dans Claude Code ;
5. lance `secret doctor`.

Relance ensuite tes terminaux, Claude Code et Claude Desktop.

## Au quotidien

1. Tu remplis ton `.env` comme avant, tout mélangé (IP, FQDN, ports, mots de passe...).
2. Dès que Claude ouvre une session dans le projet, ou lit, cherche ou cite le fichier, ou que tu
   entres dans le dossier avec ton terminal, les valeurs sensibles sont chiffrées et remplacées par
   des références `secret://`. Un message te dit lesquelles.
3. **Dans ton terminal PowerShell**, rien ne change : en entrant dans le projet, les secrets sont
   chargés en mémoire (`local-secrets : 3 secret(s) chargé(s) pour ...`), et retirés en sortant.
   `docker compose up -d`, `npm run dev`, `python app.py` ou `code .` fonctionnent sans préfixe.
4. **Claude** lance ce qui a besoin des secrets avec `secret run -- ...`, ou directement si tu l'as
   démarré depuis ce terminal.

Pour changer un mot de passe, remets la nouvelle valeur en clair dans le `.env` : elle sera
chiffrée au prochain accès. Pour ajouter un secret sans jamais l'écrire nulle part :
`secret set NOM` (saisie masquée), la référence est ajoutée au `.env` du dossier. Dans ton
terminal, `Update-LocalSecrets -Force` recharge tout de suite.

**Ne colle pas de mot de passe dans le chat.** S'il en détecte un, le plugin bloque le message
avant l'envoi. Ajoute `[nosecret]` au message pour forcer l'envoi.

## Voir les valeurs

Demande-le simplement à Claude (« montre-moi les secrets du .env »). Il lance `secret show`, une
fenêtre s'ouvre à part sur ton écran, tu confirmes, tu vois les valeurs, l'écran est effacé à la
fermeture. Claude ne reçoit qu'un accusé de réception. Pendant l'affichage et dix minutes après,
ses captures d'écran et la lecture du presse-papiers sont bloquées. Dans ton terminal,
`secret show` affiche directement.

## Serveur distant

Le plugin ne touche jamais aux fichiers d'un serveur : il ne convertit que des fichiers présents
sur ton PC. Claude peut gérer le serveur normalement (`ssh root@srv "docker compose up -d"`), les
programmes distants lisent leurs valeurs eux-mêmes. Ce qu'il lit là-bas passe par le masquage
générique (plus bas).

Pour faire passer un secret entre le serveur et ton poste sans qu'il le voie, la valeur passe par
un tuyau, jamais par l'écran :

```bash
# du serveur vers le .env local (guillemets gérés, valeurs anodines laissées en clair)
ssh root@srv "cat /opt/app/.env" | secret import --stdin --only DB_PASSWORD,DB_HOST

# du coffre local vers le serveur
secret run -- bash -c 'printf "DB_PASSWORD=%s\n" "$DB_PASSWORD" | ssh root@srv "cat >> /opt/app/.env"'
```

Le `.env` reste en clair sur le disque du serveur : DPAPI ne peut rien côté Linux (droits 600,
secrets Docker ou sops pour ça).

## Le tri

Une valeur est chiffrée si :
- le nom de la clé contient PASSWORD, PASS, PWD, SECRET, TOKEN, KEY, AUTH, CREDENTIAL, PRIVATE, SALT, COOKIE, WEBHOOK, etc. ;
- ou sa forme trahit un secret : clé PEM, jeton connu (`sk-`, `ghp_`, `AKIA`, JWT...), URL avec
  mot de passe, chaîne de connexion avec `Password=`, chaîne aléatoire, mot de passe probable.

Restent en clair : IP, FQDN, URL sans identifiants, ports, nombres, booléens, chemins, e-mails,
images Docker, versions, mots simples, et les noms d'utilisateur. Une clé sensible mais neutre
(`PASSWORD_MIN_LENGTH=12`, `SSH_KEY_PATH=C:\...`, `TOKEN_URL=https://...`) reste lisible.

Dans le doute, le tri chiffre : une valeur chiffrée à tort ne casse rien, Claude ne la voit
simplement pas. Pour forcer le choix, ajoute un commentaire en fin de ligne :

```
LICENCE_CLIENT=ABCD-1234     # @secret
PUBLIC_DSN=https://x.y/z     # @public
```

`secret status` montre la décision et sa raison pour chaque clé, sans afficher les valeurs.

## Masquage générique des sorties

En plus des valeurs du coffre, tout ce que Claude reçoit en retour d'une commande ou d'une
lecture de fichier est examiné. Ce qui est un secret est remplacé par `[masqué:CLÉ]`, sans être
stocké nulle part : le `.env` d'un serveur lu en SSH, `docker inspect`, `printenv`,
`docker compose config`, une réponse d'API, un mot de passe en dur dans une config.

Le critère est plus strict que pour les `.env`, pour ne pas gêner la lecture de configs et de
code. Une valeur n'est masquée que si :
- **elle a une forme de secret reconnaissable**, quel que soit son nom : clé PEM, jeton connu
  (`ghp_`, `sk-`, `AKIA`, JWT...), URL avec mot de passe, chaîne de connexion avec `Password=` ;
- **ou son nom est celui d'un secret** : `password`, `pwd`, `secret`, `token`, `apikey`,
  `credential`, `client_secret`... Pour un nom plus vague (`key`, `auth`, `session`, `cookie`,
  `license`...), il faut en plus que la valeur ait l'air aléatoire ou d'un mot de passe.

Une regex de matcher, un GUID, une empreinte git ou npm, du base64 d'image ou un identifiant de
build restent donc visibles. En contrepartie, un secret rangé sous un nom anodin (`NOTE=...`) passe
dans les sorties, faute d'indice. Dans un `.env` sur le disque, le tri complet le chiffre quand même.

```
ssh root@srv "cat /opt/app/.env"   ->   DB_HOST=db
                                        DB_PASSWORD=[masqué:DB_PASSWORD]
```

Formats repérés : `CLÉ=valeur`, `"CLÉ=valeur"` (docker inspect), `clé: valeur` (YAML),
`"clé": "valeur"` (JSON), `clé = "valeur"` (code, INI), tableaux `NOM  valeur` pour un nom
sensible, et partout les clés PEM, jetons reconnaissables et URL avec mot de passe. Le texte
libre (une phrase dans un log) n'est pas couvert.

Conséquences : une valeur `[masqué:...]` n'est pas réutilisable par Claude (enregistre-la avec
`secret set` s'il en a besoin) ; un enchaînement d'API où Claude doit relire un jeton renvoyé doit
tenir dans un seul script ; Claude ne peut pas écrire un masque dans un fichier ni dans une
commande ; un faux positif reste possible sur un nom de secret qui n'en contient pas un, et
`secret config allow CLÉ` l'exclut pour de bon.

### L'interrupteur

| Portée | Comment |
|---|---|
| une session lancée par un script | lancer Claude Code avec `LOCAL_SECRETS_OUTPUT_MASKING=off`, par exemple `$env:LOCAL_SECRETS_OUTPUT_MASKING='off'; claude -p "..."` |
| un dossier et ses sous-dossiers | `secret config masking off --here` (ou `--project CHEMIN`) |
| partout | `secret config masking off` |
| revenir en arrière | `secret config masking on` (avec `--here` pour un dossier) |

Seul le masquage générique est concerné : les valeurs du coffre restent toujours masquées, les
`.env` toujours convertis, les messages avec un mot de passe toujours bloqués. Claude ne peut ni
couper le masquage ni autoriser une clé.

## Exclure un dossier de la conversion

Pour un projet dont les `.env` doivent rester tels quels (lancé par un outil que tu ne contrôles
pas, par exemple) : `secret config convert off --here`. Les fichiers ne sont plus modifiés
automatiquement ; en échange, Claude ne peut plus lire ceux qui contiennent des secrets en clair,
pour qu'ils ne lui soient jamais transmis. `secret config convert on --here` annule.

## Commandes

| Commande | Rôle | Claude peut ? |
|---|---|---|
| `secret status [FICHIER]` | état de chaque clé : chiffrée, en clair, à chiffrer | oui |
| `secret show [FICHIER \| NOM]` | montrer des valeurs (fenêtre à part si c'est Claude) | oui |
| `secret import [CHEMIN] [--dry-run]` | chiffrer maintenant les `.env` d'un dossier | oui |
| `secret import --stdin [--to F] [--only K,K] [--secret]` | importer un `.env` reçu par un tuyau | oui |
| `secret run [options] -- CMD` | lancer CMD avec les secrets, sortie masquée | oui |
| `secret list [--ns ESPACE]` | noms des secrets | oui |
| `secret set NOM [--env F] [--file F]` | enregistrer un secret (saisie masquée) | via un tuyau |
| `secret protect FICHIER CLÉ` | forcer le chiffrement d'une clé | oui |
| `secret scrub [--dry-run] [--ask]` | effacer les valeurs des fichiers locaux de Claude Code | oui |
| `secret config` | réglages du masquage et de la conversion | oui |
| `secret config masking on` / `convert on` | rallumer | oui |
| `secret config masking off` / `convert off` | couper | **non** |
| `secret config allow CLÉ` / `disallow CLÉ` | clés jamais masquées dans les sorties | **non** / oui |
| `secret doctor` / `secret selftest` | vérifier l'installation / tests internes | oui |
| `secret reveal NOM` | afficher une valeur dans ton terminal | **non** |
| `secret shell` | terminal avec les secrets injectés | **non** |
| `secret env` | utilisé par le profil PowerShell | **non** |
| `secret unprotect FICHIER CLÉ` | remettre une clé en clair (`# @public`) | **non** |
| `secret undo [FICHIER]` | restaurer un `.env` d'avant conversion | **non** |
| `secret rm NOM` | supprimer un secret | **non** |
| `secret backup` / `secret restore` | sauvegarde par phrase de passe | **non** |

Les commandes marquées « non » exigent un vrai terminal hors Claude Code, et sont en plus bloquées
par les hooks.

Options de `secret run` : `-e FICHIER` (autre `.env`, répétable), `--ns ESPACE`,
`-s espace/CLÉ=VARIABLE`, `--ssh-pass CLÉ`. Dans un argument, `secret://CLÉ` est remplacé par
la valeur.

## Cas particuliers

**Hors de ton terminal PowerShell.** Docker Desktop, un bouton « Run » d'IDE lancé autrement, une
tâche planifiée : ils lisent le `.env` eux-mêmes et reçoivent les références. Lance-les via
`secret run --`, ou ouvre l'IDE depuis ton terminal (`code .`). Une tâche planifiée doit tourner
sous ton compte : sous SYSTEM ou un compte de service, le coffre est illisible.

**Docker Compose.** Compose prend les variables d'environnement avant le `.env`, donc les vraies
valeurs gagnent. Si ton compose utilise `env_file: .env`, les conteneurs recevraient les
références : passe ces variables par `environment:` (`POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}`).
Attention au premier démarrage d'une base : lancée une fois avec les références, elle les garde
comme mot de passe.

**SSH par clé.** L'agent ssh de Windows garde la clé chiffrée (DPAPI), et le fichier en clair peut
ensuite être supprimé. Une fois, dans un PowerShell administrateur :

```powershell
Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent
```

Puis, en utilisateur normal : `ssh-add C:\chemin\id_ed25519`. Claude ne peut pas lire les fichiers
de clé privée.

**SSH par mot de passe** (expérimental) :
`secret run --ssh-pass SSH_PASS -- ssh -o StrictHostKeyChecking=accept-new root@10.0.0.5 "uptime"`.
Pas encore validé sur un vrai serveur.

**WSL.** `secret run -- wsl ...` (ou le `bash` de WSL) transmet les variables. Un shell WSL lancé
autrement ne les reçoit pas.

**Identifiants Windows.** Voir le skill : un `PSCredential` est construit en mémoire dans un
`pwsh -Command '...'` lancé par `secret run`.

## Ce que ça protège, et ce que ça ne protège pas

Protégé :
- le disque au repos : `.env` copié, sauvegardé, synchronisé, poussé sur git, lu par un autre compte ;
- le contexte du modèle, donc ce qui part chez Anthropic ;
- les transcripts de Claude Code : vérifié sur de vraies sessions, aucune valeur n'y figure, même
  pour un fichier ou une sortie masqués au vol ;
- ce que Claude lit ailleurs (serveur, conteneur, API), tant que la valeur a une forme reconnaissable.

Pas protégé :
- **un programme malveillant qui tourne sous ta session** : il peut appeler DPAPI comme Claude, ou
  lire les variables de ton terminal. C'est la limite de tout accès automatique ;
- **un secret que tu donnes toi-même dans le chat** : même bloqué, le texte peut rester dans le
  transcript local. `secret scrub --ask` l'efface ;
- **une valeur que Claude écrit lui-même** (parce que tu la lui as donnée) : chiffrée juste après
  dans le `.env`, mais présente dans le transcript de la session. `secret scrub` l'efface ;
- **un contournement délibéré** : Claude Code n'a pas de sandbox sous Windows. Les hooks évitent
  les accidents, ce n'est pas une cage ;
- **les traces de l'ancien fichier sur le disque** : le contenu en clair est écrasé avant
  réécriture, mais un SSD peut garder des copies. Active BitLocker.

## Sauvegarde et changement de PC

Un coffre DPAPI ne se relit que sous **ton compte Windows, sur ce PC**. Pour changer de machine
ou réinstaller :

```powershell
secret backup D:\coffre.lsbackup      # phrase de passe demandée, 12 caractères minimum
secret restore D:\coffre.lsbackup     # sur la nouvelle machine
```

## Où sont les fichiers

| Quoi | Où |
|---|---|
| Coffre | `%LOCALAPPDATA%\local-secrets\vault.json` (chaque valeur chiffrée DPAPI) |
| Copies des `.env` d'origine | `%LOCALAPPDATA%\local-secrets\backups\` (chiffrées, 10 par fichier) |
| Réglages | `%LOCALAPPDATA%\local-secrets\config.json` |
| Journal (noms et actions, jamais de valeur) | `%LOCALAPPDATA%\local-secrets\local-secrets.log` |
| Chargement automatique du terminal | `shell\local-secrets.profile.ps1`, appelé depuis ton profil PowerShell 7 |
| Plugin | `plugins\local-secrets\` (hooks, skill, `bin\secret.exe`) |
| Code source | `src\LocalSecrets\` (C#, .NET 10) |

## Désinstaller

```powershell
claude plugin uninstall local-secrets@local-secrets
claude plugin marketplace remove local-secrets
```

Retire ensuite `plugins\local-secrets\bin` du PATH utilisateur, et la ligne marquée
`# local-secrets` de ton profil PowerShell (`notepad $PROFILE.CurrentUserAllHosts`). Le coffre
reste en place : fais un `secret backup` avant de le supprimer, et un `secret undo` sur les `.env`
que tu veux retrouver en clair.

## Développement

```powershell
.\build.ps1                 # compile et lance secret selftest
.\tests\e2e.ps1             # tests de bout en bout : CLI, hooks, terminal, fenêtre, WSL
claude --plugin-dir .\plugins\local-secrets    # essayer le plugin sans l'installer
```

`LOCAL_SECRETS_HOME` permet de pointer vers un autre coffre, pour les tests.

## Dépannage

- `secret doctor` vérifie DPAPI, le coffre, le PATH, le plugin et l'agent ssh.
- `[secret:espace/CLÉ]` dans une sortie : valeur du coffre masquée, le programme a reçu la vraie.
- `[masqué:CLÉ]` : valeur repérée comme sensible, masquée et non stockée.
- « références absentes du coffre » : le `.env` cite un secret qui n'existe pas sur ce PC (projet
  copié d'ailleurs). Recrée-le avec `secret set espace/CLÉ` ou restaure une sauvegarde.
- Le terminal ne charge rien : vérifie que `secret` est dans le PATH et que la ligne
  `# local-secrets` est dans ton profil, puis ouvre un nouveau terminal.
- Depuis Git Bash, un argument qui commence par `/` est converti en chemin : `cmd //c`, pas `cmd /c`.
