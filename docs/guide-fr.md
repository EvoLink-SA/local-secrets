# local-secrets

Les identifiants d'un projet (mots de passe, clés d'API, SSH, comptes Windows) restent dans ton
`.env` comme d'habitude, mais plus jamais en clair sur le disque, et jamais transmis à l'IA ni
écrits dans un transcript. Claude Code s'en sert sans voir les valeurs, et toi tu continues à
travailler comme avant. Tout est local, aucun service cloud : chiffrement DPAPI sous Windows,
clé du compte déverrouillée par phrase de passe sous Linux et WSL (voir [Linux et WSL](#linux-et-wsl)).

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

Prérequis : Windows 10 ou 11 (x64), PowerShell 7, Claude Code. Rien d'autre : `secret.exe` est
livré compilé en natif, sans runtime .NET à installer.

```powershell
git clone https://github.com/EvoLink-SA/local-secrets.git
cd local-secrets
.\install.ps1
```

Le script, sans droits administrateur :
1. lance les tests internes de `secret.exe` (`-Build` pour le recompiler d'abord, voir Développement) ;
2. ajoute `plugins\local-secrets\tools` au PATH utilisateur ;
3. ajoute une ligne à ton profil PowerShell 7 pour le chargement automatique (`-NoShellIntegration` pour s'en passer) ;
4. déclare la marketplace locale et installe le plugin `local-secrets` dans Claude Code ;
5. lance `secret doctor`.

Relance ensuite tes terminaux, Claude Code et Claude Desktop.

## Linux et WSL

Prérequis : Linux x86_64 (poste, serveur ou WSL 2), bash, zsh ou fish, OpenSSL (présent sur les
distributions courantes), Claude Code installé côté Linux. Le binaire `secret` est livré compilé.

```bash
git clone https://github.com/EvoLink-SA/local-secrets.git
cd local-secrets
./install.sh
```

Le script, sans droits root :
1. lance les tests internes de `secret` ;
2. crée le lien `~/.local/bin/secret` ;
3. branche le chargement automatique : une ligne dans `~/.bashrc` (et `~/.zshrc` s'il existe), et `~/.config/fish/conf.d/local-secrets.fish` si fish est installé ;
4. déclare la marketplace locale et installe le plugin `local-secrets-linux` dans Claude Code ;
5. crée la clé du coffre (`secret init`, phrase de passe de 12 caractères minimum) ;
6. lance `secret doctor`.

**Ce qui change par rapport à Windows.** Il n'y a pas de DPAPI : chaque valeur est chiffrée avec
la clé publique d'une paire propre à ton compte (ECDH P-256, AES-256-GCM). La clé privée est
rangée dans `~/.local-secrets/key.json`, chiffrée par ta phrase de passe. Pour l'utiliser :

```bash
secret unlock            # une fois après chaque démarrage, valable 12 h par défaut
secret unlock --for 8h   # ou 30m, 2d (7 jours au plus)
secret lock              # reverrouille tout de suite
secret passwd            # change la phrase de passe
```

Déverrouillée, la clé privée reste en mémoire dans le trousseau noyau de ton compte, jamais en
clair sur le disque ; elle disparaît au redémarrage ou à la fin de la durée choisie. Coffre
verrouillé, les `.env` sont quand même convertis (seule la clé publique sert à chiffrer), mais
`secret run` et le chargement du terminal demandent un `secret unlock`. Claude ne peut ni
déverrouiller ni recevoir la phrase de passe : il te demande de le faire dans un autre terminal.

**Ne plus taper la phrase de passe** (poste de travail) :

```bash
secret unlock --remember   # une fois : la clé est confiée au gardien de ta session
secret lock                # reverrouille ; pas de réouverture seule avant ton prochain unlock
secret lock --forget       # reverrouille et retire la copie confiée au gardien
```

Le gardien est la **DPAPI de Windows sous WSL** (le `secret.exe` du même dépôt, appelé à travers
WSL : la clé ne revient jamais en clair dans sa sortie, elle est chiffrée pour une clé jetable du
processus qui la demande), ou le **trousseau de session sur un bureau Linux** (GNOME Keyring,
KWallet, via `secret-tool`). Le coffre se rouvre alors tout seul, comme sous Windows. Sur un
serveur sans bureau, il n'y a pas de gardien : la phrase de passe reste la seule clé.

Dans le terminal, le chargement automatique fonctionne comme sous PowerShell ; après un
`secret set` ou un `secret unlock`, recharge avec `local_secrets_reload`. Une clé dont le nom
n'est pas un nom de variable shell (`3CX_PASSWORD`) n'est pas chargée : passe par `secret run`.
`secret show` lancé par Claude ouvre une fenêtre à part : une console Windows sous WSL, un
terminal graphique sur un bureau. En SSH, sans écran, lance-le toi-même dans un autre terminal.

**Passer un coffre de Windows à Linux** : `secret backup` sous Windows, copie le fichier, puis
`secret restore` sous Linux. Un `vault.json` copié tel quel est refusé, avec la marche à suivre.

## Au quotidien

1. Tu remplis ton `.env` comme avant, tout mélangé (IP, FQDN, ports, mots de passe...).
2. Quand Claude lit, modifie ou cite dans une commande le `.env` **du projet où tu l'as ouvert**,
   les valeurs sensibles sont chiffrées et remplacées par des références `secret://`. Un message te
   dit lesquelles. Rien d'autre n'est converti : ni au démarrage d'une session, ni lors d'une
   recherche dans un dossier, ni quand ton terminal entre dans un dossier, ni le `.env` d'un autre
   projet (un autre dépôt git sous le dossier ouvert compte comme un autre projet). Un tel fichier,
   s'il contient des secrets en clair, est simplement illisible pour Claude.
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
- le nom de la clé contient PASSWORD, PASS, PWD, SECRET, TOKEN, KEY, AUTH, CREDENTIAL, PRIVATE, SALT, COOKIE, WEBHOOK, etc.,
  ou leurs équivalents français, allemands et italiens (MOTDEPASSE, CLE, PASSWORT, KENNWORT,
  SCHLUESSEL, GEHEIM, SEGRETO, CHIAVE, JETON) ;
- ou sa forme trahit un secret : clé PEM, jeton connu (`sk-`, `ghp_`, `AKIA`, JWT...), URL avec
  mot de passe, chaîne de connexion avec `Password=` ;
- sous un nom anodin, seulement si la valeur est vraiment aléatoire (16 caractères ou plus). Un nom
  neutre (`..._ID`, `..._TABLE`, `..._NAME`) la laisse toujours en clair.

Restent en clair : IP, FQDN, URL sans identifiants, ports, nombres, booléens, chemins, e-mails,
images Docker, versions, mots simples, et les noms d'utilisateur. Une clé sensible mais neutre
(`PASSWORD_MIN_LENGTH=12`, `SSH_KEY_PATH=C:\...`, `TOKEN_URL=https://...`) reste lisible. Les
renvois à d'autres variables aussi : `${DB_PASS}`, `$DB_PASS`, `${REDIS_PASSWORD:-x}` ou
`postgres://${DB_USER}:${DB_PASS}@db/app` ne contiennent aucun secret, ils restent tels quels.

Pour un nom de secret, le tri chiffre dans le doute : une valeur chiffrée à tort ne casse rien,
Claude ne la voit simplement pas. Pour forcer le choix, ajoute un commentaire en fin de ligne :

```
LICENCE_CLIENT=ABCD-1234     # @secret
PUBLIC_DSN=https://x.y/z     # @public
```

`secret status` montre la décision et sa raison pour chaque clé, sans afficher les valeurs. Il
signale aussi les lignes qu'il ne reconnaît pas : elles sont ignorées par le tri, donc jamais
chiffrées. La conversion les signale aussi, avec leurs numéros. Les formats reconnus sont
`CLÉ=valeur` (avec ou sans `export`, guillemets, valeurs sur plusieurs lignes) et `clé:valeur`,
que certains scripts maison utilisent. Une ligne `clé:valeur` garde son format après conversion
(`ssh_password:secret://...`). Une clé peut commencer par des chiffres (`3CX_PASSWORD`) à
condition de contenir une lettre : `10.0.0.1:22` reste une ligne de texte.

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

Formats repérés : `CLÉ=valeur`, `"CLÉ=valeur"` (docker inspect), `clé: valeur` ou `clé:valeur`
(YAML, `.env` maison), `"clé": "valeur"` (JSON), `clé = "valeur"` (code, INI), tableaux
`NOM  valeur` quand le nom et la valeur ressemblent tous deux à un secret, et partout les clés PEM,
jetons reconnaissables et URL avec mot de passe. Les adresses et chemins faits de morceaux lisibles
(`DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus`) restent visibles. Le texte libre (une
phrase dans un log) n'est pas couvert.

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

Pour un seul fichier, par exemple un `.env` de déploiement qui doit garder ses vraies valeurs,
ajoute cette ligne dedans :

```
# local-secrets: ignore
```

Il ne sera plus jamais converti, ni par Claude ni par `secret import`, et Claude ne pourra pas le
lire tant qu'il contient des secrets en clair.

Claude peut quand même faire évoluer un tel fichier sans le lire :
- `secret generate CLÉ --env FICHIER --clear` y écrit une valeur aléatoire solide (32 caractères,
  `--length N` pour changer), jamais affichée ;
- `secret setenv FICHIER CLÉ VALEUR` y écrit une valeur publique (port, hôte, nom), et refuse ce
  qui ressemble à un secret ;
- `secret status FICHIER` lui montre les clés présentes et leur état, sans les valeurs.

Sans `--clear`, `secret generate CLÉ` met la valeur au coffre et écrit la référence dans le `.env`
du dossier courant : c'est le bon réflexe pour un nouveau mot de passe de base de données.

## Annuler des conversions

Chaque conversion garde une copie chiffrée du fichier d'origine. Dans ton terminal :

```powershell
secret undo --under C:\tools --since "2026-10-19 10:50" --dry-run
```

Tu obtiens la liste des fichiers convertis sous `C:\tools` depuis cette date, avec la version qui
serait remise, sans rien toucher. Retire `--dry-run` pour restaurer, après une seule confirmation.
Avec `--since`, c'est la version d'avant la première conversion faite depuis cette date qui
revient. Un fichier modifié depuis sa conversion est laissé de côté, sauf avec `--force`. Ajoute
`--ignore` pour marquer les fichiers restaurés et qu'ils ne soient plus jamais convertis.
`secret undo FICHIER` fait la même chose pour un seul fichier. Les secrets restent dans le coffre.

## Un seul coffre, même avec Claude Desktop

Le coffre est dans `%USERPROFILE%\.local-secrets`. Jusqu'à la 0.1.2, il était dans `AppData`, où
Windows redirige les écritures de Claude Desktop (une application empaquetée MSIX) vers une copie
privée : les sessions de l'application et ton terminal voyaient alors deux coffres différents. Les
anciens emplacements sont fusionnés automatiquement dans le coffre unique dès qu'ils changent, sans
rien supprimer. En cas de conflit, la valeur la plus récente gagne. `secret migrate` relance la
fusion et en affiche le compte rendu, et `secret migrate --from DOSSIER` y ajoute une copie de
secours. Lance-le une fois dans ton terminal après la mise à jour : lui seul voit le vrai ancien
coffre, Claude Desktop ne voit que sa copie.

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
| `secret generate CLÉ [--env F] [--length N] [--clear]` | créer une valeur aléatoire sans l'afficher | oui |
| `secret setenv FICHIER CLÉ VALEUR` | écrire une valeur publique dans un `.env` sans le lire | oui |
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
| `secret unprotect --all \| --under DOSSIER [--ignore]` | remettre en clair tous les `.env` connus du coffre | **non** (sauf `--dry-run`) |
| `secret undo [FICHIER \| --under DOSSIER] [--since DATE] [--ignore]` | restaurer des `.env` d'avant conversion | **non** (sauf `--dry-run`) |
| `secret migrate [--from DOSSIER]` | fusionner les anciens coffres dans le coffre unique | oui |
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

**SSH par mot de passe.**
`secret run --ssh-pass SSH_PASS -- ssh -o StrictHostKeyChecking=accept-new root@10.0.0.5 "uptime"`.
Le mot de passe est fourni à ssh par SSH_ASKPASS, sans passer par l'écran ni par Claude. Validé
le 2026-10-15 sur un serveur Linux, avec le ssh de Windows (OpenSSH 9.5) et celui de Git Bash,
depuis un terminal comme depuis Claude. `scp` et `sftp` passent par le même mécanisme (non testés). Les équipements qui
demandent autre chose qu'un mot de passe (double authentification) ne sont pas couverts.

**WSL.** `secret run -- wsl ...` (ou le `bash` de WSL) transmet les variables. Un shell WSL lancé
autrement ne les reçoit pas.

**Identifiants Windows.** Voir le skill : un `PSCredential` est construit en mémoire dans un
`pwsh -Command '...'` lancé par `secret run`.

**Autres fichiers d'identifiants.** `.pgpass` (ou `pgpass.conf`), `.netrc` (`_netrc`),
`.git-credentials` et `.aws\credentials` ne sont pas des `.env` : ils ne sont jamais convertis,
mais Claude ne peut pas les lire, et leur contenu est masqué s'il apparaît dans une sortie
(`cat ~/.pgpass` sur un serveur, par exemple). Les fichiers INI avec espaces (`password = ...`,
comme `my.cnf`) sont masqués de la même façon.

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
  réécriture, mais un SSD peut garder des copies. Active BitLocker (ou LUKS sous Linux).

Sous Linux, l'environnement d'un programme lancé par `secret run` est lisible par ton compte
(`/proc/PID/environ`, `ps e`) : les hooks refusent ces lectures à Claude, comme celle du
trousseau qui garde la clé déverrouillée. Le coffre est en 700 et ses fichiers en 600.

## Sauvegarde et changement de PC

Un coffre DPAPI ne se relit que sous **ton compte Windows, sur ce PC**. Pour changer de machine
ou réinstaller :

```powershell
secret backup D:\coffre.lsbackup      # phrase de passe demandée, 12 caractères minimum
secret restore D:\coffre.lsbackup     # sur la nouvelle machine
```

Sans sauvegarde depuis 30 jours, Claude Code te le rappelle au démarrage d'une session, une fois
par semaine au plus, et `secret doctor` le signale. Range le fichier hors du PC (clé USB, NAS) et
la phrase de passe à part : la perte du profil Windows ou une réinitialisation du mot de passe par
un administrateur rend le coffre illisible. Sous Linux, c'est l'oubli de la phrase de passe qui
le rend illisible. La même sauvegarde se restaure sur l'un ou l'autre système.

## Où sont les fichiers

| Quoi | Où |
|---|---|
| Coffre | `%USERPROFILE%\.local-secrets\vault.json` (chaque valeur chiffrée DPAPI) |
| Copies des `.env` d'origine | `%USERPROFILE%\.local-secrets\backups\` (chiffrées, 10 par fichier) |
| Réglages | `%USERPROFILE%\.local-secrets\config.json` |
| Journal (noms et actions, jamais de valeur) | `%USERPROFILE%\.local-secrets\local-secrets.log` |
| Anciens coffres, fusionnés et laissés intacts | `%LOCALAPPDATA%\local-secrets\`, et la copie privée de Claude Desktop sous `%LOCALAPPDATA%\Packages\Claude_...\LocalCache\Local\` |
| Chargement automatique du terminal | `shell\local-secrets.profile.ps1`, appelé depuis ton profil PowerShell 7 |
| Plugin | `plugins\local-secrets\` (hooks, skill, `tools\secret.exe`) |
| Code source | `src\LocalSecrets\` (C#, .NET 10) |

## Désinstaller

Dans ton terminal, depuis le dossier du dépôt :

```powershell
.\uninstall.ps1
```

Le script montre d'abord les `.env` qui contiennent des références `secret://` et propose de les
remettre en clair (`secret unprotect --all`) : sans ça, ces fichiers ne fonctionneraient plus une
fois l'outil retiré. Il retire ensuite le plugin, la marketplace, la ligne du profil PowerShell et
l'entrée du PATH. Le coffre (`%USERPROFILE%\.local-secrets`) reste en place : fais un
`secret backup` avant de le supprimer toi-même.

## Développement

```powershell
.\build.ps1                 # compile en natif (Native AOT) et lance secret selftest
.\build.ps1 -Linux          # compile le binaire linux-x64 dans Docker (SDK .NET 10 + clang)
.\tests\e2e.ps1             # tests de bout en bout : CLI, hooks, terminal, fenêtre, WSL
wsl bash tests/e2e.sh       # tests de bout en bout Linux : clé, verrouillage, pont WSL, terminal bash, hooks
.\tests\secret-service.ps1  # trousseau de session (GNOME Keyring) dans un conteneur Docker
claude --plugin-dir .\plugins\local-secrets    # essayer le plugin sans l'installer
```

Les deux variantes du plugin partagent le code et le skill : `build.ps1` recopie
`plugins\local-secrets\skills` dans `plugins\local-secrets-linux`. Les tests du trousseau noyau
se lancent dans WSL, pas dans Docker, dont le profil seccomp par défaut bloque ces appels.

La compilation native demande le SDK .NET 10 et les outils C++ de Visual Studio (charge
« Développement Desktop en C++ »). Sans eux, `.\build.ps1 -FrameworkDependent` produit un exe qui
exige le runtime .NET 10 sur chaque poste. Le `secret.exe` versionné dans `plugins\local-secrets\tools`
est celui que reçoivent les collègues : recompile et commite-le à chaque version.

`LOCAL_SECRETS_HOME` permet de pointer vers un autre coffre, pour les tests.

## Dépannage

- `secret doctor` vérifie DPAPI, le coffre, le PATH, le plugin et l'agent ssh, signale une
  sauvegarde trop ancienne et un écart de version entre `secret` et les hooks de Claude.
- « secret.exe introuvable » au démarrage d'une session : les hooks passent par `hook.cmd`, qui
  bloque alors toute lecture de `.env` (rien ne part en clair) et laisse passer le reste. Relance
  `install.ps1`.
- `[secret:espace/CLÉ]` dans une sortie : valeur du coffre masquée, le programme a reçu la vraie.
- `[masqué:CLÉ]` : valeur repérée comme sensible, masquée et non stockée.
- « références absentes du coffre » : le `.env` cite un secret qui n'existe pas sur ce PC (projet
  copié d'ailleurs). Recrée-le avec `secret set espace/CLÉ` ou restaure une sauvegarde.
- Le terminal ne charge rien : vérifie que `secret` est dans le PATH et que la ligne
  `# local-secrets` est dans ton profil, puis ouvre un nouveau terminal.
- Depuis Git Bash, un argument qui commence par `/` est converti en chemin : `cmd //c`, pas `cmd /c`.
