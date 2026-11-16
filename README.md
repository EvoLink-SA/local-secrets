# local-secrets

Keep your project secrets (passwords, API keys, SSH and Windows credentials) in your `.env` files as usual, but never in clear text on disk, never sent to the AI, never written to a transcript. Claude Code uses the values without seeing them.

- **Windows**: values encrypted with DPAPI, nothing to unlock.
- **Linux and WSL**: values encrypted with a per-account key, unlocked by a passphrase.
- **Local only**: no cloud service, no account.

## How it works

```
Your .env                  When Claude touches it           The file becomes
SERVER_IP=192.168.10.25    secret sorts each line           SERVER_IP=192.168.10.25
DB_PASSWORD=Hunter2!x      secrets go to the local vault    DB_PASSWORD=secret://myproject/DB_PASSWORD
DEBUG=false                the rest is left alone           DEBUG=false
```

- Sorting is done by the local `secret` binary, not by the AI: the AI never reads the value.
- Your terminal loads the real values when you enter the project folder.
- Claude runs commands with `secret run -- docker compose up -d`: values are injected, and masked in the output.
- Anything Claude reads elsewhere (SSH, `docker inspect`, API responses) is scanned, and secrets are masked before Claude sees them.

## Install

**Windows** 10/11 x64, PowerShell 7, Claude Code. No .NET runtime needed.

```powershell
git clone https://github.com/EvoLink-SA/local-secrets.git
cd local-secrets
.\install.ps1
```

**Linux x86_64 or WSL 2**, bash or zsh, OpenSSL, Claude Code installed on the Linux side.

```bash
git clone https://github.com/EvoLink-SA/local-secrets.git
cd local-secrets
./install.sh
```

No admin rights needed. The script runs the self-tests, adds `secret` to the PATH, hooks your shell profile, installs the Claude Code plugin (`local-secrets` or `local-secrets-linux`) and runs `secret doctor`. On Linux it also creates the vault key (passphrase of 12+ characters).

Restart your terminals and Claude Code afterwards.

### Stay up to date (optional)

The script installs the plugin from your local clone. To get plugin updates automatically, switch to the GitHub marketplace:

```bash
claude plugin marketplace remove local-secrets          # removes the local one and its plugin
claude plugin marketplace add EvoLink-SA/local-secrets
claude plugin install local-secrets@local-secrets       # local-secrets-linux@local-secrets on Linux
```

Then in Claude Code: `/plugin` > **Marketplaces** > `local-secrets` > **Enable auto-update**.

The `secret` command in your terminal still comes from your clone: run `git pull` from time to time. `secret doctor` warns when the two versions differ.

## Daily use

1. Fill your `.env` as before, secrets and settings mixed.
2. When Claude reads or edits it, secrets are encrypted and replaced by `secret://` references. A message lists them.
3. In your terminal, nothing changes: `docker compose up`, `npm run dev`, `code .` get the real values.
4. To add a secret without typing it anywhere: `secret set NAME`.
5. To change one: put the new value in clear in the `.env`, it is encrypted on next access.
6. To see values: ask Claude, `secret show` opens a separate window only you can see.

Do not paste passwords in the chat: the plugin blocks the message (add `[nosecret]` to force it).

**Linux only**: unlock the key once per boot.

```bash
secret unlock              # 12 h by default, --for 8h, 30m, 2d
secret unlock --remember   # reopen automatically (Windows DPAPI under WSL, GNOME Keyring or KWallet on a desktop)
secret lock                # lock now
```

## What gets encrypted

- Key names like PASSWORD, SECRET, TOKEN, KEY, AUTH, CREDENTIAL, PRIVATE (also French, German, Italian).
- Values that look like secrets: PEM keys, known tokens (`sk-`, `ghp_`, `AKIA`, JWT), URLs with a password, connection strings.
- Random-looking values of 16+ characters under a neutral name.

IPs, hostnames, ports, paths, emails, usernames and `${VAR}` references stay readable. Force a choice with a trailing `# @secret` or `# @public` comment. `secret status` shows each decision and why.

## Commands

| Command | What it does |
|---|---|
| `secret status [FILE]` | state of each key, never the values |
| `secret run [-e FILE] -- CMD` | run CMD with secrets injected, output masked |
| `secret set NAME` / `secret generate KEY` | store a typed / random secret |
| `secret show` | show values in a separate window |
| `secret import [PATH]` | encrypt the `.env` files of a folder now |
| `secret undo [FILE \| --under DIR]` | restore `.env` files from before conversion |
| `secret config masking off --here` | disable output masking for a folder |
| `secret config convert off --here` | never convert `.env` files in a folder |
| `secret backup` / `secret restore` | passphrase-protected backup, works across Windows and Linux |
| `secret doctor` | check the install |

`secret help` lists everything. Commands that weaken protection (`reveal`, `rm`, `unprotect`, `config ... off`) only work from your own terminal, never from Claude.

To keep a single `.env` untouched, add the line `# local-secrets: ignore`.

## What it protects

Protected: files at rest (copied, synced, pushed to git), the model context, Claude Code transcripts, secrets with a recognizable shape read from servers or APIs.

Not protected:
- malware running under your account (it can decrypt like you do);
- a secret you paste yourself in the chat (`secret scrub --ask` removes it from local transcripts);
- deliberate bypass: hooks prevent accidents, they are not a sandbox;
- old copies on an SSD: use BitLocker or LUKS.

## Backup

A DPAPI vault only opens under your Windows account on this PC. A Linux vault needs its passphrase. Run `secret backup` and keep the file and its passphrase off the machine. `secret doctor` warns after 30 days without a backup.

Vault location: `~/.local-secrets` (`%USERPROFILE%\.local-secrets` on Windows).

## Uninstall

```powershell
.\uninstall.ps1    # or ./uninstall.sh
```

It offers to restore your `.env` files in clear first, then removes the plugin, PATH entry and shell hook. The vault stays: back it up before deleting it.

## Development

```powershell
.\build.ps1          # native AOT build + self-tests (.NET 10 SDK, Visual Studio C++ tools)
.\build.ps1 -Linux   # linux-x64 build in Docker
.\tests\e2e.ps1      # end-to-end tests (wsl bash tests/e2e.sh for Linux)
```

The compiled binaries in `plugins/*/tools` are committed: rebuild and commit them with each version.

Detailed guide (French): [docs/guide-fr.md](docs/guide-fr.md).

## License

MIT, see [LICENSE](LICENSE).
