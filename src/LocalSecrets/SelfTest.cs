using System.Text;

namespace LocalSecrets;

// Tests internes, sans toucher au coffre réel : « secret selftest ».
static class SelfTest
{
    static int failures;

    static void Check(bool condition, string label)
    {
        Console.WriteLine((condition ? "  OK     " : "  ÉCHEC  ") + label);
        if (!condition) failures++;
    }

    public static int Run()
    {
        failures = 0;
        Console.WriteLine("Tri des valeurs");
        (string Key, string Value, bool Secret)[] cases =
        [
            ("SERVER_IP", "192.168.10.25", false),
            ("FQDN", "app.client.ch", false),
            ("HTTP_PORT", "8443", false),
            ("TZ", "Europe/Zurich", false),
            ("POSTGRES_USER", "appuser", false),
            ("POSTGRES_PASSWORD", "Xk9#mP2vL!q", true),
            ("API_TOKEN", "sk-proj-a8F3kL9mN2pQ7rS4tU6vW", true),
            ("DATABASE_URL", "postgres://appuser:Xk9#mP2vL!q@db:5432/app", true),
            ("SSH_USER", "root", false),
            ("SSH_PASS", "Winter2025!", true),
            ("SMTP_HOST", "mail.client.ch", false),
            ("DEBUG", "false", false),
            ("SESSION_LIFETIME", "120", false),
            ("PASSWORD_MIN_LENGTH", "12", false),
            ("SSH_KEY_PATH", @"C:\Users\x\.ssh\id_ed25519", false),
            ("ADMIN_PASSWORD", "admin", true),
            ("WEBHOOK_URL", "https://n8n.client.ch/webhook/4f1c2b7e-9a3d-4e5f-8b6a-1c2d3e4f5a6b", true),
            ("CLIENT_ID", "4f1c2b7e-9a3d-4e5f-8b6a-1c2d3e4f5a6b", false),
            ("RANDOM_THING", "a8F3kL9mN2pQ7rS4tU6vW", true),
            ("COMPOSE_PROJECT_NAME", "production-database-01", false),
            ("IMAGE", "ghcr.io/org/app:1.4.2", false),
            ("ALLOWED_HOSTS", "app.client.ch,localhost", false),
            ("APP_NAME", "Mon Application", false),
            ("NOTE", "Admin2024", false),
            ("R1_TENANT_ID", "a8F3kL9mN2pQ7rS4tU6vW", false),
            ("KB_SQL_TABLE", "OffresCommerciales_V2", false),
            ("AUTH_TYPE", "basic", false),
            ("KEY_ID", "abc123", false),
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE", true),
            ("SMTP_PASSWORD", "", false),
            ("TOKEN_URL", "https://login.example.com/oauth2/token", false),
            ("DB_CONN", "Server=db;Database=app;User Id=sa;Password=Xk9mP2vLq;", true),
            ("LETSENCRYPT_EMAIL", "admin@client.ch", false),
            ("N8N_BASIC_AUTH_ACTIVE", "true", false),
            ("APP_KEY", "base64:Q2hhbmdlTWVQbGVhc2UxMjM0NTY3ODk=", true),
            ("SNMP_COMMUNITY", "Fg7pr1v4te", true),
            ("PUID", "1000", false),
        ];
        foreach (var (key, value, secret) in cases)
        {
            var v = Classifier.Classify(key, value, Annotation.None);
            Check(v.Secret == secret, $"{key} -> {(secret ? "chiffré" : "en clair")} ({v.Reason})");
        }
        Check(Classifier.Classify("FOO", "bar", Annotation.Secret).Secret, "annotation @secret");
        Check(!Classifier.Classify("API_TOKEN", "x1y2z3w4", Annotation.Public).Secret, "annotation @public");

        Console.WriteLine("Fichiers .env");
        var sample = "# commentaire\r\nexport A=1\r\nB=\"deux mots\" # note\r\nC='x#y'\r\nD=valeur # fin\r\n" +
                     "KEY=\"-----BEGIN OPENSSH PRIVATE KEY-----\r\nabc\r\n-----END OPENSSH PRIVATE KEY-----\"\r\n" +
                     "F=secret12 # @secret\r\nE=\r\n";
        var bytes = Encoding.UTF8.GetBytes(sample);
        var env = EnvFile.Parse(bytes);
        Check(env.Render(new Dictionary<EnvAssignment, string>(), addHeader: false).AsSpan().SequenceEqual(bytes), "relecture et réécriture à l'identique (CRLF, commentaires, guillemets)");
        var byKey = env.Assignments.ToDictionary(a => a.Key);
        Check(byKey["A"].Value == "1" && byKey["B"].Value == "deux mots" && byKey["C"].Value == "x#y" && byKey["D"].Value == "valeur" && byKey["E"].Value == "",
              "valeurs : export, guillemets, # dans une valeur, commentaire de fin");
        Check(byKey["KEY"].Value.Contains("\nabc\n") && byKey["KEY"].EndLine - byKey["KEY"].StartLine == 3, "valeur sur plusieurs lignes (clé PEM)");
        Check(byKey["F"].Annotation == Annotation.Secret, "annotation lue dans le commentaire");
        var replaced = EnvFile.Parse(env.Render(new Dictionary<EnvAssignment, string> { [byKey["KEY"]] = "secret://t/KEY" }, addHeader: true));
        Check(replaced.Assignments.Select(a => a.Key).SequenceEqual(env.Assignments.Select(a => a.Key))
              && replaced.Assignments.First(a => a.Key == "KEY").Reference == "t/KEY"
              && replaced.Lines[0].Contains(EnvFile.HeaderMarker),
              "remplacement d'une valeur multiligne par une référence, en-tête ajouté");
        var utf16 = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("X=1\r\n")).ToArray();
        Check(EnvFile.Parse(utf16).Render(new Dictionary<EnvAssignment, string>(), false).AsSpan().SequenceEqual(utf16), "fichier UTF-16 (PowerShell 5) conservé");

        Console.WriteLine("Masquage");
        var patterns = Redactor.BytePatterns(Redactor.Variants([("t/P", "Winter2025!")]), allEncodings: false);
        var redactor = new StreamRedactor(patterns);
        using (var ms = new MemoryStream())
        {
            var input = Encoding.UTF8.GetBytes("avant Winter2025! milieu Winter2025%21 fin");
            for (var i = 0; i < input.Length; i += 3)
            {
                var chunk = input[i..Math.Min(i + 3, input.Length)];
                redactor.Process(chunk, chunk.Length, ms, final: false);
            }
            redactor.Process([], 0, ms, final: true);
            var text = Encoding.UTF8.GetString(ms.ToArray());
            Check(text == "avant [secret:t/P] milieu [secret:t/P] fin", "flux coupé en morceaux de 3 octets, forme encodée URL comprise");
        }
        var strong = Redactor.Variants([("t/S", "S3cr3t!x9")]);
        Check(Redactor.Redact("un S3cr3t!x9 ici", strong) == "un " + Redactor.Mask("t/S") + " ici", "valeur forte : masquée partout");
        var weak = Redactor.Variants([("p/RABBITMQ_DEFAULT_PASS", "guest")]);
        Check(Redactor.Redact("connecté en guest", weak) == "connecté en guest", "valeur faible : mot courant laissé tel quel");
        Check(Redactor.Redact("RABBITMQ_DEFAULT_PASS=guest", weak) == "RABBITMQ_DEFAULT_PASS=" + Redactor.Mask("p/RABBITMQ_DEFAULT_PASS"),
              "valeur faible : masquée à côté de son nom");
        Check(Classifier.IsWeakSecret("secret") && Classifier.IsWeakSecret("admin123") && !Classifier.IsWeakSecret("Winter2025!")
              && !Classifier.IsWeakSecret("4f1c2b7e-9a3d-4e5f-8b6a-1c2d3e4f5a6b"), "repérage des valeurs faibles");

        Console.WriteLine("Détection dans un message");
        Check(Classifier.ScanText("le mot de passe est Winter2025!").Count > 0, "mot de passe dans une phrase");
        Check(Classifier.ScanText("le mot de passe est dans le fichier .env").Count == 0, "phrase sans valeur");
        Check(Classifier.ScanText("utilise secret://monprojet/DB_PASSWORD pour ça").Count == 0, "référence secret://");
        Check(Classifier.ScanText("voir profils/evolink/temoins/jeton-confirmation.yaml et token.service.ts").Count == 0,
              "libellé collé à un nom de fichier");
        Check(Classifier.ScanText("token->Xk9mQ2vL7pR4wZ8n").Count > 0 && Classifier.ScanText("jeton : Xk9mQ2vL7pR4wZ8n").Count > 0,
              "libellé suivi d'un séparateur");
        Check(!Hooks.BlockedDuringDisplay("mcp__Claude_Browser__computer", "screenshot", true)
              && !Hooks.BlockedDuringDisplay("mcp__claude-in-chrome__computer", "left_click", true),
              "navigateur non bloqué pendant secret show");
        Check(Hooks.BlockedDuringDisplay("mcp__computer-use__computer", "screenshot", true)
              && !Hooks.BlockedDuringDisplay("mcp__computer-use__computer", "screenshot", false),
              "capture du bureau bloquée seulement fenêtre ouverte");
        var now = DateTime.UtcNow;
        var start = now.AddMinutes(-1);
        var opened = new System.Text.Json.Nodes.JsonObject { ["pid"] = 42, ["started"] = start, ["opened"] = start };
        Check(DisplayGuard.Evaluate(opened, start, now, _ => start).Open, "fenêtre secret show ouverte");
        Check(!DisplayGuard.Evaluate(opened, start, now, _ => now.AddSeconds(-30)).Open, "numéro de processus recyclé");
        var old = now.AddHours(-2);
        Check(DisplayGuard.Evaluate(new() { ["pid"] = 42, ["opened"] = old }, old, now, _ => old) == (false, false),
              "fenêtre ouverte trop ancienne ignorée");
        Check(Hooks.IsAutomatedPrompt("<task-notification>\n<task-id>x</task-id>") && !Hooks.IsAutomatedPrompt("mon jeton est Winter2025!"),
              "notification automatique reconnue");
        Check(Classifier.ScanText("1Password : utilisé par beaucoup d'équipes").Count == 0
              && Classifier.ScanText("Secrets: rien de neuf").Count == 0, "phrase « Nom : texte » sans secret");
        Check(Classifier.ScanText("db_password: hunter22").Count > 0
              && Classifier.ScanText("PASSWORD : Winter2025!").Count > 0, "ligne clé: valeur collée");
        Check(Classifier.ScanText("-----BEGIN OPENSSH PRIVATE KEY-----\nabc").Count > 0, "clé privée collée");
        Check(Classifier.ScanText("mon token ghp_" + new string('a', 36)).Count > 0, "jeton GitHub");
        Check(Classifier.ScanText("le commit 3f2a9c8e1b7d6f5a4c3b2a1908f7e6d5c4b3a291 casse le build").Count == 0, "empreinte de commit");
        Check(Classifier.ScanText("crée .env.local avec SMTP_PASSWORD=Tq3$wE8!nB").Count > 0, "ligne de .env collée (CLÉ=valeur)");
        Check(Classifier.ScanText("voici mon .env :\nDB_HOST=db.local\nDB_PASSWORD=Xk9#mP2vL!q").Count > 0, "bloc .env collé");
        Check(Classifier.ScanText("{\"user\": \"admin\", \"password\": \"Winter2025!\"}").Count > 0, "JSON collé");
        Check(Classifier.ScanText("const apiKey = process.env.API_KEY;").Count == 0, "code qui lit une variable");
        Check(Classifier.ScanText("mets API_TOKEN=${API_TOKEN} dans le compose").Count == 0, "interpolation ${...}");
        Check(Classifier.ScanText("dans l'exemple, PASSWORD=changeme suffit").Count == 0, "valeur d'exemple");
        Check(Classifier.ScanText("passe DEBUG=true et PORT=8080, url: https://app.client.ch").Count == 0, "réglages sans secret");
        Check(Classifier.ScanText("Erreur: ECONNREFUSED sur 10.0.0.5:5432").Count == 0, "message d'erreur");

        Console.WriteLine("Masquage générique des sorties");
        string M(string s, params string[] never) => OutputMasker.Mask(s, never, new HashSet<string>());
        Check(M("DB_HOST=db\nREMOTE_PASSWORD=Zr4!pLm8#q\nAPI_URL=https://api.client.ch\n") ==
              "DB_HOST=db\nREMOTE_PASSWORD=[masqué:REMOTE_PASSWORD]\nAPI_URL=https://api.client.ch\n", ".env distant : seul le mot de passe est masqué");
        var inspect = M("\"Env\": [\n  \"POSTGRES_USER=appuser\",\n  \"POSTGRES_PASSWORD=Zr4!pLm8#q\",\n  \"PATH=/usr/local/bin:/usr/bin\"\n]");
        Check(inspect.Contains("\"POSTGRES_PASSWORD=[masqué:POSTGRES_PASSWORD]\"") && inspect.Contains("POSTGRES_USER=appuser") && inspect.Contains("PATH=/usr/local/bin:/usr/bin"),
              "docker inspect (liste Env)");
        var yaml = M("services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: Zr4!pLm8#q\n      TZ: Europe/Zurich\n");
        Check(yaml.Contains("POSTGRES_PASSWORD: [masqué:POSTGRES_PASSWORD]") && yaml.Contains("image: postgres:16") && yaml.Contains("TZ: Europe/Zurich"),
              "docker compose config (YAML)");
        Check(M("{\"access_token\":\"a8F3kL9mN2pQ7rS4tU6vW\",\"expires_in\":3600,\"token_type\":\"Bearer\"}") ==
              "{\"access_token\":\"[masqué:access_token]\",\"expires_in\":3600,\"token_type\":\"Bearer\"}", "réponse d'API JSON");
        Check(M("connexion à postgres://app:Zr4!pLm8#q@db:5432/app") == "connexion à postgres://app:[masqué:MOT_DE_PASSE_URL]@db:5432/app", "URL avec mot de passe");
        Check(M("lancé avec --password=Zr4!pLm8#q --port=5432") == "lancé avec --password=[masqué:password] --port=5432", "option --password=");
        var table = M("Name                           Value\n----                           -----\nDB_PASSWORD                    Zr4!pLm8#q\nPath                           C:\\Windows\n");
        Check(table.Contains("DB_PASSWORD                    [masqué:DB_PASSWORD]") && table.Contains("C:\\Windows"), "Get-ChildItem env: (tableau)");
        Check(M("cat id_rsa\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\nfin") == "cat id_rsa\n[masqué:CLE_PRIVEE]\nfin", "clé privée");
        const string code = "const apiKey = process.env.API_KEY;\nif (password == null) return;";
        Check(M(code) == code, "code source sans valeur");
        const string refs = "password: ${DB_PASS}\nPASSWORD=changeme\nAPI_TOKEN=secret://p/API_TOKEN\nDB=[secret:p/DB_PASSWORD]";
        Check(M(refs) == refs, "variables, exemples, références et masques existants intacts");
        Check(M("BUILD_ID=a8F3kL9mN2pQ7rS4tU6vW") == "BUILD_ID=a8F3kL9mN2pQ7rS4tU6vW", "valeur aléatoire sous un nom anodin : visible");
        Check(M("API_TOKEN=a8F3kL9mN2pQ7rS4tU6vW") == "API_TOKEN=" + OutputMasker.Marker("API_TOKEN"), "même valeur sous un nom de secret : masquée");
        Check(M("API_TOKEN=a8F3kL9mN2pQ7rS4tU6vW", "API_TOKEN") == "API_TOKEN=a8F3kL9mN2pQ7rS4tU6vW", "clé autorisée jamais masquée");

        Console.WriteLine("Non-secrets courants : aucun masque attendu");
        string[] clean =
        [
            "{ \"matcher\": \"Read|Edit|MultiEdit|Write|NotebookEdit|Grep|Bash|PowerShell|mcp__.*\", \"type\": \"command\" }",
            "\"id\": \"4f1c2b7e-9a3d-4e5f-8b6a-1c2d3e4f5a6b\"",
            "\"sha\": \"3f2a9c8e1b7d6f5a4c3b2a1908f7e6d5c4b3a291\"",
            "\"integrity\": \"sha512-Q2hhbmdlTWVQbGVhc2UxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==\"",
            "\"data\": \"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQ\"",
            "{ \"key\": \"ctrl+shift+p\", \"command\": \"workbench.action.showCommands\" }",
            "\"key\": \"app.menu.settings.title\"",
            "\"tokenizer\": \"cl100k_base\"",
            "glob: src/**/*.{ts,tsx}",
            "pattern: ^(?:[a-z0-9]+(?:-[a-z0-9]+)*)$",
            "IMAGE_DIGEST=sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "// CLÉ=valeur sans espaces (.env, printenv, set, --password=...)",
        ];
        foreach (var c in clean) Check(M(c) == c, "intact : " + (c.Length > 70 ? c[..70] + "..." : c));
        Check(Classifier.ScanText("voici mon hooks.json : \"matcher\": \"Read|Edit|Grep|Bash|PowerShell|mcp__.*\"").Count == 0,
              "config JSON collée dans un message, sans secret : envoyée");

        Console.WriteLine("Vrais secrets : masque attendu");
        (string Text, string Key)[] dirty =
        [
            ("{\"auths\":{\"registry.example.com\":{\"auth\":\"dXNlcjpYazkjbVAydkwhcTEyMw==\"}}}", "auth"),
            ("\"license_key\": \"ABCD-1234-EFGH-5678\"", "license_key"),
            ("\"key\": \"a8F3kL9mN2pQ7rS4tU6vW\"", "key"),
            ("\"value\": \"ghp_" + new string('b', 36) + "\"", "JETON"),
            ("MYSQLPASSWORD=Admin2024", "MYSQLPASSWORD"),
            ("\"clientSecret\": \"Xk9#mP2vL!q\"", "clientSecret"),
            ("password: admin", "password"),
        ];
        foreach (var (text, key) in dirty) Check(M(text).Contains(OutputMasker.Marker(key)), $"masqué : {key}");

        Console.WriteLine("Format clé:valeur, variables système, tableaux");
        var colon = EnvFile.Parse(Encoding.UTF8.GetBytes("# vm\nssh_user:deploy\nssh_password:Zq8!rT4#pLm\nKEY=a:b\n"));
        var ck = colon.Assignments.ToDictionary(a => a.Key);
        Check(ck.ContainsKey("ssh_user") && ck["ssh_password"].Value == "Zq8!rT4#pLm" && ck["KEY"].Value == "a:b" && colon.UnrecognizedLines().Count == 0,
              ".env : lignes clé:valeur reconnues, CLÉ=a:b intact");
        Check(Classifier.Classify("ssh_password", ck["ssh_password"].Value, Annotation.None).Secret && !Classifier.Classify("ssh_user", "deploy", Annotation.None).Secret,
              ".env : ssh_password à chiffrer, ssh_user en clair");
        var colonOut = EnvFile.Parse(colon.Render(new Dictionary<EnvAssignment, string> { [ck["ssh_password"]] = "secret://vm/ssh_password" }, addHeader: false));
        Check(colonOut.Lines.Contains("ssh_password:secret://vm/ssh_password"), ".env : la référence garde le format clé:valeur");
        Check(EnvFile.Parse(Encoding.UTF8.GetBytes("A=1\nceci n'est pas une affectation\n")).UnrecognizedLines().SequenceEqual([1]), ".env : ligne non reconnue repérée");
        Check(M("ssh_user:deploy\nssh_password:Zq8!rT4#pLm\n") == "ssh_user:deploy\nssh_password:" + OutputMasker.Marker("ssh_password") + "\n", "sortie : clé:valeur sans espace masqué");
        const string sysenv = "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\nXDG_SESSION_ID=4\nINVOCATION_ID=7c1e4b2a9d3f4e5a8b6c1d2e3f4a5b6c\nSSH_CLIENT=10.40.41.5 52044 22\n";
        Check(M(sysenv) == sysenv, "variables système Linux (DBUS, XDG_SESSION_ID, INVOCATION_ID, SSH_CLIENT) : visibles");
        Check(M("XDG_SESSION_COOKIE=3f2a9c8e1b7d6f5a4c3b2a1908f7e6d5").Contains(OutputMasker.Marker("XDG_SESSION_COOKIE")), "cookie de session : masqué");
        const string humanTable = "ssh_password                 visible\ntoken_status                 expired\n";
        Check(M(humanTable) == humanTable, "tableau lisible, nom de secret suivi d'un mot ordinaire : visible");
        const string log = "commit 3f2a9c8e1b7d6f5a4c3b2a1908f7e6d5c4b3a291\nAuthor: Nico <n@x.ch>\nDate:   Wed Oct 15 10:12:03 2026 +0200\n\n    fix: corrige le build";
        Check(M(log) == log, "sortie git log intacte");

        Console.WriteLine("Garde-fous");
        Check(Guards.CheckForbidden("echo DB_PASSWORD=[masqué:DB_PASSWORD] > app.env") != null, "commande contenant un masque refusée");
        Check(Guards.CheckForbidden("secret config masking off --here") != null, "couper le masquage refusé pour Claude");
        Check(Guards.CheckForbidden("secret config masking on") == null, "rallumer le masquage autorisé");
        Check(Guards.CheckForbidden("secret reveal monprojet/DB") != null, "secret reveal refusé");
        Check(Guards.CheckForbidden("secret.exe undo .env") != null, "secret undo refusé");
        Check(Guards.CheckForbidden("[System.Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser')") != null, "appel DPAPI direct refusé");
        Check(Guards.CheckForbidden("secret run -- docker compose up -d") == null, "secret run autorisé");

        Console.WriteLine("0.1.4 : noms, interpolation, fichiers d'identifiants");
        (string Key, string Value, bool Secret)[] more =
        [
            ("DB_PASSWORT", "Xk9#mP2vL!q", true),
            ("MAIL_KENNWORT", "Winter2025!", true),
            ("API_SCHLUESSEL", "a8F3kL9mN2pQ7rS4tU6vW", true),
            ("CLE_API", "a8F3kL9mN2pQ7rS4tU6vW", true),
            ("DB_SEGRETO", "Zq8!rT4#pLm", true),
            ("GEHEIM_PFAD", "/opt/app/conf", false),
            ("DATABASE_URL", "postgres://${DB_USER}:${DB_PASS}@db:5432/app", false),
            ("REDIS_URL", "redis://:${REDIS_PASSWORD:-changeme}@redis:6379", false),
            ("API_TOKEN", "${API_TOKEN}", false),
            ("DB_PASSWORD", "$DB_PASSWORD", false),
            ("SMTP_URL", "smtp://mail:${SMTP_PASS}@x.ch?key=Zq8!rT4#pLm", true),
        ];
        foreach (var (key, value, secret) in more)
            Check(Classifier.Classify(key, value, Annotation.None).Secret == secret, $"{key}={value} -> {(secret ? "chiffré" : "en clair")}");
        var ini = M("[client]\nuser = app\npassword = Zq8!rT4#pLm\nhost = db.local\ntimeout = 30\n");
        Check(ini.Contains("password = " + OutputMasker.Marker("password")) && ini.Contains("user = app") && ini.Contains("host = db.local") && ini.Contains("timeout = 30"),
              "fichier INI avec espaces : seul le mot de passe est masqué");
        Check(M("db.local:5432:app:appuser:Zq8rT4pLmX9\n").Contains(OutputMasker.Marker("MOT_DE_PASSE_PGPASS")), ".pgpass : mot de passe masqué");
        Check(M("db.local:5432:*:appuser:*\n") == "db.local:5432:*:appuser:*\n", ".pgpass : joker laissé visible");
        Check(M("machine api.example.com\n  login bob\n  password Zq8rT4pLmX9\n").Contains(OutputMasker.Marker("MOT_DE_PASSE_NETRC")), ".netrc : mot de passe masqué");
        const string prose = "le password reset link a été envoyé\n";
        Check(M(prose) == prose, "phrase avec « password » hors .netrc : visible");
        var home = Path.Combine(Path.GetTempPath(), "x");
        Check(Paths.IsCredentialFileName(Path.Combine(home, ".pgpass")) && Paths.IsCredentialFileName(Path.Combine(home, ".aws", "credentials"))
              && Paths.IsCredentialFileName(Path.Combine(home, "_netrc")) && !Paths.IsCredentialFileName(Path.Combine(home, "docs", "credentials.md")),
              "fichiers d'identifiants reconnus (.pgpass, .netrc, .aws\\credentials)");

        Console.WriteLine("0.1.4 : commandes sûres pour Claude");
        Check(Guards.CheckForbidden("secret undo .env --dry-run") == null, "secret undo --dry-run autorisé");
        Check(Guards.CheckForbidden("secret unprotect --all --dry-run") == null, "secret unprotect --all --dry-run autorisé");
        Check(Guards.CheckForbidden("secret undo .env --dry-run; secret undo .env") != null, "dry-run suivi d'une vraie annulation : refusé");
        Check(Guards.IsSafeSecretCommand("secret status .env") && Guards.IsSafeSecretCommand("secret generate .env DB_PASSWORD"),
              "status et generate : commandes sûres");
        Check(!Guards.IsSafeSecretCommand("secret status .env; cat .env") && !Guards.IsSafeSecretCommand("secret status .env && type .env"),
              "commande sûre enchaînée à une lecture : pas sûre");

        Console.WriteLine("0.1.5 : clés qui commencent par un chiffre");
        var digit = EnvFile.Parse(Encoding.UTF8.GetBytes("3CX_HOST_SSH_USER=admin\n3CX_HOST_SSH_PASSWORD=Zq8!rT4#pLm\n10.0.0.60:22\n"));
        Check(digit.Assignments.Select(a => a.Key).SequenceEqual(["3CX_HOST_SSH_USER", "3CX_HOST_SSH_PASSWORD"]) && digit.UnrecognizedLines().SequenceEqual([2]),
              ".env : 3CX_...=valeur reconnu, « 10.0.0.60:22 » reste du texte");
        Check(Classifier.Classify("3CX_HOST_SSH_PASSWORD", "Zq8!rT4#pLm", Annotation.None).Secret && !Classifier.Classify("3CX_HOST_SSH_USER", "admin", Annotation.None).Secret,
              ".env : 3CX_HOST_SSH_PASSWORD à chiffrer, 3CX_HOST_SSH_USER en clair");
        Check(EnvFile.ParseReference("secret://lab/3CX_HOST_SSH_PASSWORD") == "lab/3CX_HOST_SSH_PASSWORD" && Vault.IsValidName("lab/3CX_HOST_SSH_PASSWORD"),
              "référence secret://lab/3CX_... valide");
        Check(M("3CX_HOST_SSH_PASSWORD=Zq8!rT4#pLm\n").Contains(OutputMasker.Marker("3CX_HOST_SSH_PASSWORD")), "sortie : 3CX_...=valeur masqué");
        Check(M("10.0.0.60:22\n") == "10.0.0.60:22\n", "sortie : adresse:port intacte");
        Check(Classifier.ScanText("3CX_HOST_SSH_PASSWORD=Zq8!rT4#pLm").Count > 0, "message : 3CX_...=valeur repéré");
        Check(Guards.CheckForbidden("echo [masqué:3CX_HOST_SSH_PASSWORD] > lab.env") != null, "commande contenant un masque 3CX_... refusée");

        Console.WriteLine("Périmètre des conversions");
        Check(EnvFile.HasIgnoreMarkerText("A=1\n# local-secrets: ignore\nB=2") && !EnvFile.HasIgnoreMarkerText(EnvFile.Header), "marqueur ignore reconnu, en-tête normal non");
        var scratch = Path.Combine(Path.GetTempPath(), "ls-selftest-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            Directory.CreateDirectory(Path.Combine(scratch, "projet", "sous-dossier"));
            Directory.CreateDirectory(Path.Combine(scratch, "autre", ".git"));
            Check(Paths.IsInProject(Path.Combine(scratch, "projet", "sous-dossier", ".env"), Path.Combine(scratch, "projet")), "fichier d'un sous-dossier du projet : dans le projet");
            Check(!Paths.IsInProject(Path.Combine(scratch, "autre", ".env"), scratch), "fichier d'un autre dépôt git sous la racine : hors du projet");
            Check(!Paths.IsInProject(Path.Combine(scratch, "voisin", ".env"), Path.Combine(scratch, "projet")), "fichier d'un dossier voisin : hors du projet");
        }
        finally
        {
            try { Directory.Delete(scratch, recursive: true); } catch { }
        }

        const string ownMessage = "local-secrets : coffre verrouillé, lance secret unlock\n# local-secrets: ignore\n";
        Check(M(ownMessage) == ownMessage, "messages de l'outil et marqueur ignore : jamais masqués");
        Check(Guards.CheckForbidden("secret show test/NOM --window") != null && Guards.CheckForbidden("secret show test/NOM") == null
              && Guards.CheckForbidden("/mnt/c/x/secret.exe wsl-key unwrap") != null,
              "secret show --window et secret.exe wsl-key refusés pour Claude ; secret show permis");

        Console.WriteLine("Couche plateforme");
        var platform = Platform.Current;
        if (OperatingSystem.IsWindows())
        {
            Check(Paths.Full("/c/tools/projet/.env", @"D:\ailleurs") == @"C:\tools\projet\.env", "chemin Git Bash /c/... ramené à C:\\...");
            Check(Paths.IsInProject(@"C:\TOOLS\Projet\sub\.env", @"C:\tools\projet"), "chemins comparés sans tenir compte de la casse");
            Check(platform.ResolveCommand(@"C:\x\outil.cmd", ["a b"]) is { Raw: { } raw } && raw.Contains("\"a b\""), "script .cmd lancé par cmd, arguments entre guillemets");
            Check(!Paths.Normalize(Path.GetTempPath()).Contains('~'), "noms courts 8.3 remplacés par les noms longs");
        }
        else if (OperatingSystem.IsLinux())
        {
            Check(Paths.Full("/c/tools/projet/.env", "/home") == "/c/tools/projet/.env", "chemin /c/... laissé tel quel");
            Check(!Paths.IsInProject("/TMP/Projet/sub/.env", "/tmp/projet"), "chemins comparés en tenant compte de la casse");
            Check(platform.FindExecutable("sh") is { } sh && sh.StartsWith('/'), "programme trouvé dans le PATH");
            var priv = Path.Combine(Path.GetTempPath(), "ls-selftest-" + Guid.NewGuid().ToString("N")[..8]);
            try
            {
                Paths.CreatePrivateDirectory(priv);
                var file = Path.Combine(priv, "f.json");
                Paths.WritePrivate(file, "{}");
                Check(File.GetUnixFileMode(priv) == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute)
                      && File.GetUnixFileMode(file) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "dossier en 700, fichier en 600");
            }
            finally
            {
                try { Directory.Delete(priv, recursive: true); } catch { }
            }
            Check(Guards.CheckForbidden("cat /proc/1234/environ") != null && Guards.CheckForbidden("ps eww") != null
                  && Guards.CheckForbidden("keyctl print 123") != null && Guards.CheckForbidden("ps -ef | grep app") == null
                  && Guards.CheckForbidden("ps aux") == null, "environnement d'un processus et trousseaux : refusés ; ps -ef et ps aux : permis");
        }

        var otherProtection = false;
        try { Vault.CheckProtection(new VaultData { Protection = platform.ProtectionId + "-autre" }); } catch (UserError) { otherProtection = true; }
        var legacyEmpty = true;
        try { Vault.CheckProtection(new VaultData()); } catch (UserError) { legacyEmpty = false; }
        Check(otherProtection && legacyEmpty, "coffre d'une autre protection refusé, coffre vide accepté");

        Console.WriteLine("Chiffrement");
        if (OperatingSystem.IsWindows())
        {
            var blob = platform.Protect([1, 2, 3], [9]);
            Check(platform.Unprotect(blob, [9]).SequenceEqual(new byte[] { 1, 2, 3 }), $"{platform.ProtectionName} aller-retour");
            var tampered = false;
            try { platform.Unprotect(blob, [8]); } catch { tampered = true; }
            Check(tampered, $"{platform.ProtectionName} refuse une autre entropie (blob déplacé sous un autre nom)");
        }
        {
            // ECIES : coffre Linux et pont WSL (les deux côtés). Clé de test générée ici.
            using var key = Ecies.NewKey();
            var blob = Ecies.Encrypt(Ecies.Point(key), [1, 2, 3], [9]);
            Check(Ecies.Decrypt(key, blob, [9]).SequenceEqual(new byte[] { 1, 2, 3 }), "ECIES P-256 aller-retour");
            Check(!Ecies.Encrypt(Ecies.Point(key), [1, 2, 3], [9]).SequenceEqual(blob), "ECIES : deux chiffrements de la même valeur diffèrent");
            var tampered = false;
            try { Ecies.Decrypt(key, blob, [8]); } catch { tampered = true; }
            Check(tampered, "ECIES refuse une autre entropie (blob déplacé sous un autre nom)");
            using var other = Ecies.NewKey();
            var stranger = false;
            try { Ecies.Decrypt(other, blob, [9]); } catch { stranger = true; }
            Check(stranger, "ECIES : une autre clé privée ne déchiffre pas");
        }
        if (OperatingSystem.IsLinux())
        {
            if (LinuxNative.KeyringAvailable(out var why))
            {
                var name = "local-secrets:selftest-" + Guid.NewGuid().ToString("N")[..8];
                LinuxNative.Store(name, [4, 5, 6], TimeSpan.FromSeconds(30));
                Check(LinuxNative.Read(name) is [4, 5, 6] && LinuxNative.Remaining(name) is { TotalSeconds: > 0 and <= 30 }, "trousseau noyau : rangement, relecture, durée");
                LinuxNative.Drop(name);
                Check(LinuxNative.Read(name) == null, "trousseau noyau : clé retirée");
            }
            else
            {
                Console.WriteLine($"  info   trousseau noyau indisponible ({why}) : tests ignorés");
            }
        }
        var payload = BackupCmd.EncryptPayload(Encoding.UTF8.GetBytes("{\"a\":1}"), "phrase de test assez longue");
        Check(Encoding.UTF8.GetString(BackupCmd.DecryptPayload(payload, "phrase de test assez longue")) == "{\"a\":1}", "sauvegarde : chiffrement et relecture");
        var wrong = false;
        try { BackupCmd.DecryptPayload(payload, "mauvaise phrase de passe"); } catch (UserError) { wrong = true; }
        Check(wrong, "sauvegarde : mauvaise phrase refusée");

        Console.WriteLine(failures == 0 ? "Tous les tests passent." : $"{failures} test(s) en échec.");
        return failures == 0 ? 0 : 1;
    }
}
