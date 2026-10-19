namespace LocalSecrets;

static class Program
{
    static int Main(string[] args)
    {
        Ui.Init();

        // Mode SSH_ASKPASS : pendant un « secret run --ssh-pass », ssh relance secret.exe
        // avec le texte de sa question en argument.
        var askpass = Environment.GetEnvironmentVariable(Runner.AskpassEnv);
        if (!string.IsNullOrEmpty(askpass) && (args.Length == 0 || !Commands.IsKnown(args[0])))
            return Runner.Askpass(askpass, args);

        // Les anciens coffres (AppData, copie privée de Claude Desktop) sont fusionnés dès qu'ils changent.
        if (args.Length == 0 || !args[0].Equals("migrate", StringComparison.OrdinalIgnoreCase))
        {
            try { Legacy.EnsureMerged(); }
            catch (Exception e) { Log.Write("fusion des anciens coffres impossible : " + e.Message); }
        }

        try
        {
            return Commands.Dispatch(args);
        }
        catch (UserError e)
        {
            Ui.Error(e.Message);
            return 2;
        }
        catch (Exception e)
        {
            Log.Write($"erreur {e.GetType().Name} : {e.Message}");
            Ui.Error("erreur inattendue : " + e.Message);
            return 1;
        }
    }
}
