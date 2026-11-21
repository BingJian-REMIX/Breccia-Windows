using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Breccia.WPF;

public partial class App : Application
{
    private void App_Startup(object sender, StartupEventArgs e)
    {
        // A debugger UI must survive a bad snapshot: log instead of vanishing mid-session.
        DispatcherUnhandledException += (_, args) =>
        {
            LogCrash(args.Exception);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) => LogCrash(args.ExceptionObject as Exception);

        var window = new MainWindow();
        window.Show();
        if (e.Args.Length > 0 && File.Exists(e.Args[0]))
            window.LoadFile(e.Args[0]);
    }

    private static void LogCrash(Exception? ex)
    {
        try
        {
            var path = Path.Combine(Path.GetTempPath(), "breccia-crash.log");
            File.AppendAllText(path,
                $"[{DateTime.Now:O}] {ex?.GetType().FullName}: {ex?.Message}{Environment.NewLine}{ex?.StackTrace}{Environment.NewLine}");
        }
        catch { /* nothing sensible left to do */ }
    }
}
