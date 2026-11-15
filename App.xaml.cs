using System.IO;
using System.Windows;

namespace Breccia.WPF;

public partial class App : Application
{
    private void App_Startup(object sender, StartupEventArgs e)
    {
        var window = new MainWindow();
        window.Show();
        if (e.Args.Length > 0 && File.Exists(e.Args[0]))
            window.LoadFile(e.Args[0]);
    }
}
