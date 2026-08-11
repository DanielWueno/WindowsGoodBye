using System.Text;
using System.Windows;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.TrayApp;

/// <summary>
/// Replaces the old WinForms "Set Windows Credentials" dialog. Writing directly to a local
/// <see cref="AppDatabase"/> is unchanged (and safe here, unlike device delete/enable) — the Service
/// always reads <c>Credentials</c> through a fresh, short-lived <see cref="AppDatabase"/>
/// (see <c>AuthWorker</c>'s <c>freshDb.Credentials.FirstOrDefault()</c>), so there's no
/// identity-map staleness gap for this table.
/// </summary>
public partial class CredentialsWindow : Window
{
    public CredentialsWindow()
    {
        InitializeComponent();
        txtDomain.Text = Environment.UserDomainName;
        txtUsername.Text = Environment.UserName;
    }

    private void OnSaveClicked(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(txtUsername.Text) || string.IsNullOrEmpty(txtPassword.Password))
        {
            System.Windows.MessageBox.Show(this, "El usuario y la contrasena son obligatorios.", "WindowsGoodBye",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        try
        {
            var encryptedPassword = CryptoUtils.ProtectData(Encoding.UTF8.GetBytes(txtPassword.Password));

            using var db = new AppDatabase();
            db.Initialize();

            var existing = db.Credentials.ToList();
            db.Credentials.RemoveRange(existing);

            db.Credentials.Add(new StoredCredential
            {
                Username = txtUsername.Text,
                Domain = txtDomain.Text,
                EncryptedPassword = encryptedPassword,
                UpdatedAt = DateTime.UtcNow
            });
            db.SaveChanges();

            txtPassword.Clear();

            System.Windows.MessageBox.Show(this,
                "Credenciales guardadas correctamente.\n\n" +
                "El Credential Provider las usara para desbloquear tu PC cuando tu telefono autentique.",
                "WindowsGoodBye", MessageBoxButton.OK, MessageBoxImage.Information);
            Close();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, $"No se pudieron guardar las credenciales: {ex.Message}",
                "WindowsGoodBye", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
