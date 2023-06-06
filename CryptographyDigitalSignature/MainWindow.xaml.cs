using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;

namespace CryptographyDigitalSignature
{
    public partial class MainWindow : Window
    {
        private readonly string PublicKeyFilePath = "publickey.xml";
        private readonly string PrivateKeyFilePath = "privatekey.xml";
        private readonly string SignatureFilePath = "signature.rsa";

        private RSACryptoServiceProvider Rsa = new();

        public MainWindow()
        {
            InitializeComponent();
        }

        private void GenerateKeys_Click(object sender, RoutedEventArgs e)
        {
            Rsa = new();
            Log("Keys Generated");
        }

        private void SaveKeys_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                File.WriteAllText(PublicKeyFilePath, Rsa.ToXmlString(false));
                File.WriteAllText(PrivateKeyFilePath, Rsa.ToXmlString(true));
                Log("Keys have been saved");
            }
            catch (Exception exception)
            {
                Log("Error saving keys: " + exception.Message);
            }
        }

        private void LoadKeys_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (File.Exists(PrivateKeyFilePath) && File.Exists(PublicKeyFilePath))
                {
                    Rsa.FromXmlString(File.ReadAllText(PrivateKeyFilePath));
                }
                else
                {
                    Log("Keys not found");
                }
            }
            catch (Exception exception)
            {
                Log("Error loading keys: " + exception.Message);
            }
        }

        private void LoadPublicKey_Click(object obj, RoutedEventArgs e)
        {
            try
            {
                if (File.Exists(PublicKeyFilePath))
                {
                    Rsa.FromXmlString(File.ReadAllText(PublicKeyFilePath));
                    Log("Public key have been loaded");
                }
                else
                {
                    Log("Public key file does not exist");
                }
            }
            catch (Exception exception)
            {
                Log("Error loading public key: " + exception.Message);
            }
        }

        private void BrowseFileToSign_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                FileToSign.Text = openFileDialog.FileName;
                Log("Filepath to encryption has been set");
            }
        }
        private enum AlgorithmName : int
        {
            SHA256,
            MD5
        }
        private void SignFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var filePath = FileToSign.Text;
                if (!File.Exists(filePath))
                {
                    Log("File to sign does not exist");
                    return;
                }

                byte[] fileBytes = File.ReadAllBytes(filePath);
                byte[] hash;
                HashAlgorithmName hashAlgorithmName;

                var hashAlgorithm = HashAlgorithmSelect.SelectedIndex;

                if (hashAlgorithm == (int)AlgorithmName.SHA256)
                {
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    var sha256 = SHA256.Create();
                    hash = sha256.ComputeHash(fileBytes);
                }
                else
                {
                    hashAlgorithmName = HashAlgorithmName.MD5;
                    var md5 = MD5.Create();
                    hash = md5.ComputeHash(fileBytes);
                }

                byte[] signature = Rsa.SignHash(hash, hashAlgorithmName, RSASignaturePadding.Pkcs1);
                File.WriteAllBytes(SignatureFilePath, signature);
                Log("File has been signed and signature saved in: " + SignatureFilePath);
            }
            catch (Exception exception)
            {
                Log("Error signing file: " + exception.Message);
            }
        }

        private void VerifyFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var filePath = FileToSign.Text;
                if (!File.Exists(filePath))
                {
                    return;
                }
                byte[] fileBytes = File.ReadAllBytes(filePath);
                byte[] hash;
                HashAlgorithmName hashAlgorithmName;

                var hashAlgorithm = HashAlgorithmSelect.SelectedIndex;
                if (hashAlgorithm == (int)AlgorithmName.SHA256)
                {
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    var sha256 = SHA256.Create();
                    hash = sha256.ComputeHash(fileBytes);
                }
                else
                {
                    hashAlgorithmName = HashAlgorithmName.MD5;
                    var md5 = MD5.Create();
                    hash = md5.ComputeHash(fileBytes);
                }
                byte[] signature = File.ReadAllBytes(SignatureFilePath);
                var isVerified = Rsa.VerifyHash(hash, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1);
                if (isVerified)
                {
                    Log("Signature is valid");
                }
                else
                {
                    Log("Signature is invalid");
                }
            }
            catch (Exception exception)
            {
                Log("Error verifying file: " + exception.Message);
            }
        }

        private void Log(string message)
        {
            LogTextBox.AppendText($"${DateTime.Now}- {message}\n");
            LogTextBox.ScrollToEnd();
        }
    }
}
