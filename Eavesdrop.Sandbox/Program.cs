using System;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Eavesdrop.Sandbox
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var app = new Program();
            app.Run();
        }

        private void Run()
        {
            Eavesdropper.RequestInterceptedAsync += RequestInterceptedAsync;
            Eavesdropper.ResponseInterceptedAsync += ResponseInterceptedAsync;

            //Eavesdropper.Certifier.DestroyCertificates();
            bool installedCertificateAuthority = Eavesdropper.Certifier.CreateTrustedRootCertificate();

            var interceptors = Interceptors.HTTP;
            if (installedCertificateAuthority)
            {
                interceptors |= Interceptors.HTTPS;
                Eavesdropper.Certifier.ExportTrustedRootCertificate(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "//EavesdropCA.cer");
            }

            Eavesdropper.Initiate(8282);
            Console.Title = $"{RuntimeInformation.OSDescription} | Eavesdrop.Sandbox({8282} | [{interceptors}]) - Press any key to exit...";

            Console.ReadLine();
            Eavesdropper.Terminate();
            Console.WriteLine("Eavesdropper has been terminated! | " + DateTime.Now);
        }

        private Task RequestInterceptedAsync(object sender, RequestInterceptedEventArgs e)
        {
            Console.WriteLine("Intercepted Request: " + e.Uri);
            return Task.CompletedTask;
        }
        private async Task ResponseInterceptedAsync(object sender, ResponseInterceptedEventArgs e)
        {
            var payload = new byte[0];
            if (e.Content != null)
            {
                payload = await e.Content.ReadAsByteArrayAsync();
            }
            Console.WriteLine($"Intercepted Response: {e.Uri}[{payload.Length:n0} Bytes]");
        }
    }
}