using System;
using System.Threading.Tasks;

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
            Eavesdropper.Certifier.CreateTrustedRootCertificate();

            Eavesdropper.Initiate(8282);
            Console.Title = $"Eavesdrop.Sandbox({8282}) - Press any key to exit...";

            Console.ReadLine();
            Eavesdropper.Terminate();
            Console.WriteLine("Eavesdropper has been terminated! | " + DateTime.Now);
        }

        private Task RequestInterceptedAsync(object sender, RequestInterceptedEventArgs e)
        {
            Console.WriteLine("Intercepted Request: " + e.Uri);
            return null;
        }
        private Task ResponseInterceptedAsync(object sender, ResponseInterceptedEventArgs e)
        {
            Console.WriteLine($"Intercepted Response: " + e.Uri);
            return null;
        }
    }
}