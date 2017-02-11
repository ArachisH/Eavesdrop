using System;

namespace Eavesdrop.Example
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "Eavesdrop.Example ~ Press any key to exit...";

            Eavesdropper.RequestIntercepted += RequestIntercepted;
            Eavesdropper.ResponseIntercepted += ResponseIntercepted;

            // Eavesdropper.RemoteProxy = new WebProxy(":");
            Eavesdropper.Certifier.DestroySignedCertificates();
            Eavesdropper.Certifier.CreateTrustedRootCertificate();
            Eavesdropper.Initiate(8181);

            Console.Read();
            Console.WriteLine("Terminating...");
            Eavesdropper.Terminate();
        }

        private static void RequestIntercepted(object sender, RequestInterceptedEventArgs e)
        {
            Console.Write("Intercepted Request: ");
            Console.WriteLine(e.Request.RequestUri);
        }
        private static void ResponseIntercepted(object sender, ResponseInterceptedEventArgs e)
        {
            Console.Write("Intercepted Response: ");
            Console.WriteLine($"{e.Response.ResponseUri}[{e.Payload.Length:n0} Bytes]");
        }
    }
}