namespace Eavesdrop.CLI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (Eavesdropper.Certifier.CreateTrustedRootCertificate())
            {
                Eavesdropper.RequestInterceptedAsync += Eavesdropper_RequestInterceptedAsync;
                Eavesdropper.ResponseInterceptedAsync += Eavesdropper_ResponseInterceptedAsync;

                Eavesdropper.Initiate(8686, Interceptors.Default);
                Console.WriteLine("Press any key to terminate the application at any time...");
            }

            Console.ReadKey();
            Eavesdropper.Terminate();
        }

        private static Task Eavesdropper_RequestInterceptedAsync(object sender, RequestInterceptedEventArgs e)
        {
            Console.WriteLine("Requesting: " + e.Uri);
            return Task.CompletedTask;
        }
        private static Task Eavesdropper_ResponseInterceptedAsync(object sender, ResponseInterceptedEventArgs e)
        {
            return Task.CompletedTask;
        }
    }
}