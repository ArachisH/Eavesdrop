using System.Text;

namespace Eavesdrop.CLI;

public class Program
{
    public static void Main()
    {
        if (Eavesdropper.Certifier.CreateTrustedRootCertificate())
        {
            Eavesdropper.RequestInterceptedAsync += Eavesdropper_RequestInterceptedAsync;
            Eavesdropper.ResponseInterceptedAsync += Eavesdropper_ResponseInterceptedAsync;

            // Do NOT intercept Http(s) requests from the google domain.
            Eavesdropper.Targets.Add("*google.com");

            // OR ONLY intercept Http(s) from the given list of targets.
            //Eavesdropper.IsProxyingTargets = true;

            // Intercept requests to private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            //Eavesdropper.IsProxyingPrivateNetworks = true;

            // Alternatively, we can include domains that only exist on your private network.
            //Eavesdropper.IntranetHosts.Add("*myLocalHost.domain");

            Eavesdropper.Initiate(12086);
            Console.WriteLine("Press any key to terminate the application at any time...");
        }

        Console.ReadKey();
        Eavesdropper.Terminate();
    }

    private static async Task Eavesdropper_RequestInterceptedAsync(object sender, RequestInterceptedEventArgs e)
    {
        Console.WriteLine("----[ HTTP Request ]");
        Console.WriteLine($"    {e.Method} {e.Uri} {e.Version}");
        foreach (var item in e.Headers)
        {
            Console.WriteLine($"    {item.Key}: {string.Join(", ", item.Value)}");
        }
        if (e.Content != null)
        {
            Console.WriteLine("----[ HTTP Request Content ]");
            Console.WriteLine("    " + Encoding.UTF8.GetString(await e.Content.ReadAsByteArrayAsync()));
        }
    }
    private static Task Eavesdropper_ResponseInterceptedAsync(object sender, ResponseInterceptedEventArgs e)
    {
        Console.WriteLine("----[ HTTP Response ]");
        Console.WriteLine($"    {e.Uri} {e.Version}");
        foreach (var item in e.Headers)
        {
            Console.WriteLine($"    {item.Key}: {string.Join("; ", item.Value)}");
        }
        return Task.CompletedTask;
    }
}