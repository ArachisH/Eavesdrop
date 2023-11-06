using System.Net;
using System.Text;

namespace Eavesdrop.CLI;

public class Program
{
    public static void Main()
    {
        /* Explicitly state whether to intercept HTTP traffic ONLY. (Default: false) */
        Eavesdropper.IsOnlyInterceptingHttp = false;

        /* Alternatively, we can replicate the 'IsOnlyInterceptingHTTP = true' flag by inserting a custom script into the top of the PAC file.
         * PAC Documentation: http://findproxyforurl.com/example-pac-file/ */
        //Eavesdropper.PACHeader = """
        //            if (url.substring(0, 5) == "https")
        //                return "DIRECT";
        //        """;

        Eavesdropper.RequestInterceptedAsync += Eavesdropper_RequestInterceptedAsync;
        Eavesdropper.ResponseInterceptedAsync += Eavesdropper_ResponseInterceptedAsync;

        /* Determines whether the provided hostnames below should be blacklisted, or whitelisted. (Default: false) */
        /* FALSE:   Blacklist Mode */
        /* TRUE:    Whitelist Mode */
        //Eavesdropper.IsProxyingTargets = true;
        Eavesdropper.Targets.Add("*google.com");

        /* Intercept requests to private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) */
        //Eavesdropper.IsProxyingPrivateNetworks = true;

        /* Alternatively, we can include domains that only exist on your private network. */
        //Eavesdropper.IntranetHosts.Add("*myLocalHost.domain");

        /* Setting this property to 'true' means to forward ALL requests to the provided 'Proxy' server. */
        //Eavesdropper.Proxy = new System.Net.WebProxy("http://10.10.10.10:80");
        //Eavesdropper.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials ?? new System.Net.NetworkCredential("username", "passw0rd!");
        //Eavesdropper.IsActingAsForwardingServer = true;

        /* Otherwise, to be able to decrypt HTTPS traffic, we need to install a self-signed certificate to the root store. */
        Eavesdropper.Certifier?.CreateTrustedRootCertificate();

        Eavesdropper.Initiate(12086);
        Console.WriteLine("Press any key to terminate the application at any time...");

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
            Console.WriteLine("    " + Encoding.UTF8.GetString(await e.Content.ReadAsByteArrayAsync().ConfigureAwait(false)));
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