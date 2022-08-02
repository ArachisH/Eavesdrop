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

            Eavesdropper.Initiate(12086, Interceptors.Default);
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