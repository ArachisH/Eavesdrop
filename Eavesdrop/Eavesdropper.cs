using System.Net;
using System.Text;
using System.Net.Sockets;

using Eavesdrop.Network;

namespace Eavesdrop;

public static class Eavesdropper
{
    private static readonly object _stateLock;
    private static readonly HttpClient _httpClient;
    private static readonly HttpClientHandler _httpClientHandler;

    private static Socket? _listener;

    public delegate Task AsyncEventHandler<TEventArgs>(object? sender, TEventArgs e);

    public static event AsyncEventHandler<RequestInterceptedEventArgs>? RequestInterceptedAsync;
    private static async Task OnRequestInterceptedAsync(RequestInterceptedEventArgs e, CancellationToken cancellationToken)
    {
        e.Cancel = cancellationToken.IsCancellationRequested;

        Task? interceptedTask = RequestInterceptedAsync?.Invoke(null, e);
        if (interceptedTask != null)
        {
            await interceptedTask.WaitAsync(cancellationToken);
        }
    }

    public static event AsyncEventHandler<ResponseInterceptedEventArgs>? ResponseInterceptedAsync;
    private static async Task OnResponseInterceptedAsync(ResponseInterceptedEventArgs e, CancellationToken cancellationToken)
    {
        e.Cancel = cancellationToken.IsCancellationRequested;

        Task? interceptedTask = ResponseInterceptedAsync?.Invoke(null, e);
        if (interceptedTask != null)
        {
            await interceptedTask.WaitAsync(cancellationToken);
        }
    }

    public static Certifier Certifier { get; set; }

    public static int ActivePort { get; private set; }
    public static bool IsRunning { get; private set; }
    public static List<string> Targets { get; private set; }
    public static List<string> IntranetHosts { get; private set; }

    public static bool IsProxyingTargets { get; set; }
    public static bool IsProxyingPrivateNetworks { get; set; }

    static Eavesdropper()
    {
        _stateLock = new object();
        _httpClientHandler = new HttpClientHandler { UseProxy = false };
        _httpClient = new HttpClient(_httpClientHandler);

        _httpClientHandler.AllowAutoRedirect = false;
        _httpClientHandler.CheckCertificateRevocationList = false;
        _httpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        Targets = new List<string>();
        IntranetHosts = new List<string>();
        Certifier = new Certifier("Eavesdrop", "Eavesdrop Root Certificate Authority");
    }

    public static void Terminate()
    {
        lock (_stateLock)
        {
            INETOptions.Save(null);
            IsRunning = false;

            _listener?.Close();
            _listener = null;
        }
    }
    public static void Initiate(int port)
    {
        lock (_stateLock)
        {
            _listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
            _listener.Bind(new IPEndPoint(IPAddress.Any, port));
            _listener.Listen();

            IsRunning = true;
            ActivePort = port;

            Task.Factory.StartNew(InterceptRequestAsync, TaskCreationOptions.LongRunning);
            INETOptions.Save($"http://127.0.0.1:{ActivePort}/proxy_{ActivePort}.pac/");
        }
    }

    private static string GeneratePAC()
    {
        var pacBuilder = new StringBuilder();

        pacBuilder.AppendLine("function FindProxyForURL (url, host)");
        pacBuilder.AppendLine("{");

        pacBuilder.AppendLine("    host = host.toLowerCase();");
        pacBuilder.AppendLine();
        pacBuilder.AppendLine("    var hostIP;");
        pacBuilder.AppendLine("    var isIpV4Addr = /^(\\d+.){3}\\d+$/;");
        pacBuilder.AppendLine("    if (isIpV4Addr.test(host))");
        pacBuilder.AppendLine("        hostIP = host;");
        pacBuilder.AppendLine("    else");
        pacBuilder.AppendLine("        hostIP = 0;");

        if (!IsProxyingPrivateNetworks)
        {
            pacBuilder.Append("""

                    if (isPlainHostName(host) || shExpMatch(host, "*.local") ||
                        shExpMatch(hostIP, "10.*") ||
                        shExpMatch(hostIP, "172.16.*") ||
                        shExpMatch(hostIP, "192.168.*")
                """);

            if (IntranetHosts.Count > 0)
            {
                for (int i = 0; i < IntranetHosts.Count; i++)
                {
                    pacBuilder.Append($$"""
                         ||
                                shExpMatch(host, "{{IntranetHosts[i]}}")
                        """);
                }
            }

            pacBuilder.Append("""
                ) return "DIRECT";


                """);
        }

        if (Targets.Count > 0)
        {
            pacBuilder.Append($"    if (shExpMatch(host, \"{Targets[0]}\")");
            for (int i = 1; i < Targets.Count; i++)
            {
                pacBuilder.AppendLine(" ||");
                pacBuilder.Append($"        shExpMatch(host, \"{Targets[i]}\")");
            }
            pacBuilder.AppendLine($") return \"{(IsProxyingTargets ? $"PROXY 127.0.0.1:{ActivePort}; " : null)}DIRECT\";");
            pacBuilder.AppendLine();
        }

        pacBuilder.AppendLine($"    return \"{(!IsProxyingTargets ? $"PROXY 127.0.0.1:{ActivePort}; " : null)}DIRECT\";");
        pacBuilder.Append('}');

        return pacBuilder.ToString();
    }
    private static async Task InterceptRequestAsync()
    {
        try
        {
            while (IsRunning && _listener != null)
            {
                Socket client = await _listener.AcceptAsync().ConfigureAwait(false);
                _ = HandleSocketAsync(client);
            }
        }
        catch { if (IsRunning) Terminate(); }
    }
    private static async Task HandleSocketAsync(Socket client, CancellationToken cancellationToken = default)
    {
        using var local = new EavesNode(client, Certifier);

        HttpResponseMessage? response = null;
        HttpContent? originalResponseContent = null;

        HttpRequestMessage request = await local.ReceiveHttpRequestAsync(cancellationToken).ConfigureAwait(false);
        HttpContent? originalRequestContent = request.Content;
        try
        {
            if (request.Headers.Host == $"127.0.0.1:{ActivePort}" &&
                request.RequestUri?.OriginalString == $"/proxy_{ActivePort}.pac/")
            {
                response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(GeneratePAC(), Encoding.ASCII, "application/x-ns-proxy-autoconfig")
                };
            }
            else
            {
                var requestArgs = new RequestInterceptedEventArgs(request);
                await OnRequestInterceptedAsync(requestArgs, cancellationToken).ConfigureAwait(false);
                if (requestArgs.Cancel || cancellationToken.IsCancellationRequested) return;

                response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                originalResponseContent = response.Content;

                var responseArgs = new ResponseInterceptedEventArgs(response);
                await OnResponseInterceptedAsync(responseArgs, cancellationToken).ConfigureAwait(false);
                if (responseArgs.Cancel || cancellationToken.IsCancellationRequested) return;
            }
            await local.SendHttpResponseAsync(response, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            request.Dispose();
            originalRequestContent?.Dispose();

            response?.Dispose();
            originalResponseContent?.Dispose();
        }
    }
}