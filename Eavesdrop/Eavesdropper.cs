using System.Net;
using System.Text;
using System.Buffers;
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

    public static Certifier? Certifier { get; set; }
    public static Certifier DefaultCertifier { get; }

    public static string? PACHeader { get; set; }
    public static int ActivePort { get; private set; }
    public static bool IsRunning { get; private set; }
    public static List<string> Targets { get; private set; }
    public static List<string> IntranetHosts { get; private set; }

    public static bool IsProxyingTargets { get; set; }
    public static bool IsOnlyInterceptingHTTP { get; set; }
    public static bool IsProxyingPrivateNetworks { get; set; }
    public static bool IsActingAsForwardingServer { get; set; }

    public static IWebProxy? Proxy
    {
        get => _httpClientHandler.Proxy;
        set => _httpClientHandler.Proxy = value;
    }

    static Eavesdropper()
    {
        _stateLock = new object();
        _httpClientHandler = new HttpClientHandler
        {
            UseProxy = false, // The proxying of requests will be handled manually to be able to avoid any data interception.
            AllowAutoRedirect = false,
            CheckCertificateRevocationList = false,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        _httpClient = new HttpClient(_httpClientHandler);

        Targets = new List<string>();
        IntranetHosts = new List<string>();
        Certifier = DefaultCertifier = new Certifier("Eavesdrop", "Eavesdrop Root Certificate Authority");
    }

    public static void Terminate()
    {
        lock (_stateLock)
        {
            INETOptions.Save(null);
            IsRunning = false;

            _listener?.Close();
            _listener = null;

            _httpClient.CancelPendingRequests();
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

        if (!string.IsNullOrWhiteSpace(PACHeader))
        {
            pacBuilder.AppendLine("\r\n// <-------- HEADER START -------->");
            pacBuilder.Append(PACHeader);
            pacBuilder.AppendLine("\r\n// <-------- HEADER END ---------->");
        }

        if (IsOnlyInterceptingHTTP)
        {
            pacBuilder.Append("""

                    if (url.substring(0, 5) == "https")
                        return "DIRECT";

                """);
        }

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
        using var local = new EavesNode(client, Certifier, IsActingAsForwardingServer);

        RequestInterceptedEventArgs? requestArgs = null;
        ResponseInterceptedEventArgs? responseArgs = null;

        // Keep track of the originally created request/response objects, as they still need to be disposed of at the end of the method if they were to be replaced with another instance.
        HttpRequestMessage? ogRequest = null;
        HttpResponseMessage? ogResponse = null;
        HttpContent? originalResponseContent = null, originalRequestContent = null;

        bool wasProxiedExternally = false;
        try
        {
            ogRequest = await local.ReceiveHttpRequestAsync(cancellationToken).ConfigureAwait(false);
            originalRequestContent = ogRequest.Content;

            if (ogRequest.Headers.Host == $"127.0.0.1:{ActivePort}" && ogRequest.RequestUri?.OriginalString == $"/proxy_{ActivePort}.pac/")
            {
                ogResponse = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(GeneratePAC(), Encoding.ASCII, "application/x-ns-proxy-autoconfig")
                };
            }
            else
            {
                if (ogRequest.Method == HttpMethod.Connect && Proxy != null && ogRequest.RequestUri != null)
                {
                    string? encodedCredentials = null;
                    if (Proxy.Credentials != null)
                    {
                        NetworkCredential? credentials = Proxy.Credentials.GetCredential(ogRequest.RequestUri, "Basic");
                        if (credentials == null)
                        {
                            throw new Exception("Failed to acquire credentials for the given request target.");
                        }

                        encodedCredentials = $"{credentials.UserName}:{credentials.Password}";
                        encodedCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(encodedCredentials));
                        ogRequest.Headers.TryAddWithoutValidation("Proxy-Authorization", $"Basic {encodedCredentials}");
                    }

                    wasProxiedExternally = true;
                    ogRequest.RequestUri = Proxy.GetProxy(ogRequest.RequestUri);
                }

                requestArgs = new RequestInterceptedEventArgs(ogRequest);
                await OnRequestInterceptedAsync(requestArgs, cancellationToken).ConfigureAwait(false);
                if (requestArgs.Cancel || cancellationToken.IsCancellationRequested) return;

                ogResponse = requestArgs.Response ??
                    await _httpClient.SendAsync(requestArgs.Request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

                // This flag is meant to de-clutter the interception pipeline, in the case that a request has already been provided a response we're aware of.
                // Also, check if the async event itself has any subscribers.
                if (requestArgs.IsInterceptingResponse && ResponseInterceptedAsync != null)
                {
                    originalResponseContent = ogResponse.Content; // Store it so we can dispose of it if the user decides to replace the content.

                    responseArgs = new ResponseInterceptedEventArgs(ogResponse);
                    await OnResponseInterceptedAsync(responseArgs, cancellationToken).ConfigureAwait(false);

                    if (responseArgs.Cancel || cancellationToken.IsCancellationRequested) return;
                }
            }

            HttpResponseMessage response = responseArgs?.Response ?? ogResponse;
            await local.SendHttpResponseAsync(response, cancellationToken).ConfigureAwait(false);
            if (wasProxiedExternally)
            {
                using Stream remoteStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

                Task remoteToLocalClampTask = ClampStreamsAsync(remoteStream, local.Stream);
                Task localToRemoteClampTask = ClampStreamsAsync(local.Stream, remoteStream);

                // Wait for any of the two streams to exhaust themselves, which should typically indicate that the request/response exchange was completed.
                await Task.WhenAny(remoteToLocalClampTask, localToRemoteClampTask).ConfigureAwait(false);
            }
        }
        finally
        {
            ogRequest?.Dispose();
            requestArgs?.Request?.Dispose();
            originalRequestContent?.Dispose();

            ogResponse?.Dispose();
            responseArgs?.Response?.Dispose();
            originalResponseContent?.Dispose();
        }
    }

    private static async Task ClampStreamsAsync(Stream fromStream, Stream toStream)
    {
        // Immediately return to the previous context.
        await Task.Yield();

        using IMemoryOwner<byte> bufferOwner = MemoryPool<byte>.Shared.Rent(1024);
        Memory<byte> buffer = bufferOwner.Memory;

        int bytesRead = 0;
        while (fromStream.CanRead && toStream.CanWrite)
        {
            bytesRead = await fromStream.ReadAsync(buffer).ConfigureAwait(false);
            await toStream.WriteAsync(buffer.Slice(0, bytesRead)).ConfigureAwait(false);
            await toStream.FlushAsync().ConfigureAwait(false);
        }
    }
}