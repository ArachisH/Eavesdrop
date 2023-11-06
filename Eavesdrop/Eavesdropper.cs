using System.Net;
using System.Text;
using System.Buffers;
using System.Net.Sockets;

using Eavesdrop.Network;

namespace Eavesdrop;

public static class Eavesdropper
{
    private static readonly object _stateLock;
    private static readonly HttpClient _client;
    private static readonly HttpClientHandler _handler;
    private static readonly SelfBypassWebProxy _selfBypassProxy;

    private static string? _pathPAC;
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

    private static IWebProxy? _proxy;
    public static IWebProxy? Proxy
    {
        get => _proxy;
        set
        {
            _proxy = value;

            // Only proxy if we're not using the default system proxy, since that would cause recursive requests to this server.
            if (value != null)
            {
                _selfBypassProxy.Proxy = value;

                _handler.Proxy = _selfBypassProxy;
                _handler.UseProxy = true;
            }
            else // There may(big MAY) be a race condition here, so disable the proxy gracefully to reduce possibility of recursive interception.
            {
                // Proxy destination is required for this mode to be active.
                _isActingAsForwardingServer = false;

                _handler.UseProxy = false;
                _handler.Proxy = null;
            }
        }
    }

    public static Certifier? Certifier { get; set; }
    public static Certifier DefaultCertifier { get; }

    public static List<string> Targets { get; }
    public static List<string> IntranetHosts { get; }

    public static string? PACHeader { get; set; }
    public static int ActivePort { get; private set; }
    public static bool IsRunning { get; private set; }

    public static bool IsProxyingTargets { get; set; }
    public static bool IsOnlyInterceptingHttp { get; set; }
    public static bool IsProxyingPrivateNetworks { get; set; }

    private static bool _isActingAsForwardingServer;
    public static bool IsActingAsForwardingServer
    {
        get => _isActingAsForwardingServer;
        set
        {
            if (value && Proxy == null)
            {
                throw new Exception($"Unable to act as a forwarding server without a destination. {nameof(Proxy)} = null");
            }
            _isActingAsForwardingServer = value;
        }
    }

    static Eavesdropper()
    {
        _stateLock = new object();
        _selfBypassProxy = new SelfBypassWebProxy();

        _client = new HttpClient(_handler = new HttpClientHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            CheckCertificateRevocationList = false,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        });

        Targets = new List<string>();
        IntranetHosts = new List<string>();
        Certifier = DefaultCertifier = new Certifier("Eavesdrop", "Eavesdrop Root Certificate Authority");
    }

    public static void Terminate()
    {
        lock (_stateLock)
        {
            INETOptions.Save(null, null);
            IsRunning = false;

            _listener?.Close();
            _listener = null;

            _client.CancelPendingRequests();
        }
    }
    public static void Initiate(int port)
    {
        lock (_stateLock)
        {
            _pathPAC = $"/proxy_{port}.pac/";

            _listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
            _listener.Bind(new IPEndPoint(IPAddress.Any, port));
            _listener.Listen();

            IsRunning = true;
            ActivePort = port;

            Task.Factory.StartNew(InterceptRequestAsync, TaskCreationOptions.LongRunning);
            INETOptions.Save($"http://127.0.0.1:{ActivePort}", _pathPAC);
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

        if (IsOnlyInterceptingHttp)
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
            // Parse Request(s) from Client
            ogRequest = await local.ReceiveHttpRequestAsync(cancellationToken).ConfigureAwait(false);
            originalRequestContent = ogRequest.Content;

            if (ogRequest.RequestUri?.OriginalString == _pathPAC)
            {
                ogResponse = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(GeneratePAC(), Encoding.ASCII, "application/x-ns-proxy-autoconfig")
                };
            }
            else
            {
                requestArgs = new RequestInterceptedEventArgs(ogRequest);
                await OnRequestInterceptedAsync(requestArgs, cancellationToken).ConfigureAwait(false);
                if (requestArgs.Cancel || cancellationToken.IsCancellationRequested) return;

                ogResponse = requestArgs.Response;
                if (ogResponse == null)
                {
                    if (IsActingAsForwardingServer && ogRequest.Method == HttpMethod.Connect)
                    {
                        // Double proxying should be avoided as the handler should be using the 'SelfBypassWebProxy' instance.
                        // If it fails to apply the proxy manually, discard this request.
                        if (!(wasProxiedExternally = TryApplyProxy(ogRequest))) return;
                    }
                    ogResponse = await _client.SendAsync(requestArgs.Request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                }
                originalResponseContent = ogResponse.Content;

                // This flag is meant to de-clutter the interception pipeline, in the case that a request has already been provided a response we're aware of.
                // Also, check if the async event itself has any subscribers.
                if ((!IsActingAsForwardingServer || requestArgs.Method != HttpMethod.Connect) && requestArgs.IsInterceptingResponse && ResponseInterceptedAsync != null)
                {
                    responseArgs = new ResponseInterceptedEventArgs(ogResponse);
                    await OnResponseInterceptedAsync(responseArgs, cancellationToken).ConfigureAwait(false);
                    if (responseArgs.Cancel || cancellationToken.IsCancellationRequested) return;
                }
            }

            // Send Response(s) to Client
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

    private static bool TryApplyProxy(HttpRequestMessage request)
    {
        if (request.RequestUri == null || Proxy == null) return false;

        Uri? proxyUri = Proxy.GetProxy(request.RequestUri);
        if (proxyUri == null) return false;

        ICredentials? credentials = Proxy.Credentials;
        if (credentials == null) return false;

        NetworkCredential? uriCredentials = credentials.GetCredential(proxyUri, "Basic");
        if (uriCredentials == null) return false;

        string? encodedCredentials = $"{uriCredentials.UserName}:{uriCredentials.Password}";
        encodedCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(encodedCredentials));
        request.Headers.TryAddWithoutValidation("Proxy-Authorization", $"Basic {encodedCredentials}");

        request.RequestUri = proxyUri;
        return true;
    }
    private static async Task ClampStreamsAsync(Stream fromStream, Stream toStream)
    {
        // Immediately return to the previous context.
        await Task.Yield();

        using IMemoryOwner<byte> bufferOwner = MemoryPool<byte>.Shared.Rent(512);
        Memory<byte> buffer = bufferOwner.Memory;

        int bytesRead = 0;
        while (fromStream.CanRead && toStream.CanWrite)
        {
            bytesRead = await fromStream.ReadAsync(buffer).ConfigureAwait(false);
            if (bytesRead < 1) break;

            await toStream.WriteAsync(buffer.Slice(0, bytesRead)).ConfigureAwait(false);
            await toStream.FlushAsync().ConfigureAwait(false);
        }
    }
}