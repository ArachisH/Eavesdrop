using System.Net;
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

    static Eavesdropper()
    {
        _stateLock = new object();
        _httpClientHandler = new HttpClientHandler { UseProxy = false };
        _httpClient = new HttpClient(_httpClientHandler);

        _httpClientHandler.AllowAutoRedirect = false;
        _httpClientHandler.CheckCertificateRevocationList = false;
        _httpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

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

            INETOptions.Save($"http://127.0.0.1:{port}/proxy.pac/");
            Task.Factory.StartNew(InterceptRequestAsync, TaskCreationOptions.LongRunning);
        }
    }

    private static async Task InterceptRequestAsync()
    {
        try
        {
            while (IsRunning && _listener != null)
            {
                Socket socket = await _listener.AcceptAsync().ConfigureAwait(false);
                _ = HandleSocketAsync(socket);
            }
        }
        catch { /* Catch all exceptions. */ }
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
            if (request.RequestUri?.OriginalString == "http://127.0.0.1/proxy.pac/")
            {
                // TODO: Implement dynamic filtering.
                response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new StringContent($$"""
                    function FindProxyForURL (url, host)
                    {
                        return "PROXY 127.0.0.1:{{ActivePort}}; DIRECT";
                    }
                    """, null, "application/x-ns-proxy-autoconfig");
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