using System.Net;
using System.Net.Sockets;

using Eavesdrop.Network;

namespace Eavesdrop;

public static class Eavesdropper
{
    private static readonly object _stateLock;
    private static readonly HttpClient _httpClient;
    private static readonly HttpClientHandler _httpClientHandler;

    private static TcpListener? _listener;

    public delegate Task AsyncEventHandler<TEventArgs>(object? sender, TEventArgs e);

    public static event AsyncEventHandler<RequestInterceptedEventArgs>? RequestInterceptedAsync;
    private static async Task OnRequestInterceptedAsync(RequestInterceptedEventArgs e)
    {
        Task? interceptedTask = RequestInterceptedAsync?.Invoke(null, e);
        if (interceptedTask != null)
        {
            await interceptedTask;
        }
    }

    public static event AsyncEventHandler<ResponseInterceptedEventArgs>? ResponseInterceptedAsync;
    private static async Task OnResponseInterceptedAsync(ResponseInterceptedEventArgs e)
    {
        Task? interceptedTask = ResponseInterceptedAsync?.Invoke(null, e);
        if (interceptedTask != null)
        {
            await interceptedTask;
        }
    }

    public static bool IsRunning { get; private set; }
    public static CertificateManager Certifier { get; set; }

    static Eavesdropper()
    {
        _stateLock = new object();
        _httpClientHandler = new HttpClientHandler { UseProxy = false };
        _httpClient = new HttpClient(_httpClientHandler);

        _httpClientHandler.AllowAutoRedirect = false;
        _httpClientHandler.CheckCertificateRevocationList = false;
        _httpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        Certifier = new CertificateManager("Eavesdrop", "Eavesdrop Root Certificate Authority");
    }

    public static void Terminate()
    {
        lock (_stateLock)
        {
            ResetMachineProxy();
            IsRunning = false;

            if (_listener != null)
            {
                _listener.Stop();
                _listener = null;
            }
        }
    }
    public static void Initiate(int port)
    {
        Initiate(port, Interceptors.Default);
    }
    public static void Initiate(int port, Interceptors interceptors)
    {
        Initiate(port, interceptors, true);
    }
    public static void Initiate(int port, Interceptors interceptors, bool setSystemProxy)
    {
        lock (_stateLock)
        {
            _listener = new TcpListener(IPAddress.Any, port);
            _listener.Start();

            IsRunning = true;

            Task.Factory.StartNew(InterceptRequestAsnync, TaskCreationOptions.LongRunning);
            if (setSystemProxy)
            {
                SetMachineProxy(port, interceptors);
            }
        }
    }

    public static void AddOverrides(params string[] domains)
    {
        foreach (string domain in domains)
        {
            INETOptions.Overrides.Add(domain);
        }
    }

    private static async Task InterceptRequestAsnync()
    {
        try
        {
            while (IsRunning && _listener != null)
            {
                Socket client = await _listener.AcceptSocketAsync().ConfigureAwait(false);
                _ = HandleClientAsync(client);
            }
        }
        catch { /* Catch all exceptions. */ }
    }
    private static async Task HandleClientAsync(Socket client)
    {
        using var local = new EavesNode(client, Certifier);

        HttpResponseMessage? response = null;
        HttpContent? originalResponseContent = null;

        HttpRequestMessage request = await local.ReceiveHTTPRequestAsync().ConfigureAwait(false);
        HttpContent? originalRequestContent = request.Content;
        try
        {
            var requestArgs = new RequestInterceptedEventArgs(request);
            await OnRequestInterceptedAsync(requestArgs).ConfigureAwait(false);
            if (requestArgs.Cancel) return;

            response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            originalResponseContent = response.Content;

            var responseArgs = new ResponseInterceptedEventArgs(response);
            await OnResponseInterceptedAsync(responseArgs).ConfigureAwait(false);
            if (responseArgs.Cancel) return;

            await local.SendHTTPResponseAsync(response).ConfigureAwait(false);
        }
        finally
        {
            request.Dispose();
            originalRequestContent?.Dispose();

            response?.Dispose();
            originalResponseContent?.Dispose();
        }
    }

    private static void ResetMachineProxy()
    {
        INETOptions.Overrides.Clear();
        INETOptions.IsIgnoringLocalTraffic = false;

        INETOptions.HTTPAddress = null;
        INETOptions.HTTPSAddress = null;
        INETOptions.IsProxyEnabled = false;

        INETOptions.Save();
    }
    private static void SetMachineProxy(int port, Interceptors interceptors)
    {
        string address = "127.0.0.1:" + port;
        if (interceptors.HasFlag(Interceptors.HTTP))
        {
            INETOptions.HTTPAddress = address;
        }
        if (interceptors.HasFlag(Interceptors.HTTPS))
        {
            INETOptions.HTTPSAddress = address;
        }
        INETOptions.IsProxyEnabled = true;
        INETOptions.IsIgnoringLocalTraffic = true;

        INETOptions.Save();
    }
}