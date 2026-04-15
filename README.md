# Eavesdrop
[![CI Workflow](https://github.com/ArachisH/Eavesdrop/actions/workflows/ci.yaml/badge.svg)](https://github.com/ArachisH/Eavesdrop/actions/workflows/ci.yaml)
[![NuGet](https://img.shields.io/nuget/v/Eavesdrop?label=NuGet)](https://www.nuget.org/packages/Eavesdrop)
[![NuGet](https://img.shields.io/nuget/vpre/Eavesdrop?label=NuGet%20(Pre))](https://www.nuget.org/packages/Eavesdrop)
![License](https://img.shields.io/github/license/ArachisH/Eavesdrop?label=License)

A programmable HTTP(S) interception proxy for .NET.

Eavesdrop is a machine-local proxy that can inspect, modify, block, or forward HTTP and HTTPS traffic. It configures the system to use a PAC file served by the local proxy, can generate certificates for HTTPS interception, and exposes asynchronous request and response hooks so applications can participate directly in the interception pipeline.

Although the package multi-targets modern .NET and .NET Standard, the current design is centered around Windows system proxy behavior. HTTPS certificate generation also has platform-specific behavior that is more mature on Windows than on Linux.

## What It Does
- Intercepts outbound HTTP and HTTPS traffic from the local machine
- Lets you inspect and mutate `HttpRequestMessage` and `HttpResponseMessage` instances
- Supports host-based allowlists and blocklists through PAC rules
- Can bypass intranet and private-network traffic, or include it explicitly
- Can forward traffic to another proxy instead of terminating TLS locally
- Streams chunked HTTP/1.1 responses without buffering the full payload

## Quick Start
Install the package:

```powershell
dotnet add package Eavesdrop
```

Minimal setup:

```cs
using Eavesdrop;

Eavesdropper.CertProvider.TryCreateTrustedRootCA("Eavesdrop");

Eavesdropper.RequestInterceptedAsync += async (_, e) =>
{
    Console.WriteLine($"{e.Method} {e.Uri}");
    await Task.CompletedTask;
};

Eavesdropper.ResponseInterceptedAsync += async (_, e) =>
{
    Console.WriteLine($"{(int)e.StatusCode} {e.Uri}");
    await Task.CompletedTask;
};

Eavesdropper.Initiate(12030);

Console.WriteLine("Press any key to stop...");
Console.ReadKey();

Eavesdropper.Terminate();
```

## How It Works
When `Eavesdropper.Initiate(port)` is called, Eavesdrop:

1. Starts a local socket listener on the specified port.
2. Serves a PAC file from `http://127.0.0.1:{port}/proxy_{port}.pac/`.
3. Updates the machine's proxy configuration so traffic is routed through that PAC file.
4. Accepts HTTP requests directly, and handles HTTPS by processing the `CONNECT` tunnel and optionally terminating TLS locally.

If HTTPS interception is enabled, the library generates per-host certificates from a trusted root certificate authority. That root CA must exist before HTTPS traffic can be decrypted.

When `Terminate()` is called, Eavesdrop removes the saved proxy settings, stops accepting new connections, and cancels pending outbound requests.

## Important Notes
- This library changes machine-level proxy behavior while it is running.
- HTTPS interception requires trusting a locally generated root certificate.
- If you do not create a trusted root CA, HTTPS interception will fail when the proxy attempts to process `CONNECT` requests.
- `Eavesdropper` is a static, process-wide API. Configuration is global for the current process.
- The default upstream `HttpClient` does not automatically redirect responses.

## Configuration
### Certificate Authority
HTTPS interception depends on `Eavesdropper.CertProvider`, which caches issued certificates and creates host certificates from a root CA.

The simplest setup is:

```cs
bool success = Eavesdropper.CertProvider.TryCreateTrustedRootCA("Eavesdrop");
```

This overload creates a certificate authority with:
- Organization: `Eavesdrop`
- Common name: `Eavesdrop Root Certificate Authority`

You can also specify both values explicitly:

```cs
bool success = Eavesdropper.CertProvider.TryCreateTrustedRootCA(
    organization: "My Company",
    commonName: "My Company Development Root CA");
```

The certificate provider also exposes:
- `NotBefore` and `NotAfter` to control issued certificate validity
- `IsRootCATrusted` to indicate whether the root CA was successfully added to the user root store
- `RootCertificateAuthority` for access to the loaded or generated CA certificate

### Host Filtering
Host filtering is controlled by two members:

- `Eavesdropper.Targets`
- `Eavesdropper.IsProxyingTargets`

Behavior:
- When `IsProxyingTargets == false`, entries in `Targets` are excluded from interception.
- When `IsProxyingTargets == true`, only entries in `Targets` are intercepted.

Exclude all `google.com` traffic:

```cs
Eavesdropper.Targets.Add("*google.com");
```

Intercept only GitHub and Microsoft:

```cs
Eavesdropper.IsProxyingTargets = true;
Eavesdropper.Targets.Add("*github.com");
Eavesdropper.Targets.Add("*microsoft.com");
```

Use wildcard prefixes such as `*github.com` instead of `*.github.com` so both the root domain and subdomains are matched by the PAC file.

### Private Networks and Intranet Hosts
By default, the generated PAC file bypasses:
- Plain host names
- `*.local`
- `10.*`
- `172.16.*`
- `192.168.*`

To include private networks in interception:

```cs
Eavesdropper.IsProxyingPrivateNetworks = true;
```

If you use internal DNS names for intranet services, add them explicitly:

```cs
Eavesdropper.IntranetHosts.Add("portainer.nginx.svc");
Eavesdropper.IntranetHosts.Add("sonarr.nginx.svc");
```

### HTTP-Only Interception
If you only want to intercept HTTP traffic and leave HTTPS direct:

```cs
Eavesdropper.IsOnlyInterceptingHttp = true;
```

This injects PAC behavior that returns `DIRECT` for HTTPS URLs.

### Custom PAC Logic
You can prepend custom JavaScript to the PAC file through `Eavesdropper.PACHeader`:

```cs
Eavesdropper.PACHeader = """
    if (dnsDomainIs(host, "example.internal"))
        return "DIRECT";
    """;
```

This is useful when you need PAC rules that go beyond `Targets`, `IntranetHosts`, or `IsOnlyInterceptingHttp`.

### Forwarding to an Upstream Proxy
You can route intercepted traffic to another proxy:

```cs
var upstreamProxy = new WebProxy("http://10.10.10.10:80")
{
    Credentials = CredentialCache.DefaultNetworkCredentials
};

Eavesdropper.Proxy = upstreamProxy;
```

If you want Eavesdrop to behave as a forwarding proxy instead of decrypting HTTPS locally:

```cs
Eavesdropper.Proxy = new WebProxy("http://10.10.10.10:80");
Eavesdropper.IsActingAsForwardingServer = true;
```

`IsActingAsForwardingServer` requires `Proxy` to be configured first. Otherwise, the property setter throws.

## Interception Pipeline
Eavesdrop exposes two async events:
- `Eavesdropper.RequestInterceptedAsync`
- `Eavesdropper.ResponseInterceptedAsync`

Each event is awaited by the proxy pipeline, so handlers can perform asynchronous work before traffic continues.

### Inspecting Requests
`RequestInterceptedEventArgs` exposes:
- `Request`
- `Method`
- `Content`
- `Headers`
- `Uri`
- `Version`
- `Response`
- `IsInterceptingResponse`
- `Cancel`

Example:

```cs
Eavesdropper.RequestInterceptedAsync += async (_, e) =>
{
    Console.WriteLine($"{e.Method} {e.Uri}");

    foreach ((string name, IEnumerable<string> values) in e.Headers)
    {
        Console.WriteLine($"{name}: {string.Join(", ", values)}");
    }

    await Task.CompletedTask;
};
```

### Modifying Requests
You can mutate the request in place:

```cs
Eavesdropper.RequestInterceptedAsync += async (_, e) =>
{
    e.Headers.Remove("X-Debug");
    e.Headers.TryAddWithoutValidation("X-Debug", "intercepted");

    if (e.Content != null)
    {
        string body = await e.Content.ReadAsStringAsync().ConfigureAwait(false);
        e.Content = new StringContent(body.Replace("before", "after"));
    }
};
```

You can also replace the entire request:

```cs
Eavesdropper.RequestInterceptedAsync += (_, e) =>
{
    e.Request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/replacement");
    return Task.CompletedTask;
};
```

### Short-Circuiting with a Custom Response
If you assign `e.Response` during request interception, Eavesdrop skips the outbound request and returns your response directly:

```cs
Eavesdropper.RequestInterceptedAsync += (_, e) =>
{
    if (e.Uri?.Host == "example.com")
    {
        e.Response = new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("Blocked by Eavesdrop")
        };
    }
    return Task.CompletedTask;
};
```

### Skipping Response Interception
If you only need request-time handling, you can disable the response hook for that request:

```cs
Eavesdropper.RequestInterceptedAsync += (_, e) =>
{
    e.IsInterceptingResponse = false;
    return Task.CompletedTask;
};
```

### Inspecting and Modifying Responses
`ResponseInterceptedEventArgs` exposes:
- `Response`
- `Request`
- `Uri`
- `StatusCode`
- `ReasonPhrase`
- `Version`
- `Headers`
- `Content`
- `IsSuccessStatusCode`
- `Cancel`

Example:

```cs
Eavesdropper.ResponseInterceptedAsync += async (_, e) =>
{
    Console.WriteLine($"{(int)e.StatusCode} {e.Uri}");

    if (e.Content != null)
    {
        string body = await e.Content.ReadAsStringAsync().ConfigureAwait(false);
        e.Content = new StringContent(body.Replace("server", "proxy"));
    }
};
```

You can also replace the whole response:

```cs
Eavesdropper.ResponseInterceptedAsync += (_, e) =>
{
    e.Response = new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent("Response replaced by Eavesdrop")
    };
    return Task.CompletedTask;
};
```

### Cancelling Work
Both interception event args inherit from `CancelEventArgs`.

If a handler sets `e.Cancel = true`, the current pipeline operation stops and the method returns without continuing further processing for that intercepted exchange.

## Supported Protocols
Currently supported:
- HTTP
- HTTPS through `CONNECT` interception and local TLS termination
- HTTP/1.1 request parsing
- HTTP/1.1 chunked response streaming

Not currently supported:
- HTTP/2
- Keep-alive connection reuse
- Upgrade-based protocols such as WebSocket

## Platform Notes
- The package targets `netstandard2.0`, `net8.0`, `net9.0`, and `net10.0`.
- Windows is the primary target for machine proxy configuration and HTTPS interception workflows.
- The certificate subsystem includes Linux support, but the test suite contains a Windows-only HTTPS interception path due to TLS/platform differences.

## Lifecycle and State
Useful state exposed by `Eavesdropper`:
- `ActivePort`
- `IsRunning`
- `Proxy`
- `Targets`
- `IntranetHosts`
- `PACHeader`

Typical lifecycle:

```cs
Eavesdropper.Targets.Clear();
Eavesdropper.IntranetHosts.Clear();

Eavesdropper.IsProxyingTargets = false;
Eavesdropper.IsOnlyInterceptingHttp = false;
Eavesdropper.IsProxyingPrivateNetworks = false;

Eavesdropper.CertProvider.TryCreateTrustedRootCA("Eavesdrop");
Eavesdropper.Initiate(12030);

// Run application logic here.

Eavesdropper.Terminate();
```

## Limitations and Caveats
- The API is static and global, so it is not designed for hosting multiple independent proxy instances in one process.
- Starting the proxy assumes the selected port is available; port selection and collision handling are left to the caller.
- Host filtering is enforced through the generated PAC file, so traffic that does not respect the machine proxy settings will not be intercepted.
- The default private-network PAC rules are intentionally simple and may need customization for more complex environments.
- HTTPS decryption depends on certificate trust and client behavior; some applications may still reject interception even when a root CA is installed.

## Example Console App
The repository includes a simple console sample in `Eavesdrop.CLI` that demonstrates:
- Request and response logging
- Target filtering
- Optional private-network interception
- Optional upstream proxy forwarding
- Certificate installation and proxy start/stop flow
