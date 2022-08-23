# Eavesdrop
HTTP(S) proxy server for Windows machines that allows for the interception, and modification of all HTTP/HTTPS traffic.

## Features
* Block, replace, modify HTTP/HTTPS requests and responses.
* Blacklist specific domains to avoid interception with wildcard support.
* HTTP/1.1 Chunked transfer encoding which allows for the streaming of data/headers without buffering the entire response content.

HTTP/2 is not a currently supported protocol, as well as the following HTTP/1.X features:
* Keep-Alive - Allows for the same connection to be used for multiple requests, and responses
* Upgrade - Allows for switching to different protocols other than HTTP on the same connection. (eg. WebSocket)

## Support
.NET 6+ (Windows Only)

---
# Usage

## Events
Before initializing the proxy server, you may first want to attach a delegate/method to one of the async event handlers provided by Eavesdropper:
```cs
Eavesdropper.RequestInterceptedAsync += async (object sender, RequestInterceptedEventArgs e) =>
{
    Console.WriteLine("REQUEST");
    Console.WriteLine(await e.Content.ReadAsStringAsync().ConfigureAwait(false));
};
Eavesdropper.ResponseInterceptedAsync += async (object sender, ResponseInterceptedEventArgs e) =>
{
    Console.WriteLine("RESPONSE");
    Console.WriteLine(await e.Content.ReadAsStringAsync().ConfigureAwait(false));
};
```
Each request/response is asynchronous which allows us to block the event handler with a long operation if need be, and still allow other requests/responses to process in the background. You can also just return a Task if you already have something for the event to wait on.
```cs
Eavesdropper.ResponseInterceptedAsync += (object sender, ResponseInterceptedEventArgs e) => Task.Delay(1000);
```

## Initialization
To start the proxy server and begin intercepting the system's HTTP traffic we need to call:
```cs
Eavesdropper.Initiate(PORT, Interceptors.Http);
```

This will set the system proxy to listen on the given port, but only for HTTP traffic. If you also want to intercept HTTPS traffic we'll first need to attempt to create a self-signed certificate authority to place in the root store.
```cs
if (Eavesdropper.Certifier.CreateTrustedRootCertificate())
{
    Eavesdropper.Initiate(PORT); // Intercept HTTP, and HTTPS traffic.
    //Eavesdropper.Initiate(PORT, Interceptors.Https) // Only intercept HTTPS traffic.
}
```

If you would instead only like to use the server capabilities of the library without setting it as the system wide proxy, then you may specify:
```cs
Eavesdropper.Initiate(PORT, Interceptors.Default, setSystemProxy: false); // Intercept HTTP, and HTTPS traffic but without setting as system proxy.
```

## Termination
If you have set Eavesdrop to act as the system proxy, then it is of utmost importance to explicitly call the terminate method in Eavesdropper. Not doing so will mean the machine is still trying to contact the local proxy server even if the application has been closed/killed.
```cs
Eavesdropper.Terminate();
```
