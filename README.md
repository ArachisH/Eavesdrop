# Eavesdrop
[![Build CI](https://github.com/ArachisH/Eavesdrop/actions/workflows/build.yaml/badge.svg)](https://github.com/ArachisH/Eavesdrop/actions)
[![NuGet](https://img.shields.io/nuget/v/Eavesdrop?label=NuGet)](https://www.nuget.org/packages/Eavesdrop)
![License](https://img.shields.io/github/license/ArachisH/Eavesdrop?label=License)

HTTP(S) proxy server for Windows machines that allows for the interception, and modification of all HTTP/HTTPS traffic.

---
## Features
* Block, replace, modify HTTP(S) requests and responses.
* Blacklist, and whitelist specific hosts with wildcard support.
* HTTP/1.1 Chunked transfer encoding which allows for the streaming of data/headers without buffering the entire response content.

HTTP/2 is **not** a currently supported protocol, as well as the following HTTP/1.X features:
* Keep-Alive - Allows for the same connection to be used for multiple requests, and responses
* Upgrade - Allows for switching to different protocols other than HTTP on the same connection. (eg. WebSocket)
---
## Configuring

### Generating & Installing the Certificate Authority
Before we can begin intercepting HTTPS requests from the machine, we first need to install a self-signed certificate into the root store of the machine. This certificate will act as the CA for the subsequent certificates we will be issuing to every domain/request intercepted that requires encryption(HTTPS).
```cs
bool success = Eavesdropper.Certifier.CreateTrustedRootCertificate();
```
The result of this method will let us know if permission was granted by the user for installation into the root store, and if the installation of the CA into the root store succeeded. If the CA was installed with an elevated application process, then you will also require elevated permissions to remove the CA from the root store.

### Whitelisting & Blacklisting Hosts
There is one list we can modify to either whitelist, or blacklist hosts whose behavior is determined by the value of the property 'IsProxyingTargets'. By default any host added to 'Targets' will **not** be proxied, but if 'IsProxyingTargets' is set to *true* then **only** the hosts that exist in 'Targets' will be intercepted.
```cs
// Default Behavior - Do NOT intercept any requests to *google.com
// www.google.com               - NOT INTERCEPTED
// api.google.com               - NOT INTERCEPTED
// google.com                   - NOT INTERCEPTED
// https://docs.github.com/en   - INTERCEPTED < Implicitly Whitelisted
Eavesdropper.Targets.Add("*google.com");
```
If you wish to go with a more direct approach, we can set 'IsProxyingTargets' to **true** to explicitly specify which hosts to intercept.
```cs
// The hosts that have been added to Targets are the only ones to be intercepted
IsProxyingTargets = true;
Eavesdropper.Targets.Add("*github.com");
Eavesdropper.Targets.Add("*microsoft.com");
// https://docs.github.com/en           - INTERCEPTED
// https://stackoverflow.com            - NOT INTERCEPTED < Implicitly Blacklisted
// https://support.microsoft.com/en-us  - INTERCEPTED
```
Notice that the wildcard character is used as a prefix to the host, and is not followed by a period('\*.github.com'). This is to ensure that URLs with no sub-domain are still captured/filtered by the PAC file, otherwise some requests might slip by.

### Internal Hosts
If you have services that exist on your local network that you do not wish to be intercepted when accessing them on your machine, then we don't need to do any additional work if they're being accessed via IP address(https://192.168.1.10). The default behavior is to ignore any request being made to a private subnet, but this is not the case for hosts that are setup in your local DNS server that link to these services(except *.local*). For these scenarios we need to explicitly state which hosts are part of our local network via the 'IntranetHosts' list.
```cs
// This host exist within our networks DNS table, and does not reach the Internet.
Eavesdropper.IntranetHosts.Add("portainer.nginx.svc");
// https://portainer.nginx.svc  - NOT INTERCEPTED
// https://sonarr.nginx.svc     - INTERCEPTED
// https://pfSense.svc          - INTERCEPTED
```
Alternatively, if you do wish to intercept the traffic being made to services on your internal network, we can set the 'IsProxyingPrivateNetworks' property to true.
```cs
// Intercept requests to private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
Eavesdropper.IsProxyingPrivateNetworks = true;
```

### Asynchronous Interception Events
There are two event delegates we can attach to in the Eavesdropper class that will allow us to act on either the request, or response in an asynchronous manner. Within these event callbacks we're able to use async/await to perform tasks while still allowing the underlying proxy server to continue intercepting requests/responses in the background.
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
Since both of these delegates accept a Task as a return type, we can simply return one if we wish for the request/response to 'await' it.
```cs
Eavesdropper.ResponseInterceptedAsync += (object sender, ResponseInterceptedEventArgs e) => Task.Delay(1000);
```

### External Proxying
An instance of `IWebProxy` can be pass to the `Eavesdropper.Proxy` property that will proxy all intercepted outgoing web requests to the specified proxy server.
```cs
Eavesdropper.Proxy = new WebProxy("http://10.10.10.10:80");
Eavesdropper.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials ?? new NetworkCredential("username", "passw0rd!");
```
Additionally, we can set the proxy server into forwarding mode. This mode will **not** attempt to decrypt any intercepted HTTPS traffic, and only mediate the data from the local machine to the specified proxy server.
```cs
Eavesdropper.IsActingAsForwardingServer = true;
```
This propery should only be enabled once a `IWebProxy` instance has been provided.

---
## Initialization
To start the proxy server and begin intercepting the system's HTTP/S traffic we need to call:
```cs
Eavesdropper.Initiate(port);
```
Doing so will set the URL of the 'setup script' on the machine, where the URL points to the proxy server itself.
(http://127.0.0.1:{ActivePort}/proxy_{ActivePort}.pac/)

The PAC file is created based on the configuration you applied beforehand, and given as a response when the request is intercepted from the machine. This PAC file is not stored locally, and is provided by the proxy server instead because the response must contain `application/x-ns-proxy-autoconfig` as its' `Content-Type` header value.

---
## Termination
Once you are finished, we can call the 'Terminate' method to remove the PAC URL from the machine's settings, and gracefully kill the server.
```cs
Eavesdropper.Terminate();
```
