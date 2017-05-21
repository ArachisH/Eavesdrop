using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;

using Eavesdrop.Utilities;

namespace Eavesdrop
{
    /// <summary>
    /// Represents a static HTTP/HTTPS local web proxy, that allows the ability to alter/block a request, or a response.
    /// </summary>
    public static class Eavesdropper
    {
        private static EavesListener _listener;

        private static readonly object _thisStaticObjectLock;

        /// <summary>
        /// Occurs when a HTTP/HTTPS request has been intercepted before being sent to the remote endpoint.
        /// </summary>
        public static event EventHandler<RequestInterceptedEventArgs> RequestIntercepted;
        private static void OnRequestIntercepted(RequestInterceptedEventArgs e)
        {
            RequestIntercepted?.Invoke(null, e);
        }

        /// <summary>
        /// Occurs when a HTTP/HTTPS response has been intercepted before being received by the local endpoint.
        /// </summary>
        public static event EventHandler<ResponseInterceptedEventArgs> ResponseIntercepted;
        private static void OnResponseIntercepted(ResponseInterceptedEventArgs e)
        {
            ResponseIntercepted?.Invoke(null, e);
        }

        /// <summary>
        /// Gets the certificate handler for this machine's user store.
        /// </summary>
        public static Certifier Certifier { get; }
        /// <summary>
        /// Gets or sets the remote proxy that is applied to the locally intercepted request.
        /// </summary>
        public static IWebProxy RemoteProxy { get; set; }
        /// <summary>
        /// Gets a value that determines whether local web data is being intercepted.
        /// </summary>
        public static bool IsIntercepting { get; private set; }

        static Eavesdropper()
        {
            _thisStaticObjectLock = new object();

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

            Certifier = new Certifier("Eavesdrop",
                "Eavesdrop Root Certificate Authority");
        }

        public static void Terminate()
        {
            lock (_thisStaticObjectLock)
            {
                INETOptions.IsProxyEnabled = false;
                SetProxyAddresses(0, InterceptOptions.All);

                _listener?.Stop();
                IsIntercepting = false;
            }
        }
        public static void Initiate(ushort port)
        {
            Initiate(port, InterceptOptions.Default);
        }
        public static void Initiate(ushort port, InterceptOptions options)
        {
            if (IsIntercepting) Terminate();
            lock (_thisStaticObjectLock)
            {
                IsIntercepting = true;

                _listener = new EavesListener(IPAddress.Any, port);
                _listener.Start();

                InterceptRequest();

                SetProxyAddresses(port, options);
                INETOptions.IsProxyEnabled = true;
            }
        }

        private static void InterceptRequest()
        {
            if (_listener.IsActive)
            {
                _listener.BeginAcceptSocket(SocketAccepted, null);
            }
        }
        private static void SocketAccepted(IAsyncResult ar)
        {
            Socket client = null;
            try
            {
                client = _listener.EndAcceptSocket(ar);
                InterceptRequest();
            }
            catch (ObjectDisposedException)
            {
                // Listener stopped.
            }
            if (client != null)
            {
                HandleInterceptedSocket(client);
            }
        }

        private static void HandleInterceptedSocket(Socket client)
        {
            using (var node = new EavesNode(client, Certifier))
            {
                byte[] requestBody = null;
                HttpWebRequest request = node.ReceiveWebRequest();
                if (request == null) return;

                request.Proxy = RemoteProxy;
                if (request.Method == "POST" && request.ContentLength > 0)
                {
                    requestBody = node.Receive(
                        (int)request.ContentLength);
                }

                var requestArgs = new RequestInterceptedEventArgs(request);
                requestArgs.Payload = requestBody;
                OnRequestIntercepted(requestArgs);

                // Do not use 'requestBody', and 'request' at this point and beyond.
                // Instead, use the 'Request', and 'Payload' properties in 'requestArgs'.

                if (requestArgs.Cancel) return;
                if (requestArgs.Payload?.Length > 0)
                {
                    requestArgs.Request.ContentLength =
                        requestArgs.Payload.Length;

                    using (Stream requestStream = requestArgs
                        .Request.GetRequestStream())
                    {
                        requestStream.Write(requestArgs.Payload,
                            0, requestArgs.Payload.Length);
                    }
                }

                WebResponse response = null;
                try { response = requestArgs.Request.GetResponse(); }
                catch (WebException ex) { response = ex.Response; }
                catch (ProtocolViolationException) { response = null; }
                if (response == null) return;

                using (response)
                {
                    byte[] responseBody = null;
                    using (Stream responseStream = response.GetResponseStream())
                        responseBody = node.Receive(responseStream, -1);

                    var responseArgs = new ResponseInterceptedEventArgs(response);
                    responseArgs.Payload = responseBody;
                    OnResponseIntercepted(responseArgs);

                    // Do not use 'responseBody', and 'response' at this point and beyond.
                    // Instead, use the 'Response', and 'Payload' properties in 'responseArgs'.

                    if (!responseArgs.Cancel)
                    {
                        node.SendWebResponse(
                            responseArgs.Response, responseArgs.Payload);
                    }
                }
            }
        }
        private static void SetProxyAddresses(ushort port, InterceptOptions options)
        {
            string localAddress = ("127.0.0.1:" + port);
            if (port == 0) localAddress = string.Empty;

            IEnumerable<Enum> optionFlags = options.GetUniqueFlags();
            foreach (InterceptOptions option in optionFlags)
            {
                switch (option)
                {
                    case InterceptOptions.InterceptHTTP:
                    INETOptions.HTTPAddress = localAddress;
                    break;

                    case InterceptOptions.InterceptHTTPS:
                    INETOptions.SecureAddress = localAddress;
                    break;

                    case InterceptOptions.InterceptFTP:
                    {
                        if (port != 0)
                            throw new NotSupportedException(nameof(InterceptOptions.InterceptFTP));

                        INETOptions.FTPAddress = localAddress;
                        break;
                    }

                    case InterceptOptions.InterceptSocks:
                    {
                        if (port != 0)
                            throw new NotSupportedException(nameof(InterceptOptions.InterceptSocks));

                        INETOptions.SocksAddress = localAddress;
                        break;
                    }
                }
            }
        }
    }
}