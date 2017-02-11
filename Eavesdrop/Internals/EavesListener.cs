using System;
using System.Net;
using System.Net.Sockets;

namespace Eavesdrop
{
    internal class EavesListener : TcpListener
    {
        public EavesListener(IPEndPoint localEP)
            : base(localEP)
        { }
        public EavesListener(IPAddress localaddr, int port)
            : base(localaddr, port)
        { }

        public bool IsActive => Active;
    }
}