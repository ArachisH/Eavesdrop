using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop
{
    /// <summary>
    /// Represents a manager for creating/destroying self-signed certificates.
    /// </summary>
    public class Certifier : IDisposable
    {
        private const string CERT_CREATE_FORMAT =
            "-ss {0} -n \"CN={1}, O={2}\" -sky {3} -cy {4} -m 120 -a sha256 -eku 1.3.6.1.5.5.7.3.1 {5}";

        private readonly Process _certCreateProcess;
        private readonly IDictionary<string, X509Certificate2> _certificateCache;

        public string Issuer { get; }
        public string RootCertificateName { get; }

        public X509Store MyStore { get; }
        public X509Store RootStore { get; }
        public FileInfo MakeCertInfo { get; }

        public bool IsDisposed { get; private set; }

        public Certifier(string issuer, string rootCertificateName)
        {
            string currentDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            MakeCertInfo = new FileInfo(Path.Combine(currentDirectory, "makecert.exe"));
            
            _certCreateProcess = new Process();
            _certCreateProcess.StartInfo.Verb = "runas";
            _certCreateProcess.StartInfo.CreateNoWindow = true;
            _certCreateProcess.StartInfo.UseShellExecute = false;
            _certCreateProcess.StartInfo.FileName = MakeCertInfo.FullName;
            _certificateCache = new Dictionary<string, X509Certificate2>();

            Issuer = issuer;
            RootCertificateName = rootCertificateName;
            
            MyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            RootStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        }

        public bool CreateTrustedRootCertificate()
        {
            X509Certificate2 rootCertificate =
                CreateCertificate(RootStore, RootCertificateName);

            return rootCertificate != null;
        }
        public bool DestroyTrustedRootCertificate()
        {
            return DestroyCertificate(RootStore, RootCertificateName);
        }
        public bool ExportTrustedRootCertificate(string path)
        {
            X509Certificate2 rootCertificate =
                CreateCertificate(RootStore, RootCertificateName);

            path = Path.GetFullPath(path);
            if (rootCertificate != null)
            {
                byte[] data = rootCertificate.Export(X509ContentType.Cert);
                File.WriteAllBytes(path, data);
            }
            return File.Exists(path);
        }

        public X509Certificate2Collection FindCertificates(string certificateSubject)
        {
            return FindCertificates(MyStore, certificateSubject);
        }
        protected virtual X509Certificate2Collection FindCertificates(X509Store store, string certificateSubject)
        {
            X509Certificate2Collection discoveredCertificates = store.Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, certificateSubject, false);

            return discoveredCertificates.Count > 0 ?
                discoveredCertificates : null;
        }

        public X509Certificate2 CreateCertificate(string certificateName)
        {
            return CreateCertificate(MyStore, certificateName);
        }
        protected virtual X509Certificate2 CreateCertificate(X509Store store, string certificateName)
        {
            if (_certificateCache.ContainsKey(certificateName))
                return _certificateCache[certificateName];

            lock (store)
            {
                X509Certificate2 certificate = null;
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    string certificateSubject = $"CN={certificateName}, O={Issuer}";

                    X509Certificate2Collection certificates =
                        FindCertificates(store, certificateSubject);

                    if (certificates != null)
                        certificate = certificates[0];

                    if (certificate == null)
                    {
                        string[] args = new[] {
                            GetCertificateCreateArgs(store, certificateName) };

                        CreateCertificate(args);
                        certificates = FindCertificates(store, certificateSubject);

                        if (certificates != null)
                            certificate = certificates[0];
                    }
                    return certificate;
                }
                finally
                {
                    store.Close();

                    if (certificate != null && !_certificateCache.ContainsKey(certificateName))
                        _certificateCache.Add(certificateName, certificate);
                }
            }
        }

        public bool DestroyCertificate(string certificateName)
        {
            return DestroyCertificate(MyStore, certificateName);
        }
        protected virtual bool DestroyCertificate(X509Store store, string certificateName)
        {
            lock (store)
            {
                X509Certificate2Collection certificates = null;
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    string certificateSubject = string.Format("CN={0}, O={1}", certificateName, Issuer);

                    certificates = FindCertificates(store, certificateSubject);
                    if (certificates != null)
                    {
                        store.RemoveRange(certificates);
                        certificates = FindCertificates(store, certificateSubject);
                    }
                    return certificates == null;
                }
                catch (CryptographicException) { /* Certificate removal failed. */ return false; }
                finally
                {
                    store.Close();

                    if (certificates == null &&
                        _certificateCache.ContainsKey(certificateName))
                    {
                        _certificateCache.Remove(certificateName);
                    }
                }
            }
        }

        public bool DestroySignedCertificates()
        {
            var myCertificates = new X509Certificate2Collection();
            var rootCertificates = new X509Certificate2Collection();
            try
            {
                lock (MyStore)
                {
                    MyStore.Open(OpenFlags.ReadWrite);

                    var myStoreCertificates = MyStore.Certificates
                        .Find(X509FindType.FindByIssuerName, Issuer, false);

                    myCertificates.AddRange(myStoreCertificates);
                }
                lock (RootStore)
                {
                    RootStore.Open(OpenFlags.ReadWrite);

                    var myRootCertificates = RootStore.Certificates
                        .Find(X509FindType.FindByIssuerName, Issuer, false);

                    rootCertificates.AddRange(myRootCertificates);
                }
                return DestroySignedCertificates(myCertificates, rootCertificates);
            }
            finally
            {
                MyStore.Close();
                RootStore.Close();
            }
        }
        protected virtual bool DestroySignedCertificates(
            X509Certificate2Collection myCertificates, X509Certificate2Collection rootCertificates)
        {
            try
            {
                var certificateNames = new List<string>();
                if (MyStore != null)
                {
                    MyStore.RemoveRange(myCertificates);

                    IEnumerable<string> myCertNames = myCertificates.Cast<X509Certificate2>()
                        .Select(c => c.GetNameInfo(X509NameType.SimpleName, false));

                    certificateNames.AddRange(myCertNames);
                }

                if (RootStore != null)
                {
                    RootStore.RemoveRange(rootCertificates);

                    IEnumerable<string> rootCertNames = rootCertificates.Cast<X509Certificate2>()
                        .Select(c => c.GetNameInfo(X509NameType.SimpleName, false));

                    certificateNames.AddRange(rootCertNames);
                }

                foreach (string certificateName in certificateNames)
                {
                    if (_certificateCache.ContainsKey(certificateName))
                        _certificateCache.Remove(certificateName);
                }

                return true;
            }
            catch (CryptographicException) { return false; }
        }

        protected virtual void CreateCertificate(string[] args)
        {
            lock (_certCreateProcess)
            {
                if (!File.Exists(MakeCertInfo.FullName))
                    throw new Exception($"Unable to locate '{MakeCertInfo.Name}'.");

                _certCreateProcess.StartInfo.Arguments =
                    (args != null ? args[0] : string.Empty);

                _certCreateProcess.Start();
                _certCreateProcess.WaitForExit();
            }
        }
        protected virtual string GetCertificateCreateArgs(X509Store store, string certificateName)
        {
            bool isRootCertificate =
                (certificateName == RootCertificateName);

            string certCreatArgs = string.Format(CERT_CREATE_FORMAT,
                store.Name, certificateName, Issuer,
                isRootCertificate ? "signature" : "exchange",
                isRootCertificate ? "authority" : "end",
                isRootCertificate ? "-h 1 -r" : $"-pe -in \"{RootCertificateName}\" -is root");

            return certCreatArgs;
        }

        public void Dispose()
        {
            Dispose(true);
        }
        protected virtual void Dispose(bool disposing)
        {
            if (IsDisposed) return;
            if (disposing)
            {
                _certCreateProcess.Dispose();
            }
            IsDisposed = true;
        }
    }
}