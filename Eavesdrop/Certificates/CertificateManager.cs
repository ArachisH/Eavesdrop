using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates
{
    public class CertificateManager : IDisposable
    {
        private readonly IDictionary<string, X509Certificate2> _certificateCache;

        public string Issuer { get; }
        public string CertificateAuthorityName { get; }
        public ICertificateEngine CertificateEngine { get; }
        public bool IsStoringPersonalCertificates { get; set; }

        public X509Store MyStore { get; }
        public X509Store RootStore { get; }
        public X509Certificate2 Authority { get; private set; }

        public CertificateManager(string issuer, string certificateAuthorityName)
        {
            _certificateCache = new Dictionary<string, X509Certificate2>();

            Issuer = issuer;
            CertificateEngine = new WindowsCertificateEngine();
            CertificateAuthorityName = certificateAuthorityName;

            MyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            RootStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        }

        public bool CreateTrustedRootCertificate()
        {
            return (Authority = InstallCertificate(RootStore, CertificateAuthorityName)) != null;
        }
        public bool DestroyTrustedRootCertificate()
        {
            return DestroyCertificates(RootStore);
        }
        public bool ExportTrustedRootCertificate(string path)
        {
            X509Certificate2 rootCertificate = InstallCertificate(RootStore, CertificateAuthorityName);

            path = Path.GetFullPath(path);
            if (rootCertificate != null)
            {
                byte[] data = rootCertificate.Export(X509ContentType.Cert);
                File.WriteAllBytes(path, data);
            }
            return File.Exists(path);
        }

        public X509Certificate2Collection FindCertificates(string subjectName)
        {
            return FindCertificates(MyStore, subjectName);
        }
        protected virtual X509Certificate2Collection FindCertificates(X509Store store, string subjectName)
        {
            X509Certificate2Collection certificates = store.Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, subjectName, false);

            return (certificates.Count > 0 ? certificates : null);
        }

        public X509Certificate2 GenerateCertificate(string certificateName)
        {
            return InstallCertificate(MyStore, certificateName);
        }
        protected virtual X509Certificate2 InstallCertificate(X509Store store, string certificateName)
        {
            if (_certificateCache.TryGetValue(certificateName, out X509Certificate2 certificate))
            {
                if (DateTime.Now >= certificate.NotAfter)
                {
                    _certificateCache.Remove(certificateName);
                }
                else return certificate;
            }
            lock (store)
            {
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    string subjectName = $"CN={certificateName}, O={Issuer}";

                    certificate = FindCertificates(store, subjectName)?[0];
                    if (certificate != null && DateTime.Now >= certificate.NotAfter)
                    {
                        if (Authority == null)
                        {
                            DestroyCertificates();
                            store.Open(OpenFlags.ReadWrite);
                        }
                        else
                        {
                            store.Remove(certificate);
                        }
                        certificate = null;
                    }

                    if (certificate == null)
                    {
                        certificate = CertificateEngine.CreateCertificate(subjectName, certificateName, Authority);
                        if (certificate != null)
                        {
                            if (store == RootStore || IsStoringPersonalCertificates)
                            {
                                store.Add(certificate);
                            }
                        }
                    }

                    return certificate;
                }
                catch { return (certificate = null); }
                finally
                {
                    store.Close();
                    if (certificate != null && !_certificateCache.ContainsKey(certificateName))
                    {
                        _certificateCache.Add(certificateName, certificate);
                    }
                }
            }
        }

        public void DestroyCertificates()
        {
            DestroyCertificates(MyStore);
            DestroyCertificates(RootStore);
        }
        public bool DestroyCertificates(X509Store store)
        {
            lock (store)
            {
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    X509Certificate2Collection certificates = store.Certificates.Find(X509FindType.FindByIssuerName, Issuer, false);

                    store.RemoveRange(certificates);
                    IEnumerable<string> subjectNames = certificates.Cast<X509Certificate2>().Select(c => c.GetNameInfo(X509NameType.SimpleName, false));

                    foreach (string subjectName in subjectNames)
                    {
                        if (!_certificateCache.ContainsKey(subjectName)) continue;
                        _certificateCache.Remove(subjectName);
                    }
                    return true;
                }
                catch { return false; }
                finally { store.Close(); }
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                MyStore.Close();
                RootStore.Close();
            }
        }
    }
}