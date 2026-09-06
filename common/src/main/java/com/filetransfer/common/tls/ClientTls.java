package com.filetransfer.common.tls;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

/**
 * SSLContext builders for the client agent. Both variants trust only the
 * internal CA's root -- never the platform's default trust store -- since
 * the whole point is that the server's identity is validated against a
 * pinned private root, not public CAs.
 */
public final class ClientTls {

    private ClientTls() {
    }

    /** Server-auth only, for the bootstrap /enroll call where the agent has no cert yet. */
    public static SSLContext trustOnly(Path caCertPem) throws IOException, GeneralSecurityException {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustManagers(caCertPem), null);
        return ctx;
    }

    /** mTLS: agent's own key/cert plus the pinned CA root, for /renew and uploads. */
    public static SSLContext mutual(Path clientKeystorePkcs12, char[] password, Path caCertPem)
            throws IOException, GeneralSecurityException {
        KeyStore identity = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(clientKeystorePkcs12)) {
            identity.load(in, password);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(identity, password);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), trustManagers(caCertPem), null);
        return ctx;
    }

    private static javax.net.ssl.TrustManager[] trustManagers(Path caCertPem) throws IOException, GeneralSecurityException {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(caCertPem)) {
            Certificate caCert = cf.generateCertificate(in);
            trust.setCertificateEntry("internal-ca", caCert);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        return tmf.getTrustManagers();
    }
}
