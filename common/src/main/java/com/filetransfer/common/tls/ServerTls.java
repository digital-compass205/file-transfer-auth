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
 * Builds an SSLContext for a server process using only JDK APIs: its own
 * identity from a PKCS12 keystore, and a trust anchor built directly from
 * the internal CA's root certificate PEM (so client certs signed by that CA
 * validate during the handshake).
 */
public final class ServerTls {

    private ServerTls() {
    }

    public static SSLContext buildSslContext(Path serverKeystorePkcs12, char[] keystorePassword, Path caCertPem)
            throws IOException, GeneralSecurityException {
        KeyStore identity = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(serverKeystorePkcs12)) {
            identity.load(in, keystorePassword);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(identity, keystorePassword);

        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(caCertPem)) {
            Certificate caCert = cf.generateCertificate(in);
            trust.setCertificateEntry("internal-ca", caCert);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }
}
