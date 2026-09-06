package com.filetransfer.agent.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Wraps a password-protected PKCS12 keystore holding the agent's private
 * key + cert chain. Writes are atomic (temp file + rename) so the agent
 * never observes a half-written keystore, matching the renewal flow's
 * requirement to never be left with no valid cert on disk.
 */
public final class ClientKeyStore {

    private static final String ALIAS = "client";

    public static final class Identity {
        public final PrivateKey privateKey;
        public final X509Certificate[] chain;

        public Identity(PrivateKey privateKey, X509Certificate[] chain) {
            this.privateKey = privateKey;
            this.chain = chain;
        }

        public X509Certificate clientCert() {
            return chain[0];
        }
    }

    private ClientKeyStore() {
    }

    public static boolean exists(Path path) {
        return Files.exists(path);
    }

    public static Identity load(Path path, char[] password) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(path)) {
            ks.load(in, password);
        }
        PrivateKey key = (PrivateKey) ks.getKey(ALIAS, password);
        Certificate[] chain = ks.getCertificateChain(ALIAS);
        X509Certificate[] x509Chain = new X509Certificate[chain.length];
        for (int i = 0; i < chain.length; i++) {
            x509Chain[i] = (X509Certificate) chain[i];
        }
        return new Identity(key, x509Chain);
    }

    public static void store(Path path, char[] password, PrivateKey key, X509Certificate[] chain)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(ALIAS, key, password, chain);

        Files.createDirectories(path.toAbsolutePath().getParent());
        Path tmp = Files.createTempFile(path.toAbsolutePath().getParent(), "keystore-", ".tmp");
        try {
            try (var out = Files.newOutputStream(tmp)) {
                ks.store(out, password);
            }
            restrictToOwner(tmp);
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path, Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException notPosix) {
            // Windows: rely on the launching user's profile-directory ACLs for this
            // prototype -- see spec section 8 (OS-native secure storage is future work).
        } catch (IOException ignored) {
            // best-effort permission tightening
        }
    }

    public static X509Certificate[] parseCertChain(String pem) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();
        for (Certificate c : cf.generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))) {
            certs.add((X509Certificate) c);
        }
        return certs.toArray(new X509Certificate[0]);
    }
}
