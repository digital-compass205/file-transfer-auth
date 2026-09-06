package com.filetransfer.common.tls;

import com.filetransfer.common.log.JsonLog;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Checks a client certificate against a locally-regenerated CRL file
 * (produced by scripts/revoke.sh + scripts/gen-crl.sh via `openssl ca
 * -gencrl`). The CRL is re-read whenever its mtime changes so a revocation
 * takes effect on the next request without restarting the service.
 *
 * <p>This check <strong>fails closed</strong>. If the CRL is missing,
 * unparseable, not signed by the internal CA, or has aged past its own
 * {@code nextUpdate} (plus a short grace window), every caller is rejected
 * rather than admitted. Failing open here would be silent: a typo in the
 * {@code ca.crl} config path, or a {@code gen-crl.sh} timer that stopped
 * running, would disable revocation enforcement entirely with nothing in
 * the logs to say so. The cost of failing closed is that the CRL must
 * actually be kept fresh -- see deploy/systemd-user/gen-crl.timer.
 *
 * <p>The signature check matters even though the CRL is read off local
 * disk: it means the file has to have come from the CA's own key, so a
 * process that can write to the CRL path but cannot sign cannot forge an
 * empty CRL to un-revoke a certificate.
 */
public final class CrlRevocationChecker {

    /**
     * The CRL could not be established as fresh and authentic, so no
     * revocation decision can be made. Callers must deny the request.
     */
    public static final class CrlUnavailableException extends Exception {
        public CrlUnavailableException(String message) {
            super(message);
        }

        public CrlUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * How far past its own nextUpdate a CRL is still accepted. `openssl ca
     * -gencrl` stamps nextUpdate at default_crl_days (1 day) out, and the
     * shipped timer regenerates every 6h, so this tolerates a couple of
     * missed regenerations before the system starts refusing clients.
     */
    private static final Duration STALE_GRACE = Duration.ofHours(12);

    private final Path crlFile;
    private final X509Certificate caCert;

    private X509CRL cached;
    private long cachedMtime = -1;

    public CrlRevocationChecker(Path crlFile, X509Certificate caCert) {
        this.crlFile = crlFile;
        this.caCert = caCert;
    }

    /** Builds a checker that verifies the CRL against the CA root at the given PEM path. */
    public static CrlRevocationChecker forCa(Path crlFile, Path caCertPem) throws IOException, java.security.GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(caCertPem)) {
            return new CrlRevocationChecker(crlFile, (X509Certificate) cf.generateCertificate(in));
        }
    }

    public synchronized boolean isRevoked(X509Certificate cert) throws CrlUnavailableException {
        return load().isRevoked(cert);
    }

    /**
     * Logs whether the CRL is currently usable, at startup, so a broken path
     * or a stale file is visible immediately rather than as a wave of
     * rejected clients.
     */
    public void logStatusAtStartup(JsonLog log) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("crl_file", crlFile.toString());
        try {
            X509CRL crl = load();
            fields.put("next_update", String.valueOf(crl.getNextUpdate()));
            log.log("crl_ok", fields);
        } catch (CrlUnavailableException e) {
            fields.put("error", String.valueOf(e.getMessage()));
            log.log("crl_unavailable", fields);
            System.err.println("WARNING: certificate revocation list unusable (" + e.getMessage()
                    + "). This service fails closed, so every client will be rejected until it is"
                    + " fixed. Regenerate it with server/ca-service/scripts/gen-crl.sh");
        }
    }

    private synchronized X509CRL load() throws CrlUnavailableException {
        if (!Files.exists(crlFile)) {
            throw new CrlUnavailableException("CRL file does not exist: " + crlFile);
        }
        try {
            long mtime = Files.getLastModifiedTime(crlFile).toMillis();
            if (cached == null || mtime != cachedMtime) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509CRL crl;
                try (InputStream in = Files.newInputStream(crlFile)) {
                    crl = (X509CRL) cf.generateCRL(in);
                }
                // Verify before caching, so an unsigned or foreign CRL is never
                // consulted even once.
                crl.verify(caCert.getPublicKey());
                cached = crl;
                cachedMtime = mtime;
            }
        } catch (Exception e) {
            // Drop the cache so a later repair is picked up rather than being
            // shadowed by a stale successful parse.
            cached = null;
            cachedMtime = -1;
            throw new CrlUnavailableException("CRL at " + crlFile + " could not be read or verified: " + e, e);
        }

        java.util.Date nextUpdate = cached.getNextUpdate();
        if (nextUpdate != null) {
            Instant deadline = nextUpdate.toInstant().plus(STALE_GRACE);
            if (Instant.now().isAfter(deadline)) {
                throw new CrlUnavailableException("CRL at " + crlFile + " expired at " + nextUpdate
                        + " (grace " + STALE_GRACE.toHours() + "h); regenerate it with gen-crl.sh");
            }
        }
        return cached;
    }
}
