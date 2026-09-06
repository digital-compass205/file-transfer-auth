package com.filetransfer.common.tls;

import com.filetransfer.common.log.JsonLog;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reports the remaining lifetime of a service's own TLS identity
 * certificate at startup.
 *
 * Client certificates renew themselves (RenewalLoop); these do not. They are
 * operator-issued with a long, explicit lifetime by
 * scripts/issue-server-cert.sh, which means their expiry is a date somebody
 * has to remember months later. Surfacing it on every start turns that into
 * something visible in the log and in journalctl, rather than something
 * discovered when every client's handshake begins failing at once.
 */
public final class ServerIdentityCheck {

    private static final long WARN_BELOW_DAYS = 30;

    private ServerIdentityCheck() {
    }

    public static void logExpiry(JsonLog log, Path serverKeystorePkcs12, char[] keystorePassword) {
        try {
            X509Certificate cert = identityCertificate(serverKeystorePkcs12, keystorePassword);
            if (cert == null) {
                log.log("server_identity_unknown",
                        Map.of("keystore", serverKeystorePkcs12.toString()));
                return;
            }
            Instant notAfter = cert.getNotAfter().toInstant();
            long daysRemaining = Duration.between(Instant.now(), notAfter).toDays();

            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("subject", cert.getSubjectX500Principal().getName());
            fields.put("not_after", notAfter.toString());
            fields.put("days_remaining", daysRemaining);

            if (daysRemaining < 0) {
                log.log("server_identity_expired", fields);
                warn("TLS identity certificate EXPIRED on " + notAfter
                        + " -- every client handshake will fail until it is reissued.");
            } else if (daysRemaining < WARN_BELOW_DAYS) {
                log.log("server_identity_expiring", fields);
                warn("TLS identity certificate expires in " + daysRemaining
                        + " day(s), on " + notAfter + ".");
            } else {
                log.log("server_identity_ok", fields);
            }
        } catch (Exception e) {
            log.log("server_identity_check_failed",
                    Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    private static void warn(String message) {
        System.err.println("WARNING: " + message
                + " Reissue it with server/ca-service/scripts/issue-server-cert.sh");
    }

    private static X509Certificate identityCertificate(Path keystorePath, char[] password)
            throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystorePath)) {
            ks.load(in, password);
        }
        for (String alias : Collections.list(ks.aliases())) {
            if (!ks.isKeyEntry(alias)) {
                continue;
            }
            Certificate[] chain = ks.getCertificateChain(alias);
            if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate leaf) {
                return leaf;
            }
        }
        return null;
    }
}
