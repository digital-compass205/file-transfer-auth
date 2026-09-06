package com.filetransfer.agent.http;

import com.filetransfer.agent.AgentConfig;
import com.filetransfer.common.http.HttpClients;
import com.filetransfer.common.tls.ClientTls;

import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.security.GeneralSecurityException;

/**
 * Supplies the one mTLS {@link HttpClient} the agent uses for uploads and
 * renewals, rebuilding it only when the keystore actually changes.
 *
 * <p>Two things have to be true at once here, and getting either wrong is a
 * real bug:
 *
 * <ul>
 *   <li>The client must be <strong>reused</strong>. A JDK {@code HttpClient}
 *       owns a selector thread and a connection pool, and has no {@code close()}
 *       before Java 21 -- building one per uploaded file leaks a thread per
 *       file and forces a fresh TLS handshake every time.
 *   <li>The client must <strong>not outlive the certificate it was built
 *       with</strong>. An {@code SSLContext} captures key material when it is
 *       created, so a client cached across a renewal would go on presenting
 *       the superseded certificate until it expired, and then fail every
 *       upload with no obvious cause.
 * </ul>
 *
 * Keying the cache on the keystore file's modification time satisfies both:
 * {@code RenewalLoop} swaps the keystore by atomic rename, which changes the
 * mtime, so the next caller transparently gets a client carrying the new
 * certificate.
 */
public final class AgentHttpClient {

    private final AgentConfig config;

    private HttpClient cached;
    private long cachedKeystoreMtime = -1;

    public AgentHttpClient(AgentConfig config) {
        this.config = config;
    }

    public synchronized HttpClient current() throws IOException, GeneralSecurityException {
        long mtime = Files.getLastModifiedTime(config.keystorePath).toMillis();
        if (cached == null || mtime != cachedKeystoreMtime) {
            cached = HttpClients.create(ClientTls.mutual(
                    config.keystorePath, config.keystorePassword.toCharArray(), config.caCertPath));
            cachedKeystoreMtime = mtime;
        }
        return cached;
    }
}
