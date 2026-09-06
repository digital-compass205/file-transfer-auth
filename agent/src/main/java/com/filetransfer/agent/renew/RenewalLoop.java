package com.filetransfer.agent.renew;

import com.filetransfer.agent.AgentConfig;
import com.filetransfer.agent.crypto.CsrBuilder;
import com.filetransfer.agent.http.AgentHttpClient;
import com.filetransfer.agent.keystore.ClientKeyStore;
import com.filetransfer.common.http.HttpClients;
import com.filetransfer.common.json.SimpleJson;
import com.filetransfer.common.log.JsonLog;
import com.filetransfer.common.tls.PeerIdentity;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Background renewal ticker (spec section 7). Renews once remaining cert
 * lifetime drops below 40%, rotating keys on every renewal. Never leaves
 * the agent with no valid cert on disk -- keeps using the old cert until it
 * actually expires if renewal keeps failing.
 */
public final class RenewalLoop {

    private static final int MAX_RETRIES_PER_ATTEMPT = 5;

    private final AgentConfig config;
    private final JsonLog log;
    private final AgentHttpClient httpClient;
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "renewal-loop");
        t.setDaemon(true);
        return t;
    });

    public RenewalLoop(AgentConfig config, JsonLog log, AgentHttpClient httpClient) {
        this.config = config;
        this.log = log;
        this.httpClient = httpClient;
    }

    public void start() {
        executor.scheduleWithFixedDelay(this::checkAndMaybeRenew, 0,
                config.renewalCheckIntervalSeconds, TimeUnit.SECONDS);
    }

    public void stop() {
        executor.shutdownNow();
    }

    private void checkAndMaybeRenew() {
        try {
            ClientKeyStore.Identity identity = ClientKeyStore.load(config.keystorePath, config.keystorePassword.toCharArray());
            X509Certificate cert = identity.clientCert();
            Instant notBefore = cert.getNotBefore().toInstant();
            Instant notAfter = cert.getNotAfter().toInstant();
            Instant now = Instant.now();

            long totalSeconds = Duration.between(notBefore, notAfter).getSeconds();
            long remainingSeconds = Duration.between(now, notAfter).getSeconds();

            if (remainingSeconds <= 0) {
                log.log("renewal_cert_expired", Map.of("client_id", config.clientId));
                return; // fail closed: agent's upload path checks cert validity separately and will stop uploading
            }
            if (remainingSeconds > (long) (totalSeconds * config.renewBelowFraction)) {
                return; // not due yet
            }

            attemptRenewalWithBackoff();
        } catch (Exception e) {
            log.log("renewal_check_error", Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    private void attemptRenewalWithBackoff() {
        long backoffMillis = 1000;
        for (int attempt = 1; attempt <= MAX_RETRIES_PER_ATTEMPT; attempt++) {
            try {
                renewOnce();
                log.log("renewal_ok", Map.of("client_id", config.clientId, "attempt", attempt));
                return;
            } catch (Exception e) {
                log.log("renewal_attempt_failed", Map.of(
                        "client_id", config.clientId, "attempt", attempt, "error", String.valueOf(e.getMessage())));
                if (attempt == MAX_RETRIES_PER_ATTEMPT) {
                    log.log("renewal_failed_will_retry_next_tick", Map.of("client_id", config.clientId));
                    return;
                }
                sleep(backoffMillis);
                backoffMillis = Math.min(backoffMillis * 2, 60_000);
            }
        }
    }

    private void renewOnce() throws Exception {
        // AgentHttpClient presents the still-valid keystore on disk to
        // authenticate this call -- that's the proof of "I'm allowed to renew".
        CsrBuilder.KeyAndCsr keyAndCsr = CsrBuilder.generate(config.clientId);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("csr_pem", keyAndCsr.csrPem);
        String body = SimpleJson.writeFlatObject(request);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(config.caServiceUrl + "/renew"))
                .header("Content-Type", "application/json")
                .timeout(HttpClients.CONTROL_REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> resp = httpClient.current().send(req, HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() != 200) {
            throw new IllegalStateException("Renewal failed: HTTP " + resp.statusCode() + " " + resp.body());
        }
        Map<String, String> respJson = SimpleJson.parseFlatObject(resp.body());
        String certPem = respJson.get("cert_pem");
        if (certPem == null) {
            throw new IllegalStateException("Renewal response missing cert_pem");
        }

        X509Certificate[] newChain = ClientKeyStore.parseCertChain(certPem);
        verifyIssuedCert(newChain, keyAndCsr);
        // Atomic swap (temp file + rename inside ClientKeyStore.store) -- the
        // agent is never left without a valid keystore on disk mid-renewal.
        // The mtime change is also what makes AgentHttpClient rebuild its
        // client against the new certificate on the next call.
        ClientKeyStore.store(config.keystorePath, config.keystorePassword.toCharArray(), keyAndCsr.keyPair.getPrivate(), newChain);
    }

    /**
     * Refuses to install a certificate that does not actually match the key
     * just generated, or that names a different client. The CA is
     * authenticated, so this is not defending against a hostile server -- it
     * is making a mismatch fail loudly here, while the previous keystore is
     * still intact, instead of silently producing a keystore whose key and
     * certificate disagree and whose every later handshake fails.
     */
    private void verifyIssuedCert(X509Certificate[] chain, CsrBuilder.KeyAndCsr keyAndCsr) {
        if (chain.length == 0) {
            throw new IllegalStateException("Renewal response contained no certificate");
        }
        if (!chain[0].getPublicKey().equals(keyAndCsr.keyPair.getPublic())) {
            throw new IllegalStateException("Renewed certificate does not match the key just generated");
        }
        String cn = PeerIdentity.commonName(chain[0]);
        if (!config.clientId.equals(cn)) {
            throw new IllegalStateException(
                    "Renewed certificate is for CN=" + cn + ", expected " + config.clientId);
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
