package com.filetransfer.agent.enroll;

import com.filetransfer.agent.AgentConfig;
import com.filetransfer.agent.crypto.CsrBuilder;
import com.filetransfer.agent.keystore.ClientKeyStore;
import com.filetransfer.common.http.HttpClients;
import com.filetransfer.common.json.SimpleJson;
import com.filetransfer.common.tls.ClientTls;
import com.filetransfer.common.tls.PeerIdentity;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * First-run enrollment (spec section 6): generate a keypair + CSR locally,
 * exchange a one-time token for a signed cert, store the result. The token
 * is single-use -- after this call succeeds, all further trust comes from
 * the agent's own private key.
 *
 * <p>The CA root the agent trusts from here on is the one bundled with the
 * installer at {@code ca.cert}, never anything in this response. A trust
 * anchor learned from the very exchange it is supposed to secure would be
 * no anchor at all, so the enrollment response deliberately carries only
 * the issued certificate.
 */
public final class EnrollmentClient {

    private final AgentConfig config;

    public EnrollmentClient(AgentConfig config) {
        this.config = config;
    }

    public void enroll(String oneTimeToken) throws Exception {
        CsrBuilder.KeyAndCsr keyAndCsr = CsrBuilder.generate(config.clientId);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("token", oneTimeToken);
        request.put("client_id", config.clientId);
        request.put("csr_pem", keyAndCsr.csrPem);
        String body = SimpleJson.writeFlatObject(request);

        HttpClient client = HttpClients.create(ClientTls.trustOnly(config.caCertPath));
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(config.caServiceUrl + "/enroll"))
                .header("Content-Type", "application/json")
                .timeout(HttpClients.CONTROL_REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() != 200) {
            throw new EnrollmentException("Enrollment failed: HTTP " + resp.statusCode() + " " + resp.body());
        }
        Map<String, String> respJson = SimpleJson.parseFlatObject(resp.body());
        String certPem = respJson.get("cert_pem");
        if (certPem == null) {
            throw new EnrollmentException("Enrollment response missing cert_pem");
        }

        X509Certificate[] chain = ClientKeyStore.parseCertChain(certPem);
        verifyIssuedCert(chain, keyAndCsr);
        ClientKeyStore.store(config.keystorePath, config.keystorePassword.toCharArray(),
                keyAndCsr.keyPair.getPrivate(), chain);
    }

    /**
     * Checks the issued certificate really belongs to the key just generated,
     * names this client, and was signed by the pinned CA root -- before it is
     * committed to the keystore. Otherwise a mismatch produces a keystore
     * whose key and certificate disagree, which surfaces much later as an
     * unexplained handshake failure rather than a failed enrollment.
     */
    private void verifyIssuedCert(X509Certificate[] chain, CsrBuilder.KeyAndCsr keyAndCsr) throws Exception {
        if (chain.length == 0) {
            throw new EnrollmentException("Enrollment response contained no certificate");
        }
        X509Certificate leaf = chain[0];
        if (!leaf.getPublicKey().equals(keyAndCsr.keyPair.getPublic())) {
            throw new EnrollmentException("Issued certificate does not match the key just generated");
        }
        String cn = PeerIdentity.commonName(leaf);
        if (!config.clientId.equals(cn)) {
            throw new EnrollmentException("Issued certificate is for CN=" + cn
                    + ", expected " + config.clientId);
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert;
        try (InputStream in = Files.newInputStream(config.caCertPath)) {
            caCert = (X509Certificate) cf.generateCertificate(in);
        }
        try {
            leaf.verify(caCert.getPublicKey());
        } catch (Exception e) {
            throw new EnrollmentException("Issued certificate was not signed by the pinned CA root at "
                    + config.caCertPath + ": " + e);
        }
    }

    public static final class EnrollmentException extends Exception {
        public EnrollmentException(String message) {
            super(message);
        }
    }
}
