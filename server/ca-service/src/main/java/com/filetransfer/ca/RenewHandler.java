package com.filetransfer.ca;

import com.filetransfer.common.http.Bodies;
import com.filetransfer.common.http.Responses;
import com.filetransfer.common.json.SimpleJson;
import com.filetransfer.common.log.JsonLog;
import com.filetransfer.common.tls.ClientId;
import com.filetransfer.common.tls.CrlRevocationChecker;
import com.filetransfer.common.tls.PeerIdentity;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * POST /renew -- requires mTLS with the client's current, still-valid cert.
 * The renewed cert's identity is taken from that verified peer certificate,
 * never from the request body: a client authenticated as "alice" cannot ask
 * to be renewed as "bob".
 */
public final class RenewHandler implements HttpHandler {

    private static final int MAX_BODY_BYTES = 16 * 1024;

    private final OpenSslCaInvoker invoker;
    private final CrlRevocationChecker revocationChecker;
    private final JsonLog log;

    public RenewHandler(OpenSslCaInvoker invoker, CrlRevocationChecker revocationChecker, JsonLog log) {
        this.invoker = invoker;
        this.revocationChecker = revocationChecker;
        this.log = log;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String remote = exchange.getRemoteAddress().toString();
        try {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                Responses.sendJson(exchange, 405, Map.of("status", "method_not_allowed"));
                return;
            }

            X509Certificate peerCert = PeerIdentity.peerCertificateOrNull(((HttpsExchange) exchange).getSSLSession());
            if (peerCert == null) {
                log.log("renew_rejected", Map.of("reason", "no_client_cert", "remote", remote));
                Responses.sendJson(exchange, 401, Map.of("status", "client_cert_required"));
                return;
            }
            String clientId = PeerIdentity.commonName(peerCert);
            if (clientId == null || !ClientId.isValid(clientId)) {
                log.log("renew_rejected", Map.of("reason", "bad_cert_identity", "remote", remote));
                Responses.sendJson(exchange, 401, Map.of("status", "invalid_client_identity"));
                return;
            }
            try {
                if (revocationChecker.isRevoked(peerCert)) {
                    log.log("renew_rejected", Map.of("reason", "revoked", "client_id", clientId, "remote", remote));
                    Responses.sendJson(exchange, 401, Map.of("status", "revoked"));
                    return;
                }
            } catch (CrlRevocationChecker.CrlUnavailableException crlDown) {
                // Fail closed: with no trustworthy CRL there is no way to know
                // this certificate has not been revoked, so it is not renewed.
                log.log("renew_rejected", Map.of("reason", "crl_unavailable", "client_id", clientId,
                        "remote", remote, "error", String.valueOf(crlDown.getMessage())));
                Responses.sendJson(exchange, 503, Map.of("status", "revocation_check_unavailable"));
                return;
            }

            byte[] body = Bodies.readAllLimited(exchange.getRequestBody(), MAX_BODY_BYTES);
            Map<String, String> req;
            try {
                req = SimpleJson.parseFlatObject(new String(body, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException malformed) {
                Responses.sendJson(exchange, 400, Map.of("status", "bad_request"));
                return;
            }
            String csrPem = req.get("csr_pem");
            if (csrPem == null) {
                Responses.sendJson(exchange, 400, Map.of("status", "bad_request"));
                return;
            }

            OpenSslCaInvoker.SignedCert signed;
            try {
                signed = invoker.sign(csrPem, clientId);
            } catch (OpenSslCaInvoker.InvalidCsrException badCsr) {
                log.log("renew_rejected", Map.of("reason", "invalid_csr", "client_id", clientId,
                        "remote", remote, "detail", String.valueOf(badCsr.getMessage())));
                Responses.sendJson(exchange, 400, Map.of("status", "invalid_csr"));
                return;
            }

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("status", "ok");
            resp.put("cert_pem", signed.certPem);
            log.log("renew_ok", Map.of("client_id", clientId, "remote", remote));
            Responses.sendJson(exchange, 200, resp);
        } catch (Exception e) {
            log.log("renew_error", Map.of("error", String.valueOf(e.getMessage()), "remote", remote));
            Responses.sendJson(exchange, 500, Map.of("status", "internal_error"));
        }
    }
}
