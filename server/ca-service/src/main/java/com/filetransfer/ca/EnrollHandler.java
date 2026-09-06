package com.filetransfer.ca;

import com.filetransfer.common.http.Bodies;
import com.filetransfer.common.http.Responses;
import com.filetransfer.common.json.SimpleJson;
import com.filetransfer.common.log.JsonLog;
import com.filetransfer.common.tls.ClientId;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * POST /enroll -- no client certificate exists yet, so this endpoint is
 * TLS-server-auth only. The one-time token is what stands in for identity
 * proof here; everything after this call relies on the client's own key.
 */
public final class EnrollHandler implements HttpHandler {

    private static final int MAX_BODY_BYTES = 16 * 1024;

    private final TokenStore tokenStore;
    private final OpenSslCaInvoker invoker;
    private final JsonLog log;

    public EnrollHandler(TokenStore tokenStore, OpenSslCaInvoker invoker, JsonLog log) {
        this.tokenStore = tokenStore;
        this.invoker = invoker;
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
            byte[] body = Bodies.readAllLimited(exchange.getRequestBody(), MAX_BODY_BYTES);

            Map<String, String> req;
            try {
                req = SimpleJson.parseFlatObject(new String(body, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException malformed) {
                // A malformed body is the caller's mistake, not ours: answer 400
                // rather than letting it fall through to the 500 handler below.
                log.log("enroll_rejected", Map.of("reason", "malformed_json", "remote", remote));
                Responses.sendJson(exchange, 400, Map.of("status", "bad_request"));
                return;
            }

            String token = req.get("token");
            String clientId = req.get("client_id");
            String csrPem = req.get("csr_pem");

            if (token == null || clientId == null || csrPem == null || !ClientId.isValid(clientId)) {
                log.log("enroll_rejected", Map.of("reason", "bad_request", "remote", remote));
                Responses.sendJson(exchange, 400, Map.of("status", "bad_request"));
                return;
            }

            if (!tokenStore.consume(token, clientId)) {
                log.log("enroll_rejected", Map.of("reason", "invalid_token", "client_id", clientId, "remote", remote));
                Responses.sendJson(exchange, 403, Map.of("status", "invalid_or_expired_token"));
                return;
            }

            OpenSslCaInvoker.SignedCert signed;
            try {
                signed = invoker.sign(csrPem, clientId);
            } catch (OpenSslCaInvoker.InvalidCsrException badCsr) {
                // The token was marked used a moment ago to close the window on a
                // concurrent second attempt. The CSR turned out to be the problem,
                // so give the token back rather than burning the client's single
                // chance to enroll on a request it can simply retry.
                tokenStore.release(token, clientId);
                log.log("enroll_rejected", Map.of("reason", "invalid_csr", "client_id", clientId,
                        "remote", remote, "detail", String.valueOf(badCsr.getMessage())));
                Responses.sendJson(exchange, 400, Map.of("status", "invalid_csr"));
                return;
            } catch (Exception signingFailed) {
                // Same reasoning, for a CA-side failure: an openssl outage must not
                // consume the token and force the operator to mint a new one.
                tokenStore.release(token, clientId);
                log.log("enroll_error", Map.of("reason", "signing_failed", "client_id", clientId,
                        "remote", remote, "error", String.valueOf(signingFailed.getMessage())));
                Responses.sendJson(exchange, 500, Map.of("status", "internal_error"));
                return;
            }

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("status", "ok");
            resp.put("cert_pem", signed.certPem);
            log.log("enroll_ok", Map.of("client_id", clientId, "remote", remote));
            Responses.sendJson(exchange, 200, resp);
        } catch (Exception e) {
            log.log("enroll_error", Map.of("error", String.valueOf(e.getMessage()), "remote", remote));
            Responses.sendJson(exchange, 500, Map.of("status", "internal_error"));
        }
    }
}
