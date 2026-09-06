package com.filetransfer.receiver;

import com.filetransfer.common.hash.Sha256;
import com.filetransfer.common.http.Responses;
import com.filetransfer.common.json.SimpleJson;
import com.filetransfer.common.log.JsonLog;
import com.filetransfer.common.tls.ClientId;
import com.filetransfer.common.tls.CrlRevocationChecker;
import com.filetransfer.common.tls.PeerIdentity;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * POST /v1/upload. Body framing is a small custom protocol instead of
 * multipart/form-data -- see secure-file-transfer-spec-java.md section 9
 * for why:
 *   [4 bytes big-endian manifest length N]
 *   [N bytes UTF-8 JSON manifest: {"filename","sha256","size_bytes"}]
 *   [size_bytes bytes of raw file content]
 */
public final class UploadHandler implements HttpHandler {

    private static final int MAX_MANIFEST_BYTES = 8 * 1024;

    /**
     * Leaves room for the UUID prefix a quarantined file gets, so the
     * combined name still fits the 255-byte limit of ext4 and friends.
     * Without this, quarantining a long-named file fails on the rename and
     * the upload reports a 500 instead of a hash mismatch.
     */
    private static final int MAX_QUARANTINE_NAME_BYTES = 255 - 37;

    private final ReceiverConfig config;
    private final CrlRevocationChecker revocationChecker;
    private final JsonLog log;

    public UploadHandler(ReceiverConfig config, CrlRevocationChecker revocationChecker, JsonLog log) {
        this.config = config;
        this.revocationChecker = revocationChecker;
        this.log = log;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String remote = exchange.getRemoteAddress().toString();
        String clientId = null;
        String filename = null;
        Path tempFile = null;
        try {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                Responses.sendJson(exchange, 405, Map.of("status", "method_not_allowed"));
                return;
            }

            X509Certificate peerCert = PeerIdentity.peerCertificateOrNull(((HttpsExchange) exchange).getSSLSession());
            if (peerCert == null) {
                log.log("upload_rejected", Map.of("reason", "no_client_cert", "remote", remote));
                Responses.sendJson(exchange, 401, Map.of("status", "client_cert_required"));
                return;
            }
            clientId = PeerIdentity.commonName(peerCert);
            if (clientId == null || !ClientId.isValid(clientId)) {
                log.log("upload_rejected", Map.of("reason", "bad_cert_identity", "remote", remote));
                Responses.sendJson(exchange, 401, Map.of("status", "invalid_client_identity"));
                return;
            }
            try {
                if (revocationChecker.isRevoked(peerCert)) {
                    log.log("upload_rejected", Map.of("reason", "revoked", "client_id", clientId, "remote", remote));
                    Responses.sendJson(exchange, 401, Map.of("status", "revoked"));
                    return;
                }
            } catch (CrlRevocationChecker.CrlUnavailableException crlDown) {
                // Fail closed: without a trustworthy CRL this service cannot
                // tell a good certificate from a revoked one, so it accepts
                // neither.
                log.log("upload_rejected", Map.of("reason", "crl_unavailable", "client_id", clientId,
                        "remote", remote, "error", String.valueOf(crlDown.getMessage())));
                Responses.sendJson(exchange, 503, Map.of("status", "revocation_check_unavailable"));
                return;
            }

            DataInputStream in = new DataInputStream(exchange.getRequestBody());
            int manifestLen;
            byte[] manifestBytes;
            try {
                manifestLen = in.readInt();
                if (manifestLen <= 0 || manifestLen > MAX_MANIFEST_BYTES) {
                    Responses.sendJson(exchange, 400, Map.of("status", "bad_manifest_length"));
                    return;
                }
                manifestBytes = new byte[manifestLen];
                in.readFully(manifestBytes);
            } catch (EOFException truncated) {
                Responses.sendJson(exchange, 400, Map.of("status", "truncated_manifest"));
                return;
            }

            Map<String, String> manifest;
            try {
                manifest = SimpleJson.parseFlatObject(new String(manifestBytes, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException malformed) {
                log.log("upload_rejected", Map.of("reason", "malformed_manifest", "client_id", clientId, "remote", remote));
                Responses.sendJson(exchange, 400, Map.of("status", "bad_manifest"));
                return;
            }

            filename = manifest.get("filename");
            String claimedSha256 = manifest.get("sha256");
            String sizeStr = manifest.get("size_bytes");
            if (filename == null || claimedSha256 == null || sizeStr == null) {
                Responses.sendJson(exchange, 400, Map.of("status", "bad_manifest"));
                return;
            }
            long declaredSize;
            try {
                declaredSize = Long.parseLong(sizeStr);
            } catch (NumberFormatException notANumber) {
                Responses.sendJson(exchange, 400, Map.of("status", "bad_manifest"));
                return;
            }
            if (declaredSize < 0 || declaredSize > config.maxUploadBytes) {
                log.log("upload_rejected", Map.of("reason", "too_large", "client_id", clientId, "filename", filename, "remote", remote));
                Responses.sendJson(exchange, 413, Map.of("status", "too_large"));
                return;
            }

            Path targetPath;
            try {
                targetPath = PathSanitizer.resolveUploadPath(config.incomingDir, clientId, filename);
            } catch (IllegalArgumentException badPath) {
                log.log("upload_rejected", Map.of("reason", "bad_filename", "client_id", clientId, "filename", String.valueOf(filename), "remote", remote));
                Responses.sendJson(exchange, 400, Map.of("status", "bad_filename"));
                return;
            }

            Path clientQuarantineDir = config.quarantineDir.resolve(clientId);
            Files.createDirectories(targetPath.getParent());
            Files.createDirectories(clientQuarantineDir);

            // Now that the directory exists, confirm it really is the client's
            // own directory and not a symlink out of the storage root -- the
            // check the lexical pass above cannot make.
            try {
                PathSanitizer.verifyRealPathContained(config.incomingDir, clientId, targetPath);
            } catch (IllegalArgumentException escapes) {
                log.log("upload_rejected", Map.of("reason", "path_escapes_storage_root",
                        "client_id", clientId, "filename", filename, "remote", remote,
                        "detail", String.valueOf(escapes.getMessage())));
                Responses.sendJson(exchange, 400, Map.of("status", "bad_filename"));
                return;
            }

            tempFile = Files.createTempFile(targetPath.getParent(), "upload-", ".tmp");
            String actualSha256;
            long actualSize;
            boolean complete;
            try (OutputStream out = Files.newOutputStream(tempFile)) {
                MessageDigest digest = Sha256.newDigest();
                actualSize = copyAtMost(in, out, digest, declaredSize);
                actualSha256 = Sha256.hex(digest.digest());
                complete = actualSize == declaredSize;
            }

            // A stream that ended early is a failed transfer, not a server
            // error: it belongs in quarantine with the mismatch recorded,
            // exactly like a wrong hash.
            if (!complete || !actualSha256.equalsIgnoreCase(claimedSha256)) {
                Path quarantined = clientQuarantineDir.resolve(
                        UUID.randomUUID() + "-" + truncateForQuarantine(filename));
                Files.move(tempFile, quarantined, StandardCopyOption.REPLACE_EXISTING);
                tempFile = null; // moved; nothing left to clean up
                Map<String, Object> quarantineLog = new LinkedHashMap<>();
                quarantineLog.put("client_id", clientId);
                quarantineLog.put("filename", filename);
                quarantineLog.put("remote", remote);
                quarantineLog.put("reason", complete ? "hash_mismatch" : "short_stream");
                quarantineLog.put("declared_sha256", claimedSha256);
                quarantineLog.put("actual_sha256", actualSha256);
                quarantineLog.put("declared_size", declaredSize);
                quarantineLog.put("actual_size", actualSize);
                log.log("upload_quarantined", quarantineLog);
                Responses.sendJson(exchange, 422,
                        Map.of("status", complete ? "hash_mismatch" : "incomplete_upload"));
                return;
            }

            Files.move(tempFile, targetPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            tempFile = null; // moved
            log.log("upload_ok", Map.of(
                    "client_id", clientId, "filename", filename, "remote", remote,
                    "sha256", actualSha256, "size", actualSize));
            Responses.sendJson(exchange, 200, Map.of("status", "ok", "sha256", actualSha256));
        } catch (Exception e) {
            log.log("upload_error", Map.of(
                    "error", String.valueOf(e.getMessage()), "remote", remote,
                    "client_id", String.valueOf(clientId), "filename", String.valueOf(filename)));
            Responses.sendJson(exchange, 500, Map.of("status", "internal_error"));
        } finally {
            // Any path that did not move the temp file into place has to remove
            // it. Otherwise a client that declares a large size and then
            // disconnects leaves a .tmp file behind on every attempt, in the
            // same directory as its real deliveries.
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException cleanupFailed) {
                    log.log("upload_temp_cleanup_failed", Map.of(
                            "path", tempFile.toString(),
                            "error", String.valueOf(cleanupFailed.getMessage())));
                }
            }
        }
    }

    /**
     * Shortens a filename so that a UUID prefix plus this still fits a 255-byte
     * name, measuring in UTF-8 bytes rather than characters because that is
     * what the filesystem limit counts.
     */
    private static String truncateForQuarantine(String filename) {
        byte[] bytes = filename.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= MAX_QUARANTINE_NAME_BYTES) {
            return filename;
        }
        // Trim characters (not bytes) so the result never ends mid-codepoint.
        String truncated = filename;
        while (truncated.getBytes(StandardCharsets.UTF_8).length > MAX_QUARANTINE_NAME_BYTES) {
            truncated = truncated.substring(0, truncated.length() - 1);
        }
        return truncated;
    }

    /**
     * Reads up to {@code count} bytes from in, writing to out and updating
     * digest, and returns how many actually arrived. A caller comparing the
     * result against {@code count} learns whether the stream ended early --
     * which is why this does not throw on a short read.
     */
    private static long copyAtMost(InputStream in, OutputStream out, MessageDigest digest, long count) throws IOException {
        byte[] buf = new byte[64 * 1024];
        long remaining = count;
        while (remaining > 0) {
            int toRead = (int) Math.min(buf.length, remaining);
            int n = in.read(buf, 0, toRead);
            if (n < 0) {
                break;
            }
            out.write(buf, 0, n);
            digest.update(buf, 0, n);
            remaining -= n;
        }
        return count - remaining;
    }
}
