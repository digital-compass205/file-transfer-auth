package com.filetransfer.agent.upload;

import com.filetransfer.agent.AgentConfig;
import com.filetransfer.agent.http.AgentHttpClient;
import com.filetransfer.common.hash.Sha256;
import com.filetransfer.common.json.SimpleJson;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Uploads one file using the custom length-prefixed framing described in
 * spec section 9: [4-byte manifest length][JSON manifest][raw file bytes].
 */
public final class UploadClient {

    private final AgentConfig config;
    private final AgentHttpClient httpClient;

    public UploadClient(AgentConfig config, AgentHttpClient httpClient) {
        this.config = config;
        this.httpClient = httpClient;
    }

    public String upload(Path file) throws Exception {
        String sha256 = Sha256.ofFile(file);
        long size = Files.size(file);

        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("filename", file.getFileName().toString());
        manifest.put("sha256", sha256);
        manifest.put("size_bytes", size);
        byte[] manifestBytes = SimpleJson.writeFlatObject(manifest).getBytes(StandardCharsets.UTF_8);

        byte[] header = ByteBuffer.allocate(4 + manifestBytes.length)
                .putInt(manifestBytes.length)
                .put(manifestBytes)
                .array();

        HttpRequest.BodyPublisher body = HttpRequest.BodyPublishers.concat(
                HttpRequest.BodyPublishers.ofByteArray(header),
                HttpRequest.BodyPublishers.ofFile(file));

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(config.receiverUrl + "/v1/upload"))
                .header("Content-Type", "application/octet-stream")
                // Bounds a receiver that accepts the connection and then stalls.
                // Generous, because a large file over a slow link is a legitimate
                // long request -- the point is that it cannot hang forever and
                // wedge the single-threaded watcher poll behind it.
                .timeout(Duration.ofSeconds(config.uploadTimeoutSeconds))
                .POST(body)
                .build();
        HttpResponse<String> resp = httpClient.current().send(req, HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() != 200) {
            throw new UploadException("Upload failed: HTTP " + resp.statusCode() + " " + resp.body());
        }
        Map<String, String> respJson = SimpleJson.parseFlatObject(resp.body());
        return respJson.get("sha256");
    }

    public static final class UploadException extends Exception {
        public UploadException(String message) {
            super(message);
        }
    }
}
