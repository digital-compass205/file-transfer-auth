package com.filetransfer.receiver;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Properties;

public final class ReceiverConfig {

    public final int port;
    public final Path serverKeystore;
    public final String serverKeystorePassword;
    public final Path caCertPath;
    public final Path crlPath;
    public final Path incomingDir;
    public final Path quarantineDir;
    public final Path logFile;
    public final long maxUploadBytes;

    private ReceiverConfig(Properties p) {
        this.port = Integer.parseInt(p.getProperty("port", "8443"));
        this.serverKeystore = Path.of(require(p, "server.keystore"));
        this.serverKeystorePassword = require(p, "server.keystore.password");
        this.caCertPath = Path.of(require(p, "ca.cert"));
        this.crlPath = Path.of(require(p, "ca.crl"));
        this.incomingDir = Path.of(require(p, "storage.incoming"));
        this.quarantineDir = Path.of(require(p, "storage.quarantine"));
        this.logFile = Path.of(p.getProperty("log.file", "/var/log/file-receiver/file-receiver.jsonl"));
        this.maxUploadBytes = Long.parseLong(p.getProperty("upload.max_bytes", String.valueOf(2L * 1024 * 1024 * 1024)));
    }

    private static String require(Properties p, String key) {
        String v = p.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("Missing required config property: " + key);
        }
        return v;
    }

    public static ReceiverConfig load(Path propertiesFile) throws IOException {
        Properties p = new Properties();
        try (InputStream in = java.nio.file.Files.newInputStream(propertiesFile)) {
            p.load(in);
        }
        return new ReceiverConfig(p);
    }
}
