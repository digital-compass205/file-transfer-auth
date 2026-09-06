package com.filetransfer.ca;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Properties;

public final class CaConfig {

    public final int port;
    public final Path serverKeystore;
    public final String serverKeystorePassword;
    public final Path opensslConfig;
    public final Path caCertPath;
    public final Path crlPath;
    public final Path workDir;
    public final Path tokenStoreFile;
    public final String opensslBinary;
    public final Path logFile;

    private CaConfig(Properties p) {
        this.port = Integer.parseInt(p.getProperty("port", "9443"));
        this.serverKeystore = Path.of(require(p, "server.keystore"));
        this.serverKeystorePassword = require(p, "server.keystore.password");
        this.opensslConfig = Path.of(require(p, "ca.openssl.config"));
        this.caCertPath = Path.of(require(p, "ca.cert"));
        this.crlPath = Path.of(require(p, "ca.crl"));
        this.workDir = Path.of(require(p, "ca.workdir"));
        this.tokenStoreFile = Path.of(require(p, "ca.tokenstore"));
        this.opensslBinary = p.getProperty("openssl.binary", "openssl");
        this.logFile = Path.of(p.getProperty("log.file", "/var/log/ca-service/ca-service.jsonl"));
    }

    private static String require(Properties p, String key) {
        String v = p.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("Missing required config property: " + key);
        }
        return v;
    }

    public static CaConfig load(Path propertiesFile) throws IOException {
        Properties p = new Properties();
        try (InputStream in = java.nio.file.Files.newInputStream(propertiesFile)) {
            p.load(in);
        }
        return new CaConfig(p);
    }
}
