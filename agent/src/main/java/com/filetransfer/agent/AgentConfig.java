package com.filetransfer.agent;

import com.filetransfer.common.tls.ClientId;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public final class AgentConfig {

    public final String clientId;
    public final String caServiceUrl;
    public final String receiverUrl;
    public final Path caCertPath;
    public final Path keystorePath;
    public final String keystorePassword;
    public final List<Path> watchFolders;
    public final Path journalPath;
    public final Path logFile;
    public final int stableSeconds;
    public final int pollIntervalSeconds;
    public final int renewalCheckIntervalHours;
    public final long renewalCheckIntervalSeconds;
    public final double renewBelowFraction;
    public final int uploadTimeoutSeconds;

    private AgentConfig(Properties p) {
        // Validated here as well as server-side: client.id ends up in a CSR
        // subject and, on the server, in a filesystem path.
        this.clientId = ClientId.requireValid(require(p, "client.id"));
        this.caServiceUrl = requireHttps(p, "ca.service.url");
        this.receiverUrl = requireHttps(p, "receiver.url");
        this.caCertPath = Path.of(require(p, "ca.cert"));
        this.keystorePath = Path.of(require(p, "keystore.path"));
        this.keystorePassword = require(p, "keystore.password");
        this.journalPath = Path.of(p.getProperty("journal.path", "upload-journal.jsonl"));
        this.logFile = Path.of(p.getProperty("log.file", "agent.jsonl"));
        this.stableSeconds = Integer.parseInt(p.getProperty("watch.stable_seconds", "5"));
        this.pollIntervalSeconds = Integer.parseInt(p.getProperty("watch.poll_interval_seconds", "2"));
        this.renewalCheckIntervalHours = Integer.parseInt(p.getProperty("renew.check_interval_hours", "6"));
        // Both of the following exist so that renewal -- the least
        // observable and most security-critical loop here -- can actually be
        // exercised end to end (spec section 12 asks for two rotation cycles
        // against a shortened lifetime). Neither is expected to be set in a
        // real deployment; scripts/local-demo.sh sets both.
        this.renewalCheckIntervalSeconds = Long.parseLong(p.getProperty(
                "renew.check_interval_seconds", String.valueOf(renewalCheckIntervalHours * 3600L)));
        this.renewBelowFraction = Double.parseDouble(p.getProperty("renew.below_fraction", "0.40"));
        if (renewalCheckIntervalSeconds <= 0) {
            throw new IllegalArgumentException("renew.check_interval_seconds must be positive");
        }
        this.uploadTimeoutSeconds = Integer.parseInt(p.getProperty("upload.timeout_seconds", "3600"));

        this.watchFolders = new ArrayList<>();
        String folders = require(p, "watch.folders");
        for (String f : folders.split(",")) {
            if (!f.isBlank()) {
                watchFolders.add(Path.of(f.trim()));
            }
        }
    }

    /**
     * Every outbound call in this agent is supposed to be TLS with a pinned
     * CA and a hostname check. A URL that is merely mistyped as http:// would
     * quietly bypass all of that, so it is rejected at startup rather than at
     * the first upload.
     */
    private static String requireHttps(Properties p, String key) {
        String v = require(p, key);
        if (!v.startsWith("https://")) {
            throw new IllegalArgumentException(key + " must be an https:// URL, got: " + v);
        }
        return v;
    }

    private static String require(Properties p, String key) {
        String v = p.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("Missing required config property: " + key);
        }
        return v;
    }

    public static AgentConfig load(Path propertiesFile) throws IOException {
        Properties p = new Properties();
        try (InputStream in = java.nio.file.Files.newInputStream(propertiesFile)) {
            p.load(in);
        }
        return new AgentConfig(p);
    }
}
