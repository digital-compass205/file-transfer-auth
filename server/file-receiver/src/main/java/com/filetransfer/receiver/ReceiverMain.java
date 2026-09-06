package com.filetransfer.receiver;

import com.filetransfer.common.log.JsonLog;
import com.filetransfer.common.tls.CrlRevocationChecker;
import com.filetransfer.common.tls.HttpsServerSupport;
import com.filetransfer.common.tls.ServerIdentityCheck;
import com.filetransfer.common.tls.ServerTls;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.nio.file.Path;

public final class ReceiverMain {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: file-receiver <path-to-receiver.properties>");
            System.exit(2);
        }
        ReceiverConfig config = ReceiverConfig.load(Path.of(args[0]));

        SSLContext sslContext = ServerTls.buildSslContext(
                config.serverKeystore, config.serverKeystorePassword.toCharArray(), config.caCertPath);

        JsonLog log = new JsonLog(config.logFile);
        ServerIdentityCheck.logExpiry(log, config.serverKeystore, config.serverKeystorePassword.toCharArray());
        CrlRevocationChecker revocationChecker =
                CrlRevocationChecker.forCa(config.crlPath, config.caCertPath);
        revocationChecker.logStatusAtStartup(log);

        HttpsServer server = HttpsServer.create(new InetSocketAddress(config.port), 0);
        // Every endpoint on this service requires mTLS -- unlike ca-service,
        // there's no bootstrap endpoint that has to tolerate an absent cert.
        HttpsServerSupport.configure(server, sslContext, HttpsServerSupport.ClientAuth.NEED);

        server.createContext("/v1/upload", new UploadHandler(config, revocationChecker, log));

        server.start();
        System.out.println("file-receiver listening on :" + config.port);
    }
}
