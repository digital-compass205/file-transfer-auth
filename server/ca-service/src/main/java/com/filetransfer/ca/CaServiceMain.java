package com.filetransfer.ca;

import com.filetransfer.common.log.JsonLog;
import com.filetransfer.common.tls.CrlRevocationChecker;
import com.filetransfer.common.tls.HttpsServerSupport;
import com.filetransfer.common.tls.ServerIdentityCheck;
import com.filetransfer.common.tls.ServerTls;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.nio.file.Path;

public final class CaServiceMain {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: ca-service <path-to-ca-service.properties>");
            System.exit(2);
        }
        CaConfig config = CaConfig.load(Path.of(args[0]));

        SSLContext sslContext = ServerTls.buildSslContext(
                config.serverKeystore, config.serverKeystorePassword.toCharArray(), config.caCertPath);

        JsonLog log = new JsonLog(config.logFile);
        ServerIdentityCheck.logExpiry(log, config.serverKeystore, config.serverKeystorePassword.toCharArray());
        TokenStore tokenStore = new TokenStore(config.tokenStoreFile);
        OpenSslCaInvoker invoker = new OpenSslCaInvoker(
                config.opensslBinary, config.opensslConfig, config.workDir);
        CrlRevocationChecker revocationChecker =
                CrlRevocationChecker.forCa(config.crlPath, config.caCertPath);
        revocationChecker.logStatusAtStartup(log);

        HttpsServer server = HttpsServer.create(new InetSocketAddress(config.port), 0);
        // /enroll has no client cert yet; /renew requires one. Since the JDK's
        // HttpsConfigurator applies before the HTTP path is known, client auth
        // is "wanted" (not "needed") at the TLS layer for the whole server,
        // and RenewHandler itself enforces that a cert was actually presented.
        HttpsServerSupport.configure(server, sslContext, HttpsServerSupport.ClientAuth.WANT);

        server.createContext("/enroll", new EnrollHandler(tokenStore, invoker, log));
        server.createContext("/renew", new RenewHandler(invoker, revocationChecker, log));

        server.start();
        System.out.println("ca-service listening on :" + config.port);
    }
}
