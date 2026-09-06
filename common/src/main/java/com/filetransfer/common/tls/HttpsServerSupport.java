package com.filetransfer.common.tls;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * Wires an SSLContext into a JDK HttpsServer with TLS 1.2+ only and the
 * requested client-auth mode. mTLS enforcement here is entirely a config
 * setting on the JDK's built-in server, not custom TLS handling.
 */
public final class HttpsServerSupport {

    public enum ClientAuth { NONE, WANT, NEED }

    private HttpsServerSupport() {
    }

    public static void configure(HttpsServer server, SSLContext sslContext, ClientAuth clientAuth) {
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters sslParameters = getSSLContext().getDefaultSSLParameters();
                sslParameters.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                switch (clientAuth) {
                    case NEED -> sslParameters.setNeedClientAuth(true);
                    case WANT -> sslParameters.setWantClientAuth(true);
                    case NONE -> { /* no client auth requested */ }
                }
                params.setSSLParameters(sslParameters);
            }
        });
    }
}
