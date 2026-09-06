package com.filetransfer.common.http;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.net.http.HttpClient;
import java.time.Duration;

public final class HttpClients {

    /**
     * Timeout for the small request/response exchanges (enrollment, renewal).
     * connectTimeout alone is not enough: it only bounds establishing the TCP
     * connection. A server that accepts a connection and then stalls would
     * otherwise block the calling thread forever -- and both callers here run
     * on single-threaded scheduled executors, so one stalled request
     * permanently stops renewal, or stops every later upload.
     */
    public static final Duration CONTROL_REQUEST_TIMEOUT = Duration.ofSeconds(60);

    private HttpClients() {
    }

    public static HttpClient create(SSLContext sslContext) {
        // Start from the context's own defaults rather than a blank
        // SSLParameters: a blank one leaves every field unset, which would
        // silently discard the JDK's vetted cipher-suite selection.
        SSLParameters params = sslContext.getDefaultSSLParameters();
        params.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        // Bind the presented certificate to the hostname actually dialed.
        // Chain validation alone only proves the internal CA issued *some*
        // certificate; this is what makes it the certificate for *this*
        // server. Supplying custom SSLParameters replaces the client's
        // defaults wholesale, so this has to be set explicitly here.
        params.setEndpointIdentificationAlgorithm("HTTPS");
        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .sslParameters(params)
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }
}
