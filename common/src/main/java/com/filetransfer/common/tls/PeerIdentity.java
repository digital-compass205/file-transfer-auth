package com.filetransfer.common.tls;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Extracts the client's identity from the TLS-verified peer certificate.
 * Callers must never accept a client-asserted identity from a request body
 * instead of this — the whole point of mTLS here is that identity comes
 * only from what the CA signed.
 */
public final class PeerIdentity {

    private PeerIdentity() {
    }

    /** Returns null if the peer presented no certificate (optional client auth). */
    public static X509Certificate peerCertificateOrNull(SSLSession session) {
        try {
            Certificate[] certs = session.getPeerCertificates();
            if (certs.length == 0 || !(certs[0] instanceof X509Certificate)) {
                return null;
            }
            return (X509Certificate) certs[0];
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }

    /** Returns the CN of the peer certificate's subject, or null if absent/no cert. */
    public static String clientIdFromSession(SSLSession session) {
        X509Certificate cert = peerCertificateOrNull(session);
        if (cert == null) {
            return null;
        }
        return commonName(cert);
    }

    public static String commonName(X509Certificate cert) {
        try {
            LdapName dn = new LdapName(cert.getSubjectX500Principal().getName());
            for (Rdn rdn : dn.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return String.valueOf(rdn.getValue());
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
