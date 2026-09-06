package com.filetransfer.common.tls;

import java.util.regex.Pattern;

/**
 * client_id is embedded verbatim into an OpenSSL {@code -subj "/CN=<client_id>"}
 * argument (see OpenSslCaInvoker) and into filesystem paths (see PathSanitizer).
 * The {@code -subj} mini-DSL uses "/" as an RDN separator, so an unvalidated
 * client_id containing "/" (or other metacharacters) could inject extra
 * subject fields into a signed certificate. Restricting to a conservative
 * allow-list charset up front removes that class of bug everywhere client_id
 * is used, not just at the CA boundary.
 *
 * <p>The charset alone is not sufficient, because "." and ".." are built from
 * allowed characters yet carry meaning as path components: a client_id of
 * ".." would make PathSanitizer resolve the "client directory" to the parent
 * of the upload root, so its containment check would then pass against an
 * already-escaped base. Both are rejected explicitly below.
 */
public final class ClientId {

    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    private ClientId() {
    }

    public static boolean isValid(String clientId) {
        if (clientId == null || !VALID.matcher(clientId).matches()) {
            return false;
        }
        // Reject the two names that are path components rather than names.
        return !clientId.equals(".") && !clientId.equals("..");
    }

    public static String requireValid(String clientId) {
        if (!isValid(clientId)) {
            throw new IllegalArgumentException("Invalid client_id: " + clientId);
        }
        return clientId;
    }
}
