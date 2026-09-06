package com.filetransfer.ca;

import java.nio.file.Path;

/**
 * Run by an operator, after authenticating through the existing MFA'd
 * server login, to mint a one-time enrollment token for a client_id. See
 * scripts/issue-token.sh. Deliberately has no auth of its own — the login
 * session that got the operator a shell on this host is the trust boundary.
 */
public final class IssueTokenCli {

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3) {
            System.err.println("Usage: issue-token <ca-service.properties> <client_id> [validity_hours=24]");
            System.exit(2);
        }
        CaConfig config = CaConfig.load(Path.of(args[0]));
        String clientId = args[1];
        long hours = args.length == 3 ? Long.parseLong(args[2]) : 24;

        TokenStore tokenStore = new TokenStore(config.tokenStoreFile);
        String token = tokenStore.issue(clientId, hours);
        System.out.println("client_id: " + clientId);
        System.out.println("token:     " + token);
        System.out.println("expires:   in " + hours + "h");
    }
}
