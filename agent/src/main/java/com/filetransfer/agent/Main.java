package com.filetransfer.agent;

import com.filetransfer.agent.enroll.EnrollmentClient;
import com.filetransfer.agent.http.AgentHttpClient;
import com.filetransfer.agent.keystore.ClientKeyStore;
import com.filetransfer.agent.queue.UploadJournal;
import com.filetransfer.agent.renew.RenewalLoop;
import com.filetransfer.agent.upload.UploadClient;
import com.filetransfer.agent.watch.FolderWatcher;
import com.filetransfer.common.log.JsonLog;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/**
 * Started by hand for this prototype (no service-wrapper packaging yet --
 * see spec section 13). Usage:
 *   java -jar agent.jar <agent.properties>                 # normal run
 *   java -jar agent.jar <agent.properties> <one-time-token> # first-run enrollment, then run
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) {
            System.err.println("Usage: agent <agent.properties> [one-time-enrollment-token]");
            System.exit(2);
        }
        AgentConfig config = AgentConfig.load(Path.of(args[0]));
        JsonLog log = new JsonLog(config.logFile);

        if (!ClientKeyStore.exists(config.keystorePath)) {
            if (args.length != 2) {
                System.err.println("No keystore found at " + config.keystorePath
                        + " -- pass the one-time enrollment token as the second argument.");
                System.exit(2);
            }
            System.out.println("Enrolling client_id=" + config.clientId + " ...");
            new EnrollmentClient(config).enroll(args[1]);
            log.log("enrolled", java.util.Map.of("client_id", config.clientId));
            System.out.println("Enrollment complete.");
        }

        UploadJournal journal = new UploadJournal(config.journalPath);
        // One mTLS client shared by uploads and renewals; it rebuilds itself
        // when RenewalLoop swaps the keystore. See AgentHttpClient.
        AgentHttpClient httpClient = new AgentHttpClient(config);
        UploadClient uploadClient = new UploadClient(config, httpClient);
        FolderWatcher watcher = new FolderWatcher(config, journal, uploadClient, log);
        RenewalLoop renewalLoop = new RenewalLoop(config, log, httpClient);

        watcher.start();
        renewalLoop.start();
        log.log("agent_started", java.util.Map.of("client_id", config.clientId));
        System.out.println("Agent running for client_id=" + config.clientId + ". Ctrl+C to stop.");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            watcher.stop();
            renewalLoop.stop();
            log.log("agent_stopped", java.util.Map.of("client_id", config.clientId));
        }));

        new CountDownLatch(1).await(); // run until killed
    }
}
