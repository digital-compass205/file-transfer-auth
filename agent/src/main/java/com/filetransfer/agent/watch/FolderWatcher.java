package com.filetransfer.agent.watch;

import com.filetransfer.agent.AgentConfig;
import com.filetransfer.agent.queue.UploadJournal;
import com.filetransfer.agent.upload.UploadClient;
import com.filetransfer.common.log.JsonLog;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Watches configured folders, waits for a file to stop changing size before
 * treating it as complete (spec section 10), then hands it to UploadClient.
 * Failed uploads stay candidates and are retried on the next poll tick with
 * a simple per-file exponential backoff -- files are never silently dropped.
 *
 * <p>Symbolic links are deliberately not followed. The stated boundary of
 * this agent is the folders it was configured to watch, and anyone able to
 * drop a file into a watched folder can also drop a symlink into it;
 * following one would turn the agent into a reader of arbitrary files its
 * account can reach, which is exactly the surface it is supposed not to have.
 */
public final class FolderWatcher {

    private static final long MAX_BACKOFF_SECONDS = 300;

    private final AgentConfig config;
    private final UploadJournal journal;
    private final UploadClient uploadClient;
    private final JsonLog log;

    private final Map<Path, Candidate> candidates = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "folder-watcher-poll");
        t.setDaemon(true);
        return t;
    });
    private WatchService watchService;
    private Thread watchThread;

    public FolderWatcher(AgentConfig config, UploadJournal journal, UploadClient uploadClient, JsonLog log) {
        this.config = config;
        this.journal = journal;
        this.uploadClient = uploadClient;
        this.log = log;
    }

    public void start() throws IOException {
        watchService = FileSystems.getDefault().newWatchService();
        for (Path dir : config.watchFolders) {
            Files.createDirectories(dir);
            dir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
            // Pick up files that already existed before this run (e.g. after a restart).
            try (var stream = Files.list(dir)) {
                stream.forEach(this::trackCandidate);
            }
        }
        replayUnfinishedFromJournal();

        watchThread = new Thread(this::watchLoop, "folder-watcher-events");
        watchThread.setDaemon(true);
        watchThread.start();

        scheduler.scheduleWithFixedDelay(this::evaluateCandidates,
                config.pollIntervalSeconds, config.pollIntervalSeconds, TimeUnit.SECONDS);
    }

    /**
     * Re-queues anything the journal recorded as pending or failed in a
     * previous run. Listing the watched folders above already finds files
     * still sitting there; this additionally accounts for journal entries
     * whose file has since disappeared, which would otherwise be dropped
     * with no record that they were never delivered.
     */
    private void replayUnfinishedFromJournal() {
        for (String path : journal.pathsNeedingUpload()) {
            Path file = Path.of(path);
            if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                trackCandidate(file);
            } else {
                log.log("upload_abandoned_file_gone", Map.of("path", path));
            }
        }
    }

    public void stop() {
        scheduler.shutdownNow();
        if (watchThread != null) {
            watchThread.interrupt();
        }
        try {
            if (watchService != null) {
                watchService.close();
            }
        } catch (IOException ignored) {
        }
    }

    private void watchLoop() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                WatchKey key = watchService.take();
                Path dir = (Path) key.watchable();
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.OVERFLOW) {
                        continue;
                    }
                    trackCandidate(dir.resolve((Path) event.context()));
                }
                key.reset();
            }
        } catch (ClosedWatchServiceException | InterruptedException stopping) {
            // normal shutdown
        }
    }

    private void trackCandidate(Path file) {
        try {
            BasicFileAttributes attrs =
                    Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attrs.isSymbolicLink()) {
                log.log("watch_skipped_symlink", Map.of("path", file.toString()));
                return;
            }
            if (!attrs.isRegularFile()) {
                return;
            }
            if (journal.isUploadedUnchanged(file, attrs.size(), attrs.lastModifiedTime().toMillis())) {
                return;
            }
            candidates.computeIfAbsent(file, f -> new Candidate());
        } catch (IOException notReadable) {
            // File vanished between the event and this stat, or is not readable.
            // Either way there is nothing to queue.
        }
    }

    private void evaluateCandidates() {
        long now = System.currentTimeMillis();
        for (Map.Entry<Path, Candidate> entry : candidates.entrySet()) {
            Path file = entry.getKey();
            Candidate candidate = entry.getValue();
            try {
                BasicFileAttributes attrs;
                try {
                    attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                } catch (NoSuchFileException gone) {
                    candidates.remove(file);
                    continue;
                }
                if (!attrs.isRegularFile() || attrs.isSymbolicLink()) {
                    candidates.remove(file);
                    continue;
                }
                long size = attrs.size();
                if (size != candidate.lastSize) {
                    candidate.lastSize = size;
                    candidate.lastChangeMillis = now;
                    continue; // still being written
                }
                boolean stableLongEnough = (now - candidate.lastChangeMillis) >= config.stableSeconds * 1000L;
                boolean backoffElapsed = now >= candidate.nextAttemptMillis;
                if (stableLongEnough && backoffElapsed) {
                    attemptUpload(file, candidate, size, attrs.lastModifiedTime().toMillis());
                }
            } catch (IOException e) {
                log.log("watch_error", Map.of("path", file.toString(), "error", String.valueOf(e.getMessage())));
            }
        }
    }

    private void attemptUpload(Path file, Candidate candidate, long size, long mtimeMillis) {
        journal.markPending(file);
        try {
            String sha256 = uploadClient.upload(file);
            journal.markUploaded(file, sha256, size, mtimeMillis);
            candidates.remove(file);
            log.log("upload_ok", Map.of("path", file.toString(), "sha256", String.valueOf(sha256)));
        } catch (Exception e) {
            journal.markFailed(file, String.valueOf(e.getMessage()));
            candidate.backoffSeconds = Math.min(Math.max(candidate.backoffSeconds * 2, 5), MAX_BACKOFF_SECONDS);
            candidate.nextAttemptMillis = System.currentTimeMillis() + candidate.backoffSeconds * 1000L;
            log.log("upload_failed_will_retry", Map.of(
                    "path", file.toString(), "error", String.valueOf(e.getMessage()),
                    "retry_in_seconds", candidate.backoffSeconds));
        }
    }

    private static final class Candidate {
        long lastSize = -1;
        long lastChangeMillis = System.currentTimeMillis();
        long backoffSeconds = 0;
        long nextAttemptMillis = 0;
    }
}
