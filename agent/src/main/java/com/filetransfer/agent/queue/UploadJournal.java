package com.filetransfer.agent.queue;

import com.filetransfer.common.json.SimpleJson;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Append-only JSON-lines record of upload attempts, replayed on startup so
 * a restart never silently drops a file that was pending or failed --
 * matches spec section 10's "never drop a file silently" requirement.
 *
 * <p>Each uploaded path is recorded together with the size and modification
 * time of the bytes that were actually sent. A path alone is not enough:
 * keyed only on path, a file edited in place after a successful upload would
 * be treated as already delivered and never sent again, which loses the edit
 * silently. Comparing the cheap (size, mtime) fingerprint on each sighting
 * makes a changed file a new upload without re-hashing every candidate on
 * every poll.
 */
public final class UploadJournal {

    public enum State { PENDING, UPLOADED, FAILED }

    /** What the journal knows about one path. */
    public static final class Record {
        public final State state;
        public final long size;
        public final long mtimeMillis;

        Record(State state, long size, long mtimeMillis) {
            this.state = state;
            this.size = size;
            this.mtimeMillis = mtimeMillis;
        }
    }

    private final Path journalFile;
    private final Map<String, Record> byPath = new ConcurrentHashMap<>();

    public UploadJournal(Path journalFile) throws IOException {
        this.journalFile = journalFile.toAbsolutePath();
        replay();
    }

    /**
     * True only if this exact path was uploaded and its bytes look unchanged
     * since. A differing size or mtime means the file was rewritten and is
     * due for upload again.
     */
    public boolean isUploadedUnchanged(Path file, long size, long mtimeMillis) {
        Record record = byPath.get(key(file));
        return record != null
                && record.state == State.UPLOADED
                && record.size == size
                && record.mtimeMillis == mtimeMillis;
    }

    /** Paths the journal saw but never recorded as successfully uploaded. */
    public List<String> pathsNeedingUpload() {
        List<String> pending = new ArrayList<>();
        for (Map.Entry<String, Record> entry : byPath.entrySet()) {
            if (entry.getValue().state != State.UPLOADED) {
                pending.add(entry.getKey());
            }
        }
        return pending;
    }

    public void markPending(Path file) {
        append(file, State.PENDING, -1, -1, null, null);
    }

    public void markUploaded(Path file, String sha256, long size, long mtimeMillis) {
        append(file, State.UPLOADED, size, mtimeMillis, sha256, null);
    }

    public void markFailed(Path file, String reason) {
        append(file, State.FAILED, -1, -1, null, reason);
    }

    private synchronized void append(Path file, State state, long size, long mtimeMillis,
                                     String sha256, String detail) {
        String key = key(file);
        byPath.put(key, new Record(state, size, mtimeMillis));

        Map<String, Object> record = new LinkedHashMap<>();
        record.put("timestamp", Instant.now().toString());
        record.put("path", key);
        record.put("state", state.name());
        if (size >= 0) {
            record.put("size", size);
            record.put("mtime", mtimeMillis);
        }
        if (sha256 != null) {
            record.put("sha256", sha256);
        }
        if (detail != null) {
            record.put("detail", detail);
        }
        try {
            Files.createDirectories(journalFile.getParent());
            Files.writeString(journalFile, SimpleJson.writeFlatObject(record) + System.lineSeparator(),
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("UploadJournal append failed: " + e.getMessage());
        }
    }

    private static String key(Path file) {
        return file.toAbsolutePath().toString();
    }

    private void replay() throws IOException {
        if (!Files.exists(journalFile)) {
            return;
        }
        for (String line : Files.readAllLines(journalFile, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            Map<String, String> record;
            try {
                record = SimpleJson.parseFlatObject(line);
            } catch (IllegalArgumentException malformed) {
                // A torn final line (killed mid-write) must not stop the agent
                // from starting and re-uploading everything else.
                System.err.println("UploadJournal: skipping unparseable line: " + malformed.getMessage());
                continue;
            }
            String path = record.get("path");
            String state = record.get("state");
            if (path == null || state == null) {
                continue;
            }
            try {
                byPath.put(path, new Record(State.valueOf(state),
                        parseLong(record.get("size")), parseLong(record.get("mtime"))));
            } catch (IllegalArgumentException unknownState) {
                System.err.println("UploadJournal: skipping unknown state '" + state + "'");
            }
        }
    }

    private static long parseLong(String value) {
        if (value == null) {
            return -1;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
