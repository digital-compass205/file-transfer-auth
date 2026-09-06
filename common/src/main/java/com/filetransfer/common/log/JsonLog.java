package com.filetransfer.common.log;

import com.filetransfer.common.json.SimpleJson;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Append-only JSON-lines logger. One JSON object per line, always including
 * a "timestamp" field. Deliberately not a general logging framework --
 * every transfer/decision this system needs to audit has a small, fixed
 * shape.
 *
 * <p>Rotates by size: once the active file passes {@code maxBytes} it is
 * renamed to {@code <name>.1} (shifting any existing generations up, oldest
 * discarded) and a fresh file is opened. Without this these files grow
 * without bound -- the agent appends a line per upload attempt, and a
 * persistently failing upload retries every few minutes forever.
 */
public final class JsonLog implements AutoCloseable {

    private static final long DEFAULT_MAX_BYTES = 16L * 1024 * 1024;
    private static final int DEFAULT_GENERATIONS = 5;

    private final Path logFile;
    private final long maxBytes;
    private final int generations;

    private Writer writer;
    private long bytesWritten;

    public JsonLog(Path logFile) throws IOException {
        this(logFile, DEFAULT_MAX_BYTES, DEFAULT_GENERATIONS);
    }

    public JsonLog(Path logFile, long maxBytes, int generations) throws IOException {
        // toAbsolutePath() first: a bare relative filename ("agent.jsonl") has a
        // null parent, which would fail here rather than meaning "current dir".
        this.logFile = logFile.toAbsolutePath();
        this.maxBytes = maxBytes;
        this.generations = generations;
        Files.createDirectories(this.logFile.getParent());
        open();
    }

    private void open() throws IOException {
        OpenOption[] opts = {StandardOpenOption.CREATE, StandardOpenOption.APPEND};
        this.writer = Files.newBufferedWriter(logFile, StandardCharsets.UTF_8, opts);
        this.bytesWritten = Files.exists(logFile) ? Files.size(logFile) : 0;
        restrictToOwner(logFile);
    }

    public synchronized void log(String event, Map<String, ?> fields) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("timestamp", Instant.now().toString());
        record.put("event", event);
        record.putAll(fields);
        String line = SimpleJson.writeFlatObject(record) + System.lineSeparator();
        try {
            writer.write(line);
            writer.flush();
            bytesWritten += line.getBytes(StandardCharsets.UTF_8).length;
            if (bytesWritten >= maxBytes) {
                rotate();
            }
        } catch (IOException e) {
            System.err.println("JsonLog write failed: " + e.getMessage());
        }
    }

    private void rotate() {
        try {
            writer.close();
            Path oldest = sibling(generations);
            Files.deleteIfExists(oldest);
            for (int i = generations - 1; i >= 1; i--) {
                Path from = sibling(i);
                if (Files.exists(from)) {
                    Files.move(from, sibling(i + 1), StandardCopyOption.REPLACE_EXISTING);
                }
            }
            Files.move(logFile, sibling(1), StandardCopyOption.REPLACE_EXISTING);
            open();
        } catch (IOException e) {
            System.err.println("JsonLog rotation failed: " + e.getMessage());
            try {
                open(); // never leave the logger without an open writer
            } catch (IOException reopenFailed) {
                System.err.println("JsonLog reopen failed: " + reopenFailed.getMessage());
            }
        }
    }

    private Path sibling(int generation) {
        return logFile.resolveSibling(logFile.getFileName() + "." + generation);
    }

    /** Spec section 10: local logs are readable by the running account only. */
    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path,
                    Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException notPosix) {
            // Windows: rely on the account's profile-directory ACLs, as for the keystore.
        } catch (IOException ignored) {
            // best-effort permission tightening
        }
    }

    @Override
    public synchronized void close() throws IOException {
        writer.close();
    }
}
