package com.filetransfer.ca;

import com.filetransfer.common.tls.ClientId;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * One-time enrollment tokens, stored as tab-separated lines:
 * {@code token\tclient_id\texpires_epoch_seconds\tused}
 *
 * Written to by the operator-run issue-token CLI (after they have
 * authenticated through the existing MFA'd server login -- see
 * scripts/issue-token.sh) and consumed by EnrollHandler. A flat file with
 * whole-file rewrite-on-consume is adequate at this system's expected
 * enrollment volume (occasional, human-triggered) and keeps the CA-service
 * free of any embedded-database dependency.
 *
 * <p>Two processes touch this file: the long-running ca-service, and the
 * operator's issue-token CLI in a separate JVM. {@code synchronized} only
 * orders the service's own threads, so every read-modify-write below also
 * takes an OS-level file lock. Without it, a token minted at the
 * moment another one is being consumed can be lost when the consuming
 * process rewrites the whole file from a snapshot taken before the append.
 *
 * <p>The file holds live credentials, so it is created readable only by its
 * owner rather than at whatever the process umask happens to be.
 */
public final class TokenStore {

    private static final Set<PosixFilePermission> OWNER_ONLY =
            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private final Path file;
    private final Path lockFile;
    private final SecureRandom random = new SecureRandom();

    public TokenStore(Path file) {
        this.file = file.toAbsolutePath();
        // A sidecar rather than a lock on the token file itself: every write
        // below replaces that file by atomic rename, and holding an open
        // channel on the file being replaced is not portable.
        this.lockFile = this.file.resolveSibling(this.file.getFileName() + ".lock");
    }

    /** Acquires the cross-process lock guarding read-modify-write of the token file. */
    private FileChannel lockChannel() throws IOException {
        Files.createDirectories(file.getParent());
        FileChannel channel = FileChannel.open(lockFile,
                StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
        restrictToOwner(lockFile);
        try {
            channel.lock();
        } catch (IOException | RuntimeException e) {
            channel.close();
            throw e;
        }
        return channel;
    }

    public synchronized String issue(String clientId, long validityHours) throws IOException {
        ClientId.requireValid(clientId);
        if (validityHours <= 0) {
            throw new IllegalArgumentException("validity_hours must be positive, got " + validityHours);
        }
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        StringBuilder tokenHex = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            tokenHex.append(String.format("%02x", b));
        }
        String token = tokenHex.toString();
        long expiresAt = Instant.now().getEpochSecond() + validityHours * 3600;
        String line = token + "\t" + clientId + "\t" + expiresAt + "\t0";

        try (FileChannel ignored = lockChannel()) {
            List<String> lines = readLines();
            lines.add(line);
            writeLines(lines);
        }
        return token;
    }

    /**
     * Validates and consumes a token in one step. Returns true only if the
     * token exists, is unused, unexpired, and matches the claimed client_id.
     */
    public synchronized boolean consume(String token, String claimedClientId) throws IOException {
        return setUsedFlag(token, claimedClientId, true);
    }

    /**
     * Puts a consumed token back into play. EnrollHandler calls this when
     * signing failed after the token was already marked used, so an outage on
     * the CA side does not silently burn the client's one-time token and
     * force the operator to mint another. The token stays marked used for the
     * duration of the signing attempt, so a concurrent second attempt is
     * still rejected.
     */
    public synchronized void release(String token, String clientId) throws IOException {
        setUsedFlag(token, clientId, false);
    }

    private boolean setUsedFlag(String token, String clientId, boolean used) throws IOException {
        if (!Files.exists(file)) {
            return false;
        }
        try (FileChannel ignored = lockChannel()) {
            List<String> lines = readLines();
            List<String> updated = new ArrayList<>(lines.size());
            boolean changed = false;
            long now = Instant.now().getEpochSecond();

            for (String line : lines) {
                if (line.isBlank()) {
                    continue;
                }
                String[] parts = line.split("\t");
                if (parts.length != 4) {
                    updated.add(line);
                    continue;
                }
                String lineToken = parts[0];
                String lineClientId = parts[1];
                long expiresAt;
                try {
                    expiresAt = Long.parseLong(parts[2]);
                } catch (NumberFormatException corrupt) {
                    // One damaged line must not take down enrollment for every
                    // other client; keep it verbatim and move on.
                    updated.add(line);
                    continue;
                }
                boolean lineUsed = "1".equals(parts[3]);

                boolean matches = !changed
                        && lineToken.equals(token)
                        && lineClientId.equals(clientId)
                        && lineUsed != used
                        // Expiry only gates consumption; a release must be able
                        // to restore a token whose window closed mid-signing.
                        && (!used || expiresAt >= now);
                if (matches) {
                    changed = true;
                    updated.add(lineToken + "\t" + lineClientId + "\t" + expiresAt + "\t" + (used ? "1" : "0"));
                    continue;
                }
                updated.add(line);
            }

            if (changed) {
                writeLines(updated);
            }
            return changed;
        }
    }

    private List<String> readLines() throws IOException {
        if (!Files.exists(file)) {
            return new ArrayList<>();
        }
        return new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
    }

    /**
     * Rewrites the file through a temp file in the same directory, so a crash
     * mid-write leaves the previous contents rather than a truncated one.
     */
    private void writeLines(List<String> lines) throws IOException {
        Path tmp = Files.createTempFile(file.getParent(), "tokens", ".tmp");
        restrictToOwner(tmp);
        Files.write(tmp, lines, StandardCharsets.UTF_8);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch (UnsupportedOperationException notPosix) {
            // Windows: rely on directory ACLs.
        } catch (IOException ignored) {
            // best-effort permission tightening
        }
    }
}
