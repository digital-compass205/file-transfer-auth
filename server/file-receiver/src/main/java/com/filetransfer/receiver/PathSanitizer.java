package com.filetransfer.receiver;

import com.filetransfer.common.tls.ClientId;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Turns a client-supplied filename into a filesystem path without ever
 * trusting it directly. Every check here is redundant with at least one
 * other check (character-level rejection AND a normalize()+startsWith()
 * containment check AND, once the directory exists, a toRealPath()
 * comparison) deliberately -- path traversal is exactly the kind of bug
 * where a single clever check that seems sufficient often isn't.
 */
public final class PathSanitizer {

    private static final int MAX_FILENAME_LENGTH = 255;

    private PathSanitizer() {
    }

    public static Path resolveUploadPath(Path baseDir, String clientId, String filename) {
        // Rejects "." and ".." as well as the charset check: both are built
        // from allowed characters but name a directory rather than a client,
        // which would move the "client directory" out from under baseDir.
        ClientId.requireValid(clientId);

        if (filename == null || filename.isEmpty() || filename.length() > MAX_FILENAME_LENGTH) {
            throw new IllegalArgumentException("Invalid filename");
        }
        if (filename.equals(".") || filename.equals("..")) {
            throw new IllegalArgumentException("Invalid filename");
        }
        if (filename.indexOf('/') >= 0 || filename.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("Filename must not contain path separators");
        }
        if (filename.indexOf(0) >= 0) {
            throw new IllegalArgumentException("Filename must not contain NUL");
        }
        for (int i = 0; i < filename.length(); i++) {
            char c = filename.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                throw new IllegalArgumentException("Filename must not contain control characters");
            }
        }

        Path clientDir = baseDir.resolve(clientId).normalize();
        Path candidate = clientDir.resolve(filename).normalize();

        if (!candidate.startsWith(clientDir) || candidate.equals(clientDir)) {
            throw new IllegalArgumentException("Resolved path escapes client directory");
        }
        return candidate;
    }

    /**
     * Re-checks containment against the paths as they exist on disk, after the
     * client directory has been created. The lexical checks above cannot see a
     * symlink: if {@code incoming/<client-id>} were itself a link pointing
     * elsewhere, every string-level check would still pass while the write
     * landed outside the storage root. Resolving both sides with
     * {@code toRealPath()} is the check that notices.
     *
     * <p>Called on the write path rather than folded into
     * {@code resolveUploadPath} because it needs the directory to exist, which
     * it does not until the caller creates it.
     */
    public static void verifyRealPathContained(Path baseDir, String clientId, Path targetPath) throws IOException {
        Path realClientDir = baseDir.resolve(clientId).toRealPath();
        Path realParent = targetPath.getParent().toRealPath();
        if (!realParent.equals(realClientDir)) {
            throw new IllegalArgumentException(
                    "Resolved parent " + realParent + " is not the client directory " + realClientDir);
        }
    }
}
