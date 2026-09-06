package com.filetransfer.common.hash;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Sha256 {

    private Sha256() {
    }

    public static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available in this JDK", e);
        }
    }

    public static String hex(byte[] digest) {
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String ofFile(Path file) throws IOException {
        MessageDigest md = newDigest();
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) >= 0) {
                md.update(buf, 0, n);
            }
        }
        return hex(md.digest());
    }

    /**
     * Copies all bytes from {@code in} to {@code out} while updating {@code digest},
     * returning the total byte count copied.
     */
    public static long copyWithDigest(InputStream in, OutputStream out, MessageDigest digest) throws IOException {
        DigestOutputStream dos = new DigestOutputStream(out, digest);
        byte[] buf = new byte[64 * 1024];
        long total = 0;
        int n;
        while ((n = in.read(buf)) >= 0) {
            dos.write(buf, 0, n);
            total += n;
        }
        return total;
    }
}
