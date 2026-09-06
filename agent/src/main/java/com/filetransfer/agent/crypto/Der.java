package com.filetransfer.agent.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Minimal DER (ASN.1 Distinguished Encoding Rules) primitives -- just
 * enough for CsrBuilder to hand-build the one PKCS#10 CertificationRequest
 * structure it needs (RFC 2986), without a general-purpose ASN.1 library.
 */
final class Der {

    private static final int SEQUENCE = 0x30;
    private static final int SET = 0x31;
    private static final int UTF8_STRING = 0x0C;
    private static final int INTEGER = 0x02;
    private static final int BIT_STRING = 0x03;

    private Der() {
    }

    static byte[] sequence(byte[]... parts) {
        return tlv(SEQUENCE, concat(parts));
    }

    static byte[] set(byte[]... parts) {
        return tlv(SET, concat(parts));
    }

    /** [tagNumber] IMPLICIT/EXPLICIT constructed, e.g. contextConstructed(0) for "[0]". */
    static byte[] contextConstructed(int tagNumber, byte[]... parts) {
        return tlv(0xA0 | (tagNumber & 0x1F), concat(parts));
    }

    static byte[] utf8String(String s) {
        return tlv(UTF8_STRING, s.getBytes(StandardCharsets.UTF_8));
    }

    /** Only ever used for the CSR version field, which is always 0. */
    static byte[] smallInteger(int value) {
        if (value < 0 || value > 127) {
            throw new IllegalArgumentException("smallInteger only supports 0..127");
        }
        return tlv(INTEGER, new byte[]{(byte) value});
    }

    /** Wraps an already-DER-encoded, byte-aligned value (e.g. a signature) as a BIT STRING. */
    static byte[] bitString(byte[] rawBytes) {
        byte[] content = new byte[rawBytes.length + 1];
        content[0] = 0; // 0 unused bits -- our inputs are always whole-byte DER blobs
        System.arraycopy(rawBytes, 0, content, 1, rawBytes.length);
        return tlv(BIT_STRING, content);
    }

    private static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, content.length);
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
            return;
        }
        byte[] be = minimalBigEndian(len);
        out.write(0x80 | be.length);
        out.writeBytes(be);
    }

    private static byte[] minimalBigEndian(int value) {
        byte[] full = {(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
        int start = 0;
        while (start < 3 && full[start] == 0) {
            start++;
        }
        return Arrays.copyOfRange(full, start, full.length);
    }
}
