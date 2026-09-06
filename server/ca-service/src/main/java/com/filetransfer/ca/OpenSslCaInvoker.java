package com.filetransfer.ca;

import com.filetransfer.common.tls.ClientId;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Signs CSRs by shelling out to the system `openssl ca` binary rather than
 * doing X.509 signing in-process, per the decision to keep the server's
 * runtime dependency footprint to what RHEL 8 already ships. This class
 * owns the one security-critical detail of that integration: the signed
 * cert's CN always comes from the server-supplied, already-validated
 * client_id via `-subj`, never from the CSR's own subject.
 */
public final class OpenSslCaInvoker {

    /** Rejected below this; P-256 and RSA-2048 are the floor. */
    private static final int MIN_EC_BITS = 256;
    private static final int MIN_RSA_BITS = 2048;

    private static final long OPENSSL_TIMEOUT_SECONDS = 30;

    private final String opensslBinary;
    private final Path opensslConfig;
    private final Path workDir;

    public OpenSslCaInvoker(String opensslBinary, Path opensslConfig, Path workDir) {
        this.opensslBinary = opensslBinary;
        this.opensslConfig = opensslConfig;
        this.workDir = workDir;
    }

    public static final class SignedCert {
        public final String certPem;

        SignedCert(String certPem) {
            this.certPem = certPem;
        }
    }

    /** A CSR was rejected before signing; the caller should answer 400, not 500. */
    public static final class InvalidCsrException extends Exception {
        public InvalidCsrException(String message) {
            super(message);
        }
    }

    public SignedCert sign(String csrPem, String clientId)
            throws IOException, InterruptedException, InvalidCsrException {
        ClientId.requireValid(clientId);

        Files.createDirectories(workDir);
        Path csrFile = Files.createTempFile(workDir, "csr-", ".pem");
        Path certFile = Files.createTempFile(workDir, "cert-", ".pem");
        try {
            Files.writeString(csrFile, csrPem, StandardCharsets.UTF_8);
            // createTempFile() above is only used to reserve a unique path; delete
            // it so openssl ca is the one creating the -out file fresh.
            Files.deleteIfExists(certFile);

            requireAcceptableKey(csrFile);

            ProcessBuilder pb = new ProcessBuilder(
                    opensslBinary, "ca",
                    "-config", opensslConfig.toString(),
                    "-batch",
                    "-subj", "/CN=" + clientId,
                    "-in", csrFile.toString(),
                    "-out", certFile.toString()
            );
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            boolean finished = proc.waitFor(OPENSSL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                proc.destroyForcibly();
                throw new IOException("openssl ca timed out signing cert for client_id=" + clientId);
            }
            if (proc.exitValue() != 0) {
                throw new IOException("openssl ca failed (exit " + proc.exitValue() + ") for client_id=" + clientId + ": " + output);
            }

            return new SignedCert(Files.readString(certFile, StandardCharsets.UTF_8));
        } finally {
            Files.deleteIfExists(csrFile);
            Files.deleteIfExists(certFile);
        }
    }

    /**
     * Refuses to sign a CSR carrying a key weaker than this system's floor.
     * `openssl ca` verifies that a CSR is internally consistent and correctly
     * self-signed, but it will happily certify a 512-bit RSA key if one is
     * offered -- nothing in the pipeline otherwise constrains what the client
     * generated. A certificate is a statement this CA makes, so the strength
     * of the key it names is the CA's business, not only the client's.
     *
     * <p>The key is extracted with `openssl req -pubkey` and inspected with
     * the JDK rather than parsed by hand: the agent hand-encodes the one CSR
     * shape it emits, but the CA must cope with any CSR that arrives, and
     * that is a general ASN.1 parsing problem worth not owning.
     */
    private void requireAcceptableKey(Path csrFile) throws IOException, InterruptedException, InvalidCsrException {
        ProcessBuilder pb = new ProcessBuilder(
                opensslBinary, "req", "-in", csrFile.toString(), "-noout", "-pubkey");
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!proc.waitFor(OPENSSL_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            proc.destroyForcibly();
            throw new IOException("openssl req timed out reading the CSR public key");
        }
        if (proc.exitValue() != 0) {
            throw new InvalidCsrException("CSR could not be parsed: " + output.trim());
        }

        PublicKey key = parsePublicKeyPem(output);
        if (key instanceof ECPublicKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            if (bits < MIN_EC_BITS) {
                throw new InvalidCsrException("EC key of " + bits + " bits is below the "
                        + MIN_EC_BITS + "-bit minimum");
            }
        } else if (key instanceof RSAPublicKey rsa) {
            int bits = rsa.getModulus().bitLength();
            if (bits < MIN_RSA_BITS) {
                throw new InvalidCsrException("RSA key of " + bits + " bits is below the "
                        + MIN_RSA_BITS + "-bit minimum");
            }
        } else {
            throw new InvalidCsrException("Unsupported CSR key algorithm: "
                    + (key == null ? "unknown" : key.getAlgorithm()));
        }
    }

    private static PublicKey parsePublicKeyPem(String pem) throws InvalidCsrException {
        int begin = pem.indexOf("-----BEGIN PUBLIC KEY-----");
        int end = pem.indexOf("-----END PUBLIC KEY-----");
        if (begin < 0 || end < 0) {
            throw new InvalidCsrException("CSR contained no readable public key");
        }
        String base64 = pem.substring(begin + "-----BEGIN PUBLIC KEY-----".length(), end)
                .replaceAll("\\s", "");
        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new InvalidCsrException("CSR public key was not valid base64");
        }
        // SubjectPublicKeyInfo names its own algorithm; try the two this
        // system is willing to certify and let anything else fall through.
        for (String algorithm : new String[]{"EC", "RSA"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der));
            } catch (Exception notThisAlgorithm) {
                // try the next
            }
        }
        throw new InvalidCsrException("CSR public key is neither EC nor RSA");
    }
}
