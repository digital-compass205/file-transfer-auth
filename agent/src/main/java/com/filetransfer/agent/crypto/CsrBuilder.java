package com.filetransfer.agent.crypto;

import com.filetransfer.common.tls.ClientId;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Builds a PKCS#10 CSR (RFC 2986) using nothing but java.security.* --
 * key generation and signing are already pure JDK; this class only
 * hand-encodes the small, fixed ASN.1/DER structure PKCS#10 wraps them in,
 * since the JDK exposes no public API for that part. This keeps the whole
 * project (client and server) free of any third-party dependency.
 *
 * The structure built here is exactly:
 *   CertificationRequest ::= SEQUENCE {
 *     certificationRequestInfo CertificationRequestInfo,
 *     signatureAlgorithm       AlgorithmIdentifier,
 *     signature                BIT STRING }
 *   CertificationRequestInfo ::= SEQUENCE {
 *     version    INTEGER (0),
 *     subject    Name,                  -- just "CN=<clientId>"
 *     subjectPKInfo SubjectPublicKeyInfo, -- keyPair.getPublic().getEncoded()
 *     attributes [0] IMPLICIT SET OF Attribute } -- always empty here
 *
 * copy_extensions = none on the CA side (see openssl-ca.cnf) means the CA
 * ignores any attributes/extensions a CSR requests anyway, so there is
 * nothing to gain by populating this beyond the empty set PKCS#10 requires.
 */
public final class CsrBuilder {

    // Fully TLV-encoded (tag+length+value) OIDs, checked against RFC
    // 3279/5480 test vectors: commonName (2.5.4.3) and ecdsa-with-SHA256
    // (1.2.840.10045.4.3.2).
    private static final byte[] OID_COMMON_NAME =
            {0x06, 0x03, 0x55, 0x04, 0x03};
    private static final byte[] OID_ECDSA_WITH_SHA256 =
            {0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02};

    private CsrBuilder() {
    }

    public static final class KeyAndCsr {
        public final KeyPair keyPair;
        public final String csrPem;

        KeyAndCsr(KeyPair keyPair, String csrPem) {
            this.keyPair = keyPair;
            this.csrPem = csrPem;
        }
    }

    public static KeyAndCsr generate(String clientId) throws GeneralSecurityException {
        ClientId.requireValid(clientId);
        KeyPair keyPair = generateEcKeyPair();

        byte[] name = Der.sequence(
                Der.set(
                        Der.sequence(OID_COMMON_NAME, Der.utf8String(clientId))));
        // ECPublicKey.getEncoded() is already a complete, correctly-formed
        // DER SubjectPublicKeyInfo (the JDK's "X.509" public key encoding
        // *is* that structure) -- nothing to hand-encode here.
        byte[] subjectPublicKeyInfo = keyPair.getPublic().getEncoded();
        byte[] attributes = Der.contextConstructed(0); // empty [0] IMPLICIT SET OF Attribute

        byte[] certificationRequestInfo = Der.sequence(
                Der.smallInteger(0), name, subjectPublicKeyInfo, attributes);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(certificationRequestInfo);
        // The JCA "SHA256withECDSA" signature format is already the
        // ASN.1 SEQUENCE{r,s} (ECDSA-Sig-Value) DER encoding X.509/PKCS#10
        // expect -- not the raw concatenated r||s (P1363) form.
        byte[] signatureBytes = signer.sign();

        byte[] signatureAlgorithm = Der.sequence(OID_ECDSA_WITH_SHA256);
        byte[] certificationRequest = Der.sequence(
                certificationRequestInfo, signatureAlgorithm, Der.bitString(signatureBytes));

        return new KeyAndCsr(keyPair, pemEncode("CERTIFICATE REQUEST", certificationRequest));
    }

    private static KeyPair generateEcKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static String pemEncode(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, System.lineSeparator().getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----" + System.lineSeparator()
                + base64 + System.lineSeparator()
                + "-----END " + type + "-----" + System.lineSeparator();
    }
}
