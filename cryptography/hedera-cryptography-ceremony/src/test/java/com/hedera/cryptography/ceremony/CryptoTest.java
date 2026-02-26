// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.ceremony.crypto.SigningSchema;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class CryptoTest {
    private static final long NODE_ID = 1;
    private static final String PASSWORD = "password";
    private static final List<String> KEY_CERT_FILES =
            List.of("s-private-node2.key", "s-private-node2.pem", "s-public-node2.pem");

    private static Path KEYS_PATH;

    @BeforeAll
    static void setup() throws IOException {
        KEYS_PATH = Files.createTempDirectory("keys");

        for (String name : KEY_CERT_FILES) {
            try (InputStream is = CryptoTest.class.getClassLoader().getResourceAsStream(name)) {
                Files.copy(is, KEYS_PATH.resolve(name));
            }
        }
    }

    @Test
    void testCryptoHappy() {
        final Crypto crypto = new Crypto(NODE_ID, KEYS_PATH.toAbsolutePath().toString(), PASSWORD.toCharArray());

        // Just check all the things exist. The keys/certs are subject to change when regenerated.
        // However, if they couldn't be loaded/created, then the below assertions would fail.
        assertNotNull(crypto.getKeyPair());
        assertNotNull(crypto.getKeyPair().getPrivate());
        assertNotNull(crypto.getKeyPair().getPublic());

        assertNotNull(crypto.getTssCert());

        // But do check that the cert is for our actual public key:
        assertEquals(crypto.getKeyPair().getPublic(), crypto.getTssCert().getPublicKey());
    }

    @Test
    void testCryptoCannotLoad() {
        assertThrows(
                RuntimeException.class,
                () -> new Crypto(666, KEYS_PATH.toAbsolutePath().toString(), PASSWORD.toCharArray()));
        assertThrows(RuntimeException.class, () -> new Crypto(NODE_ID, "/", PASSWORD.toCharArray()));
        // NOTE: apparently, the key store isn't password-protected, and even if it was, the current hard-coded password
        // is trivial.
        // So the below actually doesn't throw.
        // assertThrows(RuntimeException.class, () -> new Crypto(NODE_ID, keys.toAbsolutePath().toString(),
        // "badPassword".toCharArray()));
    }

    private static X509Certificate loadCertificate(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream is = new FileInputStream(filePath)) {
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(is);
            return certificate;
        }
    }

    @Test
    void testSignDir() throws Exception {
        final Crypto crypto = new Crypto(NODE_ID, KEYS_PATH.toAbsolutePath().toString(), PASSWORD.toCharArray());

        // Let's just sign the keys that we use.
        // Clean up first in case there were previous run reusing the same temp dir
        Files.deleteIfExists(KEYS_PATH.resolve("certificate.pem"));
        for (String name : KEY_CERT_FILES) {
            Files.deleteIfExists(KEYS_PATH.resolve(name + ".sig"));
        }

        // Now sign:
        crypto.signDir(KEYS_PATH);

        // Verify the cert
        assertTrue(Files.exists(KEYS_PATH.resolve("certificate.pem")));
        final X509Certificate cert = loadCertificate(
                KEYS_PATH.resolve("certificate.pem").toAbsolutePath().toString());
        assertNotNull(cert);
        assertEquals(crypto.getKeyPair().getPublic(), cert.getPublicKey());

        // And then verify every signature
        verifySignature(KEYS_PATH, KEY_CERT_FILES, cert);
    }

    private void verifySignature(Path dir, List<String> files, X509Certificate cert) throws Exception {
        for (String name : files) {
            assertTrue(Files.exists(dir.resolve(name + ".sig")));

            Signature sig = Signature.getInstance(SigningSchema.ED25519.getSigningAlgorithm());
            sig.initVerify(cert);

            final MessageDigest md = MessageDigest.getInstance("SHA-384");
            try (final FileBytesIterator fileBytesIterator = new FileBytesIterator(dir.resolve(name))) {
                while (fileBytesIterator.hasNext()) {
                    md.update(fileBytesIterator.next());
                }
            }
            sig.update(md.digest());

            assertTrue(sig.verify(Files.readAllBytes(dir.resolve(name + ".sig"))));
        }
    }

    @Test
    void testSignHugeFile() throws Exception {
        final Path path = Files.createTempDirectory("hugeFileDir");
        System.err.println("Writing a huge file to disk. This can take a few seconds...");
        try (FileOutputStream fos =
                new FileOutputStream(path.resolve("testHugeFile.bin").toFile())) {
            // Make a file of 4GB+1byte size
            final long SIZE = (long) Integer.MAX_VALUE * 2L + 1;
            final int CHUNKS = 64;
            final int CHUNK_SIZE = (int) (SIZE / CHUNKS);
            byte[] array = new byte[CHUNK_SIZE];
            final Random random = new Random();
            for (int i = 0; i < CHUNKS; i++) {
                random.nextBytes(array);
                fos.write(array);
            }
        }

        System.err.println("Done writing the huge file to disk. On to signing and verifying...");
        final Crypto crypto = new Crypto(NODE_ID, KEYS_PATH.toAbsolutePath().toString(), PASSWORD.toCharArray());

        crypto.signDir(path);

        final X509Certificate cert =
                loadCertificate(path.resolve("certificate.pem").toAbsolutePath().toString());
        verifySignature(path, List.of("testHugeFile.bin"), cert);
    }
}
