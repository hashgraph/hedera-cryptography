// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import static com.hedera.cryptography.ceremony.crypto.EnhancedKeyStoreLoader.SIG_TYPE2;

import com.hedera.cryptography.ceremony.crypto.CryptoStatic;
import com.hedera.cryptography.ceremony.crypto.EnhancedKeyStoreLoader;
import com.hedera.cryptography.ceremony.crypto.KeyGeneratingException;
import com.hedera.cryptography.ceremony.crypto.KeyLoadingException;
import com.hedera.cryptography.ceremony.crypto.KeysAndCerts;
import com.hedera.cryptography.ceremony.crypto.KeysAndCertsGenerator;
import com.hedera.cryptography.ceremony.crypto.NodeId;
import com.hedera.cryptography.ceremony.crypto.SigningSchema;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/// Utility to load Consensus Node keys, create new derived keys, and sign files in a directory.
class Crypto {
    // For manual testing, use the scripts/keygen.sh to create node keys.

    private final EnhancedKeyStoreLoader keyStoreLoader;
    private final Map<NodeId, KeysAndCerts> keysAndCertsMap;
    private final KeyPair keyPair;
    private final X509Certificate tssCert;

    Crypto(long nodeId, String keyStoreDirectory, final char[] keyStorePassphrase) {
        try {
            // First, load the local node keys
            final NodeId nodeIdObj = new NodeId(nodeId);
            keyStoreLoader =
                    new EnhancedKeyStoreLoader(Path.of(keyStoreDirectory), keyStorePassphrase, Set.of(nodeIdObj));
            keyStoreLoader.scan();
            keyStoreLoader.generate();
            keyStoreLoader.verify();
            keysAndCertsMap = keyStoreLoader.keysAndCerts();

            // Then create a key pair and its cert to sign artifacts later
            keyPair = KeysAndCertsGenerator.generateKeyPair(SigningSchema.ED25519, new SecureRandom());

            // Distinguished name for "TSS Ceremony Artifacts Signing":
            final String dnT = CryptoStatic.distinguishedName("t-" + nodeIdObj.formatNodeName());
            // The public cert signed by the node's private key:
            tssCert = CryptoStatic.generateCertificate(
                    dnT,
                    keyPair,
                    keysAndCertsMap
                            .get(nodeIdObj)
                            .sigCert()
                            .getSubjectX500Principal()
                            .getName(),
                    keysAndCertsMap.get(nodeIdObj).sigKeyPair(),
                    SecureRandom.getInstanceStrong(),
                    SIG_TYPE2);
        } catch (KeyLoadingException
                | KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | KeyGeneratingException e) {
            throw new RuntimeException(e);
        }
    }

    KeyPair getKeyPair() {
        return keyPair;
    }

    X509Certificate getTssCert() {
        return tssCert;
    }

    private byte[] signFile(Path path) throws IOException {
        try {
            // Signature will throw OOM on a 2GB+ file, so we hash it first and then sign the hash:
            final MessageDigest md = MessageDigest.getInstance("SHA-384");
            try (final FileBytesIterator fileBytesIterator = new FileBytesIterator(path)) {
                while (fileBytesIterator.hasNext()) {
                    md.update(fileBytesIterator.next());
                }
            }

            final Signature signature = Signature.getInstance(SigningSchema.ED25519.getSigningAlgorithm());
            signature.initSign(keyPair.getPrivate());
            signature.update(md.digest());

            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    /// Sign every file in the directory, write .sig files, and then write the signing.cert.pem file as well.
    void signDir(Path filesDir) throws IOException {
        final Map<String, byte[]> fileSignatures = new HashMap<>();

        // Sign each file:
        // Must close() the stream to release resources!
        try (final Stream<Path> filesStream = Files.walk(filesDir)) {
            // Easier to handle exceptions in a loop than from stream.forEach():
            final List<Path> files = filesStream.toList();
            for (Path path : files) {
                if (path.equals(filesDir)) continue;

                final String fileName = path.getFileName().toString();

                fileSignatures.put(fileName, signFile(path));
            }
        }

        // Write each .sig file:
        for (Map.Entry<String, byte[]> entry : fileSignatures.entrySet()) {
            Path path = filesDir.resolve(entry.getKey() + ".sig");
            try (FileOutputStream fos = new FileOutputStream(path.toFile())) {
                fos.write(entry.getValue());
                fos.flush();
            }
        }

        // Write the signing certificate:
        try {
            final byte[] certBytes = tssCert.getEncoded();
            EnhancedKeyStoreLoader.writePemFile(false, filesDir.resolve("certificate.pem"), certBytes);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
