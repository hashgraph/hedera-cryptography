// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony.crypto;

import static com.hedera.cryptography.ceremony.crypto.CryptoStatic.createEmptyTrustStore;
import static com.hedera.cryptography.ceremony.crypto.CryptoStatic.loadKeys;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.jcajce.JceInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * This class is responsible for loading the key stores for all nodes in the address book.
 *
 * <p>
 * The {@link EnhancedKeyStoreLoader} class is a replacement for the now deprecated
 *  method. This new implementation adds support for
 * loading industry standard PEM formatted PKCS #8 private keys and X.509 certificates. The legacy key stores are still
 * supported, but are no longer the preferred format.
 *
 * <p>
 * This implementation will attempt to load the private key stores in the following order:
 *     <ol>
 *         <li>Enhanced private key store ({@code [type]-private-[nodeName].pem})</li>
 *         <li>Legacy private key store ({@code private-[nodeName].pfx})</li>
 *     </ol>
 * <p>
 *     Public key stores are loaded in the following order:
 *     <ol>
 *          <li>Enhanced certificate store ({@code [type]-public-[nodeName].pem})</li>
 *          <li>Legacy certificate store ({@code public.pfx})</li>
 *     </ol>
 *     where {@code nodeName} is the string "node"+(NodeId+1)
 */
public class EnhancedKeyStoreLoader {
    // A few constants from external classes:
    public static final String PUBLIC_KEYS_FILE = "public.pfx";
    public static final String SIG_TYPE2 = "SHA384withRSA"; // or RSA

    /**
     * The constant message to use when the {@code nodeId} required parameter is {@code null}.
     */
    private static final String MSG_NODE_ID_NON_NULL = "nodeId must not be null";

    /**
     * The constant message to use when the {@code nodeAlias} required parameter is {@code null}.
     */
    private static final String MSG_NODE_ALIAS_NON_NULL = "nodeAlias must not be null";

    /**
     * The constant message to use when the {@code purpose} required parameter is {@code null}.
     */
    private static final String MSG_PURPOSE_NON_NULL = "purpose must not be null";

    /**
     * The constant message to use when the {@code legacyPublicStore} required parameter is {@code null}.
     */
    private static final String MSG_LEGACY_PUBLIC_STORE_NON_NULL = "legacyPublicStore must not be null";

    /**
     * The constant message to use when the {@code location} required parameter is {@code null}.
     */
    private static final String MSG_LOCATION_NON_NULL = "location must not be null";

    /**
     * The constant message to use when the {@code entryType} required parameter is {@code null}.
     */
    private static final String MSG_ENTRY_TYPE_NON_NULL = "entryType must not be null";

    /**
     * The constant message to use when the {@code entry} required parameter is {@code null}.
     */
    private static final String MSG_ENTRY_NON_NULL = "entry must not be null";

    /**
     * The constant message to use when the {@code keyStoreDirectory} required parameter is {@code null}.
     */
    private static final String MSG_KEY_STORE_DIRECTORY_NON_NULL = "keyStoreDirectory must not be null";

    /**
     * The constant message to use when the {@code keyStorePassphrase} required parameter is {@code null}.
     */
    private static final String MSG_KEY_STORE_PASSPHRASE_NON_NULL = "keyStorePassphrase must not be null";

    /**
     * The constant message to use when the {@code localNodes} required parameter is {@code null}.
     */
    private static final String MSG_NODES_TO_START_NON_NULL = "the local nodes must not be null";

    /**
     * The absolute path to the key store directory.
     */
    private final Path keyStoreDirectory;

    /**
     * The passphrase used to protect the key stores.
     */
    private final char[] keyStorePassphrase;

    /**
     * The private keys loaded from the key stores.
     */
    private final Map<NodeId, PrivateKey> sigPrivateKeys;

    /**
     * The X.509 Certificates loaded from the key stores.
     */
    private final Map<NodeId, Certificate> sigCertificates;

    /**
     * The private keys loaded from the key stores.
     */
    private final Map<NodeId, PrivateKey> agrPrivateKeys;

    /**
     * The X.509 Certificates loaded from the key stores.
     */
    private final Map<NodeId, Certificate> agrCertificates;

    /**
     * The list of {@link NodeId}s which must have a private key loaded.
     */
    private final Set<NodeId> nodeIds;

    /*
     * Static initializer to ensure the Bouncy Castle security provider is registered.
     */
    static {
        if (Arrays.stream(Security.getProviders()).noneMatch(p -> p instanceof BouncyCastleProvider)) {
            try {
                Security.addProvider(new BouncyCastleProvider());
            } catch (Throwable ex) {
                ex.printStackTrace();
            }
        }
    }

    /**
     * Constructs a new {@link EnhancedKeyStoreLoader} instance.
     *
     * @param keyStoreDirectory  the absolute path to the key store directory.
     * @param keyStorePassphrase the passphrase used to protect the key stores.
     * @param nodeIds         the set of local nodes that need private keys loaded
     * @throws NullPointerException if {@code addressBook} or {@code configuration} is {@code null}.
     */
    public EnhancedKeyStoreLoader(
            final Path keyStoreDirectory, final char[] keyStorePassphrase, final Set<NodeId> nodeIds) {
        this.keyStoreDirectory = Objects.requireNonNull(keyStoreDirectory, MSG_KEY_STORE_DIRECTORY_NON_NULL);
        this.keyStorePassphrase = Objects.requireNonNull(keyStorePassphrase, MSG_KEY_STORE_PASSPHRASE_NON_NULL);
        this.sigPrivateKeys = HashMap.newHashMap(nodeIds.size());
        this.sigCertificates = HashMap.newHashMap(nodeIds.size());
        this.agrPrivateKeys = HashMap.newHashMap(nodeIds.size());
        this.agrCertificates = HashMap.newHashMap(nodeIds.size());
        this.nodeIds = Collections.unmodifiableSet(Objects.requireNonNull(nodeIds, MSG_NODES_TO_START_NON_NULL));
    }

    /**
     * Scan the directory specified by {@code paths.keyDirPath} configuration element for key stores. This method will
     * process and load keys found in both the legacy or enhanced formats.
     *
     * @return this {@link EnhancedKeyStoreLoader} instance.
     */
    public EnhancedKeyStoreLoader scan() throws KeyLoadingException, KeyStoreException {
        final KeyStore legacyPublicStore = resolveLegacyPublicStore();

        for (final NodeId nodeId : this.nodeIds) {
            if (nodeIds.contains(nodeId)) {
                sigPrivateKeys.compute(nodeId, (k, v) -> resolveNodePrivateKey(nodeId));
            }

            sigCertificates.compute(nodeId, (k, v) -> resolveNodeCertificate(nodeId, legacyPublicStore));
        }

        return this;
    }

    /**
     * Iterates over the local nodes and creates the agreement key and certificate for each.  This method should be
     * called after {@link #scan()} and before {@link #verify()}.
     *
     * @return this {@link EnhancedKeyStoreLoader} instance.
     * @throws NoSuchAlgorithmException if the algorithm required to generate the key pair is not available.
     * @throws NoSuchProviderException  if the security provider required to generate the key pair is not available.
     * @throws KeyGeneratingException   if an error occurred while generating the agreement key pair.
     */
    public EnhancedKeyStoreLoader generate()
            throws NoSuchAlgorithmException, NoSuchProviderException, KeyGeneratingException {

        for (final NodeId nodeId : nodeIds) {
            if (!agrPrivateKeys.containsKey(nodeId)) {
                // Generate a new agreement key since it does not exist
                final KeyPair agrKeyPair = KeysAndCertsGenerator.generateAgreementKeyPair();
                agrPrivateKeys.put(nodeId, agrKeyPair.getPrivate());

                // recover signing key pair to be root of trust on agreement certificate
                final PrivateKey privateSigningKey = sigPrivateKeys.get(nodeId);
                final X509Certificate signingCert = (X509Certificate) sigCertificates.get(nodeId);
                if (privateSigningKey == null || signingCert == null) {
                    continue;
                }
                final PublicKey publicSigningKey = signingCert.getPublicKey();
                final KeyPair signingKeyPair = new KeyPair(publicSigningKey, privateSigningKey);

                // generate the agreement certificate
                final String dnA = CryptoStatic.distinguishedName(KeyCertPurpose.AGREEMENT.storeName(nodeId));
                final X509Certificate agrCert = CryptoStatic.generateCertificate(
                        dnA,
                        agrKeyPair,
                        signingCert.getSubjectX500Principal().getName(),
                        signingKeyPair,
                        SecureRandom.getInstanceStrong(),
                        SIG_TYPE2);
                agrCertificates.put(nodeId, agrCert);
            }
        }
        return this;
    }

    /**
     * Verifies the presence of all required keys based on the address book provided during initialization.
     *
     * @return this {@link EnhancedKeyStoreLoader} instance.
     * @throws KeyLoadingException if one or more of the required keys were not loaded.
     * @throws KeyStoreException    if an error occurred while parsing the key store or the key store is not
     *                              initialized.
     */
    public EnhancedKeyStoreLoader verify() throws KeyLoadingException, KeyStoreException {
        for (final NodeId nodeId : this.nodeIds) {
            try {
                if (!sigPrivateKeys.containsKey(nodeId)) {
                    throw new KeyLoadingException("No private key found for nodeId %s [ purpose = %s ]"
                            .formatted(nodeId, KeyCertPurpose.SIGNING));
                }

                if (!agrPrivateKeys.containsKey(nodeId)) {
                    throw new KeyLoadingException("No private key found for nodeId %s [purpose = %s ]"
                            .formatted(nodeId, KeyCertPurpose.AGREEMENT));
                }

                // the agreement certificate must be present for local nodes
                if (!agrCertificates.containsKey(nodeId)) {
                    throw new KeyLoadingException("No certificate found for nodeId %s [purpose = %s ]"
                            .formatted(nodeId, KeyCertPurpose.AGREEMENT));
                }

                if (!sigCertificates.containsKey(nodeId)) {
                    throw new KeyLoadingException("No certificate found for nodeId %s [purpose = %s ]"
                            .formatted(nodeId, KeyCertPurpose.SIGNING));
                }
            } catch (final KeyLoadingException e) {
                throw e;
            }
        }

        return this;
    }

    /**
     * Creates a map containing the private keys for all local nodes and the public keys for all nodes using the
     * supplied address book.
     *
     * @return the map of all keys and certificates per {@link NodeId}.
     * @throws KeyStoreException   if an error occurred while parsing the key store or the key store is not
     *                             initialized.
     * @throws KeyLoadingException if one or more of the required keys were not loaded or are not of the correct type.
     */
    public Map<NodeId, KeysAndCerts> keysAndCerts() throws KeyStoreException, KeyLoadingException {
        final Map<NodeId, KeysAndCerts> keysAndCerts = HashMap.newHashMap(nodeIds.size());
        final Map<NodeId, X509Certificate> signing = signingCertificates();

        for (final NodeId nodeId : this.nodeIds) {
            final Certificate agrCert = agrCertificates.get(nodeId);
            final PrivateKey sigPrivateKey = sigPrivateKeys.get(nodeId);
            final PrivateKey agrPrivateKey = agrPrivateKeys.get(nodeId);

            if (sigPrivateKey == null) {
                throw new KeyLoadingException("No signing private key found for nodeId: %s".formatted(nodeId));
            }

            if (agrPrivateKey == null) {
                throw new KeyLoadingException("No agreement private key found for nodeId: %s".formatted(nodeId));
            }

            // the agreement certificate must be present for local nodes
            if (agrCert == null) {
                throw new KeyLoadingException("No agreement certificate found for nodeId: %s".formatted(nodeId));
            }

            if (!(agrCert instanceof final X509Certificate x509AgrCert)) {
                throw new KeyLoadingException("Illegal agreement certificate type for nodeId: %s [ purpose = %s ]"
                        .formatted(nodeId, KeyCertPurpose.AGREEMENT));
            }

            final X509Certificate sigCert = signing.get(nodeId);

            final KeyPair sigKeyPair = new KeyPair(sigCert.getPublicKey(), sigPrivateKey);
            final KeyPair agrKeyPair = new KeyPair(agrCert.getPublicKey(), agrPrivateKey);
            final KeysAndCerts kc = new KeysAndCerts(sigKeyPair, agrKeyPair, sigCert, x509AgrCert);

            keysAndCerts.put(nodeId, kc);
        }

        return keysAndCerts;
    }

    private Map<NodeId, X509Certificate> signingCertificates() throws KeyLoadingException {
        final Map<NodeId, X509Certificate> certs = HashMap.newHashMap(nodeIds.size());
        for (final NodeId nodeId : this.nodeIds) {
            final Certificate sigCert = sigCertificates.get(nodeId);

            if (sigCert == null) {
                throw new KeyLoadingException("No signing certificate found for nodeId: %s".formatted(nodeId));
            }
            if (!(sigCert instanceof final X509Certificate x509SigCert)) {
                throw new KeyLoadingException("Illegal signing certificate type for nodeId: %s [ purpose = %s ]"
                        .formatted(nodeId, KeyCertPurpose.SIGNING));
            }
            certs.put(nodeId, x509SigCert);
        }
        return certs;
    }

    /**
     * Attempts to locate the legacy (combined) public key store and load it.
     *
     * @return the legacy public key store fully loaded; otherwise, an empty key store.
     * @throws KeyLoadingException if the legacy public key store cannot be loaded or is empty.
     * @throws KeyStoreException   if an error occurred while parsing the key store or the key store is not
     *                             initialized.
     */
    private KeyStore resolveLegacyPublicStore() throws KeyLoadingException, KeyStoreException {
        final Path legacyStorePath = legacyCertificateStore();

        if (Files.exists(legacyStorePath)) {
            return loadKeys(legacyStorePath, keyStorePassphrase);
        }

        return createEmptyTrustStore();
    }

    /**
     * Attempts to locate a private key for the specified {@code nodeId}, {@code nodeAlias}, and {@code purpose}.
     *
     * <p>
     * This method will attempt to load the private key stores in the following order:
     * <ol>
     *     <li>Enhanced private key store ({@code [type]-private-[alias].pem})</li>
     *     <li>Legacy private key store ({@code private-[alias].pfx})</li>
     * </ol>
     *
     * @param nodeId the {@link NodeId} for which the private key should be loaded.
     * @return the private key for the specified {@code nodeId}, {@code nodeAlias}, and {@code purpose}; otherwise,
     * {@code null} if no key was found.
     * @throws NullPointerException if {@code nodeId}, {@code nodeAlias}, or {@code purpose} is {@code null}.
     */
    private PrivateKey resolveNodePrivateKey(final NodeId nodeId) {
        Objects.requireNonNull(nodeId, MSG_NODE_ID_NON_NULL);

        // Check for the enhanced private key store. The enhance key store is preferred over the legacy key store.
        Path ksLocation = privateKeyStore(nodeId);
        if (Files.exists(ksLocation)) {
            return readPrivateKey(nodeId, ksLocation);
        }

        // Check for the legacy private key store.
        ksLocation = legacyPrivateKeyStore(nodeId);
        if (Files.exists(ksLocation)) {
            return readLegacyPrivateKey(nodeId, ksLocation, KeyCertPurpose.SIGNING.storeName(nodeId));
        }

        // No keys were found so return null. Missing keys will be detected during a call to
        // EnhancedKeyStoreLoader::verify() or EnhancedKeyStoreLoader::keysAndCerts().
        return null;
    }

    /**
     * Attempts to locate a certificate for the specified {@code nodeId}, {@code nodeAlias}, and {@code purpose}.
     * <p>
     * This method will attempt to load the certificate stores in the following order:
     * <ol>
     *     <li>Enhanced certificate store ({@code [type]-public-[alias].pem})</li>
     *     <li>Legacy certificate store ({@code public.pfx})</li>
     * </ol>
     *
     * @param nodeId            the {@link NodeId} for which the certificate should be loaded.
     * @param legacyPublicStore the preloaded legacy public key store to fallback on if the enhanced certificate store
     *                          is not found.
     * @return the certificate for the specified {@code nodeId}, {@code nodeAlias}, and {@code purpose}; otherwise,
     * {@code null} if no certificate was found.
     * @throws NullPointerException if {@code nodeId}, {@code nodeAlias}, {@code purpose}, or {@code legacyPublicStore}
     *                              is {@code null}.
     */
    private Certificate resolveNodeCertificate(final NodeId nodeId, final KeyStore legacyPublicStore) {
        Objects.requireNonNull(nodeId, MSG_NODE_ID_NON_NULL);
        Objects.requireNonNull(KeyCertPurpose.SIGNING, MSG_PURPOSE_NON_NULL);
        Objects.requireNonNull(legacyPublicStore, MSG_LEGACY_PUBLIC_STORE_NON_NULL);

        // Check for the enhanced certificate store. The enhanced certificate store is preferred over the legacy
        // certificate store.
        Path ksLocation = certificateStore(nodeId);
        if (Files.exists(ksLocation)) {
            return readCertificate(nodeId, ksLocation);
        }

        // Check for the legacy certificate store.
        ksLocation = legacyCertificateStore();
        if (Files.exists(ksLocation)) {
            return readLegacyCertificate(nodeId, legacyPublicStore);
        }

        // No certificates were found so return null. Missing certificates will be detected during a call to
        // EnhancedKeyStoreLoader::verify() or EnhancedKeyStoreLoader::keysAndCerts().
        return null;
    }

    /**
     * Attempts to read a certificate contained in an enhanced store from the specified {@code location} for the
     * specified {@code nodeId}.
     *
     * @param nodeId   the {@link NodeId} for which the certificate should be loaded.
     * @param location the location of the enhanced certificate store.
     * @return the certificate for the specified {@code nodeId}; otherwise, {@code null} if no certificate was found or
     * an error occurred while attempting to read the store.
     * @throws NullPointerException if {@code nodeId} or {@code location} is {@code null}.
     */
    private Certificate readCertificate(final NodeId nodeId, final Path location) {
        Objects.requireNonNull(nodeId, MSG_NODE_ID_NON_NULL);
        Objects.requireNonNull(location, MSG_LOCATION_NON_NULL);

        try {
            return readEnhancedStore(location, Certificate.class);
        } catch (final KeyLoadingException e) {
            return null;
        }
    }

    /**
     * Attempts to read a certificate contained in the legacy store from the specified {@code legacyPublicStore} for the
     * specified {@code nodeId}, {@code nodeAlias}, and {@code purpose}.
     *
     * @param nodeId            the {@link NodeId} for which the certificate should be loaded.
     * @param legacyPublicStore the preloaded legacy public key store from which to load the certificate.
     * @return the certificate for the specified {@code nodeId}; otherwise, {@code null} if no certificate was found or
     * an error occurred while attempting to read the store.
     * @throws NullPointerException if {@code nodeId}, {@code nodeAlias}, {@code purpose}, or {@code legacyPublicStore}
     *                              is {@code null}.
     */
    private Certificate readLegacyCertificate(final NodeId nodeId, final KeyStore legacyPublicStore) {
        Objects.requireNonNull(nodeId, MSG_NODE_ID_NON_NULL);
        Objects.requireNonNull(legacyPublicStore, MSG_LEGACY_PUBLIC_STORE_NON_NULL);

        try {
            final Certificate cert = legacyPublicStore.getCertificate(KeyCertPurpose.SIGNING.storeName(nodeId));

            // Legacy certificate store was found, but did not contain the certificate requested.

            return cert;
        } catch (final KeyStoreException e) {
            return null;
        }
    }

    /**
     * Attempts to read a private key contained in an enhanced store from the specified {@code location} for the
     * specified {@code nodeId}.
     *
     * @param nodeId   the {@link NodeId} for which the private key should be loaded.
     * @param location the location of the enhanced private key store.
     * @return the private key for the specified {@code nodeId}; otherwise, {@code null} if no private key was found or
     * an error occurred while attempting to read the store.
     * @throws NullPointerException if {@code nodeId} or {@code location} is {@code null}.
     */
    PrivateKey readPrivateKey(final NodeId nodeId, final Path location) {
        Objects.requireNonNull(nodeId, MSG_NODE_ID_NON_NULL);
        Objects.requireNonNull(location, MSG_LOCATION_NON_NULL);

        try {
            return readEnhancedStore(location, PrivateKey.class);
        } catch (final KeyLoadingException e) {
            return null;
        }
    }

    /**
     * Attempts to read a private key contained in the legacy store from the specified {@code location} for the
     * specified {@code nodeId} and {@code entryName}.
     *
     * @param nodeId    the {@link NodeId} for which the private key should be loaded.
     * @param location  the location of the legacy private key store.
     * @param entryName the name of the entry in the legacy private key store.
     * @return the private key for the specified {@code nodeId}; otherwise, {@code null} if no private key was found or
     * an error occurred while attempting to read the store.
     * @throws NullPointerException if {@code nodeId}, {@code location}, or {@code entryName} is {@code null}.
     */
    private PrivateKey readLegacyPrivateKey(final NodeId nodeId, final Path location, final String entryName) {
        Objects.requireNonNull(nodeId, MSG_NODE_ID_NON_NULL);
        Objects.requireNonNull(location, MSG_LOCATION_NON_NULL);

        try {
            final KeyStore ks = loadKeys(location, keyStorePassphrase);
            final Key k = ks.getKey(entryName, keyStorePassphrase);

            return (k instanceof final PrivateKey pk) ? pk : null;
        } catch (final KeyLoadingException
                | KeyStoreException
                | UnrecoverableKeyException
                | NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Utility method for resolving the {@link Path} to the enhanced private key store for the specified
     * {@code nodeAlias} and {@code purpose}.
     *
     * @param nodeId the alias of the node for which the private key store should be loaded.
     * @return the {@link Path} to the enhanced private key store for the specified {@code nodeAlias} and
     * {@code purpose}.
     * @throws NullPointerException if {@code nodeAlias} or {@code purpose} is {@code null}.
     */
    private Path privateKeyStore(final NodeId nodeId) {
        return keyStoreDirectory.resolve(
                String.format("%s-private-%s.pem", KeyCertPurpose.SIGNING.prefix(), nodeId.formatNodeName()));
    }

    /**
     * Utility method for resolving the {@link Path} to the legacy private key store for the specified
     * {@code nodeAlias}.
     *
     * @param nodeId            the {@link NodeId} for which the certificate should be loaded.
     * @return the {@link Path} to the legacy private key store for the specified {@code nodeAlias}.
     * @throws NullPointerException if {@code nodeAlias} is {@code null}.
     */
    private Path legacyPrivateKeyStore(final NodeId nodeId) {
        Objects.requireNonNull(nodeId, MSG_NODE_ALIAS_NON_NULL);
        return keyStoreDirectory.resolve(String.format("private-%s.pfx", nodeId.formatNodeName()));
    }

    /**
     * Utility method for resolving the {@link Path} to the enhanced certificate store for the specified
     * {@code nodeAlias} and {@code purpose}.
     *
     * @param nodeId the {@link NodeId} for which the certificate should be loaded.
     * @return the {@link Path} to the enhanced certificate store for the specified {@code nodeAlias} and
     * {@code purpose}.
     * @throws NullPointerException if {@code nodeAlias} or {@code purpose} is {@code null}.
     */
    private Path certificateStore(final NodeId nodeId) {
        Objects.requireNonNull(nodeId, MSG_NODE_ID_NON_NULL);
        return keyStoreDirectory.resolve(
                String.format("%s-public-%s.pem", KeyCertPurpose.SIGNING.prefix(), nodeId.formatNodeName()));
    }

    /**
     * Utility method for resolving the {@link Path} to the legacy certificate store.
     *
     * @return the {@link Path} to the legacy certificate store.
     */
    private Path legacyCertificateStore() {
        return keyStoreDirectory.resolve(PUBLIC_KEYS_FILE);
    }

    /**
     * Utility method for reading a specific {@code entryType} from an enhanced key store at the specified
     * {@code location}.
     *
     * @param location  the {@link Path} to the enhanced key store.
     * @param entryType the {@link Class} instance of the requested entry type.
     * @param <T>       the type of entry to load from the key store.
     * @return the entry of the specified {@code entryType} from the key store.
     * @throws KeyLoadingException  if an error occurred while attempting to read the key store or the requested entry
     *                              was not found.
     * @throws NullPointerException if {@code location} or {@code entryType} is {@code null}.
     */
    private <T> T readEnhancedStore(final Path location, final Class<T> entryType) throws KeyLoadingException {
        Objects.requireNonNull(location, MSG_LOCATION_NON_NULL);
        Objects.requireNonNull(entryType, MSG_ENTRY_TYPE_NON_NULL);

        try (final PEMParser parser =
                new PEMParser(new InputStreamReader(Files.newInputStream(location), StandardCharsets.UTF_8))) {
            Object entry;

            while ((entry = parser.readObject()) != null) {
                if (isCompatibleStoreEntry(entry, entryType)) {
                    break;
                }
            }

            if (entry == null) {
                throw new KeyLoadingException("No entry of the requested type found [ entryType = %s, fileName = %s ]"
                        .formatted(entryType.getName(), location.getFileName()));
            }

            return extractEntityOfType(entry, entryType);
        } catch (final IOException | DecoderException e) {
            throw new KeyLoadingException(
                    "Unable to read enhanced store [ fileName = %s ]".formatted(location.getFileName()), e);
        }
    }

    /**
     * Helper method related to {@link #readEnhancedStore(Path, Class)} used to extract the requested {@code entryType}
     * from the specified {@code entry} loaded from the store.
     *
     * @param entry     the entry loaded from the store.
     * @param entryType the {@link Class} instance of the requested entry type.
     * @param <T>       the type of entry to load from the key store.
     * @return the requested entry of the specified {@code entryType}.
     * @throws KeyLoadingException  if an error occurred while attempting to extract the requested entry or entry is an
     *                              unsupported type.
     * @throws NullPointerException if {@code entry} or {@code entryType} is {@code null}.
     */
    @SuppressWarnings("unchecked")
    private <T> T extractEntityOfType(final Object entry, final Class<T> entryType) throws KeyLoadingException {
        Objects.requireNonNull(entry, MSG_ENTRY_NON_NULL);
        Objects.requireNonNull(entryType, MSG_ENTRY_TYPE_NON_NULL);

        if (entryType.isAssignableFrom(PublicKey.class)) {
            return (T) extractPublicKeyEntity(entry);
        } else if (entryType.isAssignableFrom(PrivateKey.class)) {
            return (T) extractPrivateKeyEntity(entry);
        } else if (entryType.isAssignableFrom(Certificate.class)) {
            return (T) extractCertificateEntity(entry);
        } else {
            throw new KeyLoadingException("Unsupported entry type [ entryType = %s ]".formatted(entryType.getName()));
        }
    }

    /**
     * Helper method used by {@link #extractEntityOfType(Object, Class)} for extracting a {@link PublicKey} from the
     * specified {@code entry}.
     *
     * @param entry the entry loaded from the store.
     * @return the {@link PublicKey} extracted from the specified {@code entry}.
     * @throws KeyLoadingException  if an error occurred while attempting to extract the {@link PublicKey} from the
     *                              specified {@code entry}.
     * @throws NullPointerException if {@code entry} is {@code null}.
     */
    private PublicKey extractPublicKeyEntity(final Object entry) throws KeyLoadingException {
        Objects.requireNonNull(entry, MSG_ENTRY_NON_NULL);

        try {
            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            final PEMDecryptorProvider decrypter = new JcePEMDecryptorProviderBuilder().build(keyStorePassphrase);

            return switch (entry) {
                case final SubjectPublicKeyInfo spki -> converter.getPublicKey(spki);
                case final PEMKeyPair kp -> converter.getPublicKey(kp.getPublicKeyInfo());
                case final PEMEncryptedKeyPair ekp ->
                    converter.getPublicKey(ekp.decryptKeyPair(decrypter).getPublicKeyInfo());
                default ->
                    throw new KeyLoadingException("Unsupported entry type [ entryType = %s ]"
                            .formatted(entry.getClass().getName()));
            };
        } catch (final IOException e) {
            throw new KeyLoadingException(
                    "Unable to extract a public key from the specified entry [ entryType = %s ]"
                            .formatted(entry.getClass().getName()),
                    e);
        }
    }

    /**
     * Helper method used by {@link #extractEntityOfType(Object, Class)} for extracting a {@link PrivateKey} from the
     * specified {@code entry}.
     *
     * @param entry the entry loaded from the store.
     * @return the {@link PrivateKey} extracted from the specified {@code entry}.
     * @throws KeyLoadingException  if an error occurred while attempting to extract the {@link PrivateKey} from the
     *                              specified {@code entry}.
     * @throws NullPointerException if {@code entry} is {@code null}.
     */
    private PrivateKey extractPrivateKeyEntity(final Object entry) throws KeyLoadingException {
        Objects.requireNonNull(entry, MSG_ENTRY_NON_NULL);

        try {
            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            final PEMDecryptorProvider decrypter = new JcePEMDecryptorProviderBuilder().build(keyStorePassphrase);
            final InputDecryptorProvider inputDecrypter =
                    new JceInputDecryptorProviderBuilder().build(new String(keyStorePassphrase).getBytes());

            return switch (entry) {
                case final PrivateKeyInfo pki -> converter.getPrivateKey(pki);
                case final PKCS8EncryptedPrivateKeyInfo epki ->
                    converter.getPrivateKey(epki.decryptPrivateKeyInfo(inputDecrypter));
                case final PEMKeyPair kp -> converter.getPrivateKey(kp.getPrivateKeyInfo());
                case final PEMEncryptedKeyPair ekp ->
                    converter.getPrivateKey(ekp.decryptKeyPair(decrypter).getPrivateKeyInfo());
                default ->
                    throw new KeyLoadingException("Unsupported entry type [ entryType = %s ]"
                            .formatted(entry.getClass().getName()));
            };
        } catch (final IOException | PKCSException e) {
            throw new KeyLoadingException(
                    "Unable to extract a private key from the specified entry [ entryType = %s ]"
                            .formatted(entry.getClass().getName()),
                    e);
        }
    }

    /**
     * Helper method used by {@link #extractEntityOfType(Object, Class)} for extracting a {@link Certificate} from the
     * specified {@code entry}.
     *
     * @param entry the entry loaded from the store.
     * @return the {@link Certificate} extracted from the specified {@code entry}.
     * @throws KeyLoadingException  if an error occurred while attempting to extract the {@link Certificate} from the
     *                              specified {@code entry}.
     * @throws NullPointerException if {@code entry} is {@code null}.
     */
    private Certificate extractCertificateEntity(final Object entry) throws KeyLoadingException {
        Objects.requireNonNull(entry, MSG_ENTRY_NON_NULL);

        try {
            if (entry instanceof final X509CertificateHolder ch) {
                return new JcaX509CertificateConverter().getCertificate(ch);
            }

            throw new KeyLoadingException("Unsupported entry type [ entryType = %s ]"
                    .formatted(entry.getClass().getName()));
        } catch (final CertificateException e) {
            throw new KeyLoadingException(
                    "Unable to extract a certificate from the specified entry [ entryType = %s ]"
                            .formatted(entry.getClass().getName()),
                    e);
        }
    }

    /**
     * Utility method for determining if the specified {@code entry} is compatible with the specified
     * {@code entryType}.
     *
     * @param entry     the entry loaded from the store.
     * @param entryType the {@link Class} instance of the requested entry type.
     * @param <T>       the type of entry to load from the key store.
     * @return {@code true} if the specified {@code entry} is compatible with the specified {@code entryType};
     * otherwise, {@code false}.
     * @throws NullPointerException if {@code entry} or {@code entryType} is {@code null}.
     */
    private static <T> boolean isCompatibleStoreEntry(final Object entry, final Class<T> entryType) {
        Objects.requireNonNull(entry, MSG_ENTRY_NON_NULL);
        Objects.requireNonNull(entryType, MSG_ENTRY_TYPE_NON_NULL);

        if (entryType.isAssignableFrom(PublicKey.class)
                && (entry instanceof SubjectPublicKeyInfo
                        || entry instanceof PEMKeyPair
                        || entry instanceof PEMEncryptedKeyPair)) {
            return true;
        } else if (entryType.isAssignableFrom(PrivateKey.class)
                && (entry instanceof PEMKeyPair
                        || entry instanceof PrivateKeyInfo
                        || entry instanceof PKCS8EncryptedPrivateKeyInfo
                        || entry instanceof PEMEncryptedKeyPair)) {
            return true;
        } else if (entryType.isAssignableFrom(KeyPair.class)
                && (entry instanceof PEMKeyPair || entry instanceof PEMEncryptedKeyPair)) {
            return true;
        } else {
            return entryType.isAssignableFrom(Certificate.class) && entry instanceof X509CertificateHolder;
        }
    }

    // ----------------------------------------------------------------------------------------------
    //                                   MIGRATION METHODS
    // ----------------------------------------------------------------------------------------------

    /**
     * Performs any necessary migration steps to ensure the key storage is up-to-date.
     * <p>
     * As of release 0.56 the on-disk cryptography should reflect the following structure:
     * <ul>
     *     <li>s-private-alias.pem - the private signing key </li>
     *     <li>s-public-alias.pem - the public signing certificates of each node</li>
     *     <li>all *.pfx files moved to <b>OLD_PFX_KEYS</b> subdirectory and no longer used.</li>
     *     <li>all agreement key material is deleted from disk.</li>
     * </ul>
     *
     * @return this {@link EnhancedKeyStoreLoader} instance.
     */
    public EnhancedKeyStoreLoader migrate() throws KeyLoadingException, KeyStoreException {
        final Map<NodeId, PrivateKey> pfxPrivateKeys = new HashMap<>();
        final Map<NodeId, Certificate> pfxCertificates = new HashMap<>();

        // delete agreement keys permanently.  They are being created at startup by generateIfNecessary() after scan().
        deleteAgreementKeys();

        // create PEM files for signing keys and certs.
        long errorCount = extractPrivateKeysAndCertsFromPfxFiles(pfxPrivateKeys, pfxCertificates);

        if (errorCount == 0) {
            // validate only when there are no errors extracting pem files.
            errorCount = validateKeysAndCertsAreLoadableFromPemFiles(pfxPrivateKeys, pfxCertificates);
        }

        if (errorCount > 0) {
            // roll back due to errors.
            // this deletes any pem files created, but leaves the agreement keys deleted.
            rollBackSigningKeysAndCertsChanges(pfxPrivateKeys, pfxCertificates);
        } else {
            // cleanup pfx files by moving them to subdirectory
            cleanupByMovingPfxFilesToSubDirectory();
        }

        return this;
    }

    /**
     * Delete any agreement keys from the key store directory.
     */
    private void deleteAgreementKeys() {
        // delete any agreement keys of the form a-*
        final File[] agreementKeyFiles = keyStoreDirectory.toFile().listFiles((dir, name) -> name.startsWith("a-"));
        if (agreementKeyFiles != null) {
            for (final File agreementKeyFile : agreementKeyFiles) {
                if (agreementKeyFile.isFile()) {
                    try {
                        Files.delete(agreementKeyFile.toPath());
                    } catch (final IOException e) {
                    }
                }
            }
        }
    }

    /**
     * Extracts the private keys and certificates from the PFX files and writes them to PEM files.
     *
     * @param pfxPrivateKeys  the map of private keys being extracted (Updated By Method Call)
     * @param pfxCertificates the map of certificates being extracted (Updated By Method Call)
     * @return the number of errors encountered during the extraction process.
     * @throws KeyStoreException   if the underlying method calls throw this exception.
     * @throws KeyLoadingException if the underlying method calls throw this exception.
     */
    private long extractPrivateKeysAndCertsFromPfxFiles(
            final Map<NodeId, PrivateKey> pfxPrivateKeys, final Map<NodeId, Certificate> pfxCertificates)
            throws KeyStoreException, KeyLoadingException {
        final KeyStore legacyPublicStore = resolveLegacyPublicStore();
        final AtomicLong errorCount = new AtomicLong(0);

        for (final NodeId nodeId : this.nodeIds) {
            // extract private keys for local nodes
            final Path sPrivateKeyLocation =
                    keyStoreDirectory.resolve(String.format("s-private-%s.pem", nodeId.formatNodeName()));
            final Path privateKs = legacyPrivateKeyStore(nodeId);
            if (!Files.exists(sPrivateKeyLocation) && Files.exists(privateKs)) {
                final PrivateKey privateKey =
                        readLegacyPrivateKey(nodeId, privateKs, KeyCertPurpose.SIGNING.storeName(nodeId));
                pfxPrivateKeys.put(nodeId, privateKey);
                if (privateKey == null) {
                    errorCount.incrementAndGet();
                } else {
                    try {
                        writePemFile(true, sPrivateKeyLocation, privateKey.getEncoded());
                    } catch (final IOException e) {
                        errorCount.incrementAndGet();
                    }
                }
            }

            // extract certificates for all nodes
            final Path sCertificateLocation =
                    keyStoreDirectory.resolve(String.format("s-public-%s.pem", nodeId.formatNodeName()));
            final Path ksLocation = legacyCertificateStore();
            if (!Files.exists(sCertificateLocation) && Files.exists(ksLocation)) {
                final Certificate certificate = readLegacyCertificate(nodeId, legacyPublicStore);
                pfxCertificates.put(nodeId, certificate);
                if (certificate == null) {
                    errorCount.incrementAndGet();
                } else {
                    try {
                        writePemFile(false, sCertificateLocation, certificate.getEncoded());
                    } catch (final CertificateEncodingException | IOException e) {
                        errorCount.incrementAndGet();
                    }
                }
            }
        }
        return errorCount.get();
    }

    /**
     * Validates that the private keys and certs in PEM files are loadable and match the PFX loaded keys and certs.
     *
     * @param pfxPrivateKeys  the map of private keys being extracted.
     * @param pfxCertificates the map of certificates being extracted.
     * @return the number of errors encountered during the validation process.
     */
    private long validateKeysAndCertsAreLoadableFromPemFiles(
            final Map<NodeId, PrivateKey> pfxPrivateKeys, final Map<NodeId, Certificate> pfxCertificates) {
        final AtomicLong errorCount = new AtomicLong(0);
        for (final NodeId nodeId : this.nodeIds) {
            if (pfxCertificates.containsKey(nodeId)) {
                // validate private keys for local nodes
                final Path ksLocation = privateKeyStore(nodeId);
                final PrivateKey pemPrivateKey = readPrivateKey(nodeId, ksLocation);
                if (pemPrivateKey == null
                        || !Arrays.equals(
                                pemPrivateKey.getEncoded(),
                                pfxPrivateKeys.get(nodeId).getEncoded())) {
                    errorCount.incrementAndGet();
                }
            }

            // validate certificates for all nodes PEM files were created for.
            if (pfxCertificates.containsKey(nodeId)) {
                final Path ksLocation = certificateStore(nodeId);
                final Certificate pemCertificate = readCertificate(nodeId, ksLocation);
                try {
                    if (pemCertificate == null
                            || !Arrays.equals(
                                    pemCertificate.getEncoded(),
                                    pfxCertificates.get(nodeId).getEncoded())) {
                        errorCount.incrementAndGet();
                    }
                } catch (final CertificateEncodingException e) {
                    errorCount.incrementAndGet();
                }
            }
        }
        return errorCount.get();
    }

    /**
     * Rollback the creation of PEM files for signing keys and certificates.
     *
     * @param pfxPrivateKeys  the map of private keys being extracted.
     * @param pfxCertificates the map of certificates being extracted.
     */
    private void rollBackSigningKeysAndCertsChanges(
            final Map<NodeId, PrivateKey> pfxPrivateKeys, final Map<NodeId, Certificate> pfxCertificates) {

        final AtomicLong cleanupErrorCount = new AtomicLong(0);
        for (final NodeId nodeId : this.nodeIds) {
            // private key rollback
            if (pfxPrivateKeys.containsKey(nodeId)) {
                try {
                    Files.deleteIfExists(privateKeyStore(nodeId));
                } catch (final IOException e) {
                    cleanupErrorCount.incrementAndGet();
                }
            }
            // certificate rollback
            if (pfxCertificates.containsKey(nodeId)) {
                try {
                    Files.deleteIfExists(certificateStore(nodeId));
                } catch (final IOException e) {
                    cleanupErrorCount.incrementAndGet();
                }
            }
        }
        if (cleanupErrorCount.get() > 0) {
            throw new IllegalStateException("Cryptography Migration failed to generate or validate PEM files.");
        }
    }

    /**
     * Move the PFX files to the OLD_PFX_KEYS subdirectory.
     */
    private void cleanupByMovingPfxFilesToSubDirectory() {
        final AtomicLong cleanupErrorCount = new AtomicLong(0);
        final AtomicBoolean doCleanup = new AtomicBoolean(false);
        for (final NodeId nodeId : this.nodeIds) {
            // move private key PFX files per local node
            final File sPrivatePfx = legacyPrivateKeyStore(nodeId).toFile();
            if (sPrivatePfx.exists() && sPrivatePfx.isFile()) {
                doCleanup.set(true);
            }
        }

        if (!doCleanup.get()) return;

        final String archiveDirectory = ".archive";
        final String now = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss").format(LocalDateTime.now());
        final String newDirectory = archiveDirectory + File.pathSeparator + now;
        final Path pfxArchiveDirectory = keyStoreDirectory.resolve(archiveDirectory);
        final Path pfxDateDirectory = pfxArchiveDirectory.resolve(now);

        if (!Files.exists(pfxDateDirectory)) {
            try {
                if (!Files.exists(pfxArchiveDirectory)) {
                    Files.createDirectory(pfxArchiveDirectory);
                }
                Files.createDirectory(pfxDateDirectory);
            } catch (final IOException e) {
                return;
            }
        }
        for (final NodeId nodeId : this.nodeIds) {
            // move private key PFX files per local node
            final File sPrivatePfx = legacyPrivateKeyStore(nodeId).toFile();
            if (sPrivatePfx.exists()
                    && sPrivatePfx.isFile()
                    && !sPrivatePfx.renameTo(
                            pfxDateDirectory.resolve(sPrivatePfx.getName()).toFile())) {
                cleanupErrorCount.incrementAndGet();
            }
        }
        final File sPublicPfx = legacyCertificateStore().toFile();
        if (sPublicPfx.exists()
                && sPublicPfx.isFile()
                && !sPublicPfx.renameTo(
                        pfxDateDirectory.resolve(sPublicPfx.getName()).toFile())) {
            cleanupErrorCount.incrementAndGet();
        }
        if (cleanupErrorCount.get() > 0) {
            throw new IllegalStateException(
                    "Cryptography Migration failed to move PFX files to [" + newDirectory + "] subdirectory.");
        }
    }

    /**
     * Write the provided encoded key or certificate as a base64 DER encoded PEM file to the provided location.
     *
     * @param isPrivateKey true if the encoded data is a private key; false if it is a certificate.
     * @param location     the location to write the PEM file.
     * @param encoded      the byte encoded data to write to the PEM file.
     * @throws IOException if an error occurred while writing the PEM file.
     */
    public static void writePemFile(final boolean isPrivateKey, final Path location, final byte[] encoded)
            throws IOException {
        final PemObject pemObj = new PemObject(isPrivateKey ? "PRIVATE KEY" : "CERTIFICATE", encoded);
        try (final FileOutputStream file = new FileOutputStream(location.toFile(), false);
                final var out = new OutputStreamWriter(file);
                final PemWriter writer = new PemWriter(out)) {
            writer.writeObject(pemObj);
            file.getFD().sync();
        }
    }
}
