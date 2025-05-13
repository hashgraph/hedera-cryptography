// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

import com.hedera.common.nativesupport.SingletonLoader;
import com.hedera.cryptography.hints.HintsLibraryBridge;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A JNI Bridge for the HistoryLibrary implementation as defined at
 * https://github.com/hashgraph/hedera-services/blob/main/hedera-node/hedera-app/src/main/java/com/hedera/node/app/history/HistoryLibrary.java .
 */
public class HistoryLibraryBridge {
    /** Instance Holder for lazy loading and concurrency handling */
    private static final SingletonLoader<HistoryLibraryBridge> INSTANCE_HOLDER =
            new SingletonLoader<>("raps", new HistoryLibraryBridge());

    static {
        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        HistoryLibraryBridge.class
                .getModule()
                .addOpens(INSTANCE_HOLDER.getNativeLibraryPackageName(), SingletonLoader.class.getModule());
    }

    private HistoryLibraryBridge() {
        // private constructor to ensure singleton
    }

    /**
     * Returns the singleton instance of this library adapter.
     *
     * @return the singleton instance of this library adapter.
     */
    public static HistoryLibraryBridge getInstance() {
        return INSTANCE_HOLDER.getInstance();
    }

    /**
     * Loads the Succinct RISC-V zkVM implementing the AddressBook rotation program,
     * which is in the ELF (executable and linkable) format.
     *
     * @return a byte array with the ELF
     * @throws IOException if I/O errors occur
     */
    public static byte[] loadAddressBookRotationProgram() throws IOException {
        try (final InputStream is = HistoryLibraryBridge.class.getResourceAsStream("/ab-rotation-program");
                final ByteArrayOutputStream baos = new ByteArrayOutputStream(); ) {
            // The current program is about 350KB, so try to read it in one go
            byte[] buffer = new byte[400 * 1024];
            int bytesRead;

            while ((bytesRead = is.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }

            return baos.toByteArray();
        }
    }

    /**
     * Returns the SNARK verification key in use by this library.
     * <p>
     * <b>Important:</b> If this changes, the ledger id must also change.
     * @param elf the ELF (executable and linkable format) file for the Succinct RISC-V zkVM
     */
    public native ProvingAndVerifyingSnarkKeys snarkVerificationKey(final byte[] elf);

    /**
     * Returns a new Schnorr key pair.
     * @param random the random 256 bits (32 bytes)
     */
    public native SigningAndVerifyingSchnorrKeys newSchnorrKeyPair(final byte[] random);

    /**
     * Constructs a rotation message by concatenating the hash of the next address book with the hash
     * of the hinTS VerificationKey.
     * @param nextAddressBookHash the hash of the next address book
     * @param hintsVerificationKeyHash the hash of the hinTS VerificationKey
     * @return
     */
    public static byte[] formatRotationMessage(
            final byte[] nextAddressBookHash, final byte[] hintsVerificationKeyHash) {
        final byte[] arr = new byte[nextAddressBookHash.length + hintsVerificationKeyHash.length];
        System.arraycopy(nextAddressBookHash, 0, arr, 0, nextAddressBookHash.length);
        System.arraycopy(hintsVerificationKeyHash, 0, arr, nextAddressBookHash.length, hintsVerificationKeyHash.length);
        return arr;
    }

    /**
     * Signs a rotation message with a Schnorr signing key. In Hiero TSS, this message will always be the concatenation
     * of an address book hash and the hash of the hinTS VerificationKey as returned by the HistoryLibraryBridge.formatRotationMessage()
     * method.
     *
     * @param message the message
     * @param signingKey the signing key
     * @return the signature
     */
    public native byte[] signSchnorr(final byte[] message, final byte[] signingKey);

    /**
     * Checks that a signature on a message verifies under a Schnorr verifying key.
     *
     * @param signature the signature
     * @param message the message
     * @param verifyingKey the verifying key
     * @return true if the signature is valid; false otherwise
     */
    public native boolean verifySchnorr(final byte[] signature, final byte[] message, final byte[] verifyingKey);

    /**
     * Computes the hash of the given address book with the same algorithm used by the SNARK circuit.
     * <p>
     * The verifyingKeys and weights arrays model the address book. The elements of these arrays are related,
     * so that verifyingKeys[0] is a verifying key for a node with a weight of weights[0]. Note that the order
     * of the entries matters, and should generally match the order of the nodes in the actual AddressBook
     * (e.g. sorted by the increasing nodeId.)
     *
     * @param verifyingKeys the address book verifying keys
     * @param weights the address book weights
     * @return the hash of the address book
     */
    public byte[] hashAddressBook(final byte[][] verifyingKeys, final long[] weights) {
        if (verifyingKeys == null
                || weights == null
                || verifyingKeys.length != weights.length
                || !HintsLibraryBridge.validateWeightsSum(weights)) {
            return null;
        }
        return hashAddressBookImpl(verifyingKeys, weights);
    }

    private native byte[] hashAddressBookImpl(final byte[][] verifyingKeys, final long[] weights);

    /**
     * Returns a hash of the given hinTS verification key.
     * @param verificationKey the hinTS verification key as obtained from HintsLibraryBridge.preprocess()
     * @return the hash of the given key
     */
    public native byte[] hashHintsVerificationKey(final byte[] verificationKey);

    /**
     * Returns a SNARK recursively proving the next address book and associated metadata belong to the given ledger
     * id's chain of trust that includes the given current address book, based on its own proof of belonging. (Unless the
     * source address book hash <i>is</i> the ledger id, which is the base case of the recursion).
     *
     * @param snarkProvingKey the SNARK proving key
     * @param snarkVerifyingKey the SNARK verifying key
     * @param genesisAddressBookHash the hash of the genesis address book
     *
     * @param currentAddressBookVerifyingKeys the current address book verifying keys
     * @param currentAddressBookWeights the current address book weights
     *
     * @param nextAddressBookVerifyingKeys the next address book verifying keys
     * @param nextAddressBookWeights the next address book weights
     *
     * @param currentAddressBookProof the current address book proof, or null if it's the genesis address book
     *
     * @param nextAddressBookHintsVerificationKeyHash the hash of the next address book hinTS verification key
     * @param signatures the Schnorr signatures produced by the current address book for the next address book
     *
     * @return the SNARK proving the next address book and metadata belong to the ledger id's chain of trust
     */
    public byte[] proveChainOfTrust(
            final byte[] snarkProvingKey,
            final byte[] snarkVerifyingKey,
            final byte[] genesisAddressBookHash,
            final byte[][] currentAddressBookVerifyingKeys,
            final long[] currentAddressBookWeights,
            final byte[][] nextAddressBookVerifyingKeys,
            final long[] nextAddressBookWeights,
            final byte[] currentAddressBookProof,
            final byte[] nextAddressBookHintsVerificationKeyHash,
            final byte[][] signatures) {
        if (snarkProvingKey == null
                || snarkProvingKey.length == 0
                || genesisAddressBookHash == null
                || genesisAddressBookHash.length == 0
                || currentAddressBookVerifyingKeys == null
                || currentAddressBookVerifyingKeys.length == 0
                || currentAddressBookWeights == null
                || currentAddressBookWeights.length == 0
                || nextAddressBookVerifyingKeys == null
                || nextAddressBookVerifyingKeys.length == 0
                || nextAddressBookWeights == null
                || nextAddressBookWeights.length == 0
                || nextAddressBookHintsVerificationKeyHash == null
                || nextAddressBookHintsVerificationKeyHash.length == 0
                || signatures == null
                || signatures.length == 0
                || !HintsLibraryBridge.validateWeightsSum(currentAddressBookWeights)
                || !HintsLibraryBridge.validateWeightsSum(nextAddressBookWeights)) {
            return null;
        }
        if (currentAddressBookVerifyingKeys.length != currentAddressBookWeights.length
                || signatures.length != currentAddressBookWeights.length
                || nextAddressBookVerifyingKeys.length != nextAddressBookWeights.length) {
            return null;
        }
        if (currentAddressBookProof != null && currentAddressBookProof.length == 0) {
            return null;
        }
        return proveChainOfTrustImpl(
                snarkProvingKey,
                snarkVerifyingKey,
                genesisAddressBookHash,
                currentAddressBookVerifyingKeys,
                currentAddressBookWeights,
                nextAddressBookVerifyingKeys,
                nextAddressBookWeights,
                currentAddressBookProof,
                nextAddressBookHintsVerificationKeyHash,
                signatures);
    }

    private native byte[] proveChainOfTrustImpl(
            final byte[] snarkProvingKey,
            final byte[] snarkVerifyingKey,
            final byte[] genesisAddressBookHash,
            final byte[][] currentAddressBookVerifyingKeys,
            final long[] currentAddressBookWeights,
            final byte[][] nextAddressBookVerifyingKeys,
            final long[] nextAddressBookWeights,
            final byte[] currentAddressBookProof,
            final byte[] nextAddressBookHintsVerificationKeyHash,
            final byte[][] signatures);

    /**
     * Verifies the given SNARK proves the given address book hash and associated metadata belong to the given
     * ledger id's chain of trust
     * @param snarkVerifyingKey the SNARK verifying key
     * @param proof the SNARK proving the address book hash and metadata belong to the ledger id's chain of trust
     * @return true if the proof is valid; false otherwise
     */
    public native boolean verifyChainOfTrust(final byte[] snarkVerifyingKey, final byte[] proof);
}
