// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

import com.hedera.common.nativesupport.SingletonLoader;

/**
 * A JNI Bridge for the HistoryLibrary implementation as defined at
 * https://github.com/hashgraph/hedera-services/blob/main/hedera-node/hedera-app/src/main/java/com/hedera/node/app/history/HistoryLibrary.java .
 */
public class HistoryLibraryBridge {
    /** Instance Holder for lazy loading and concurrency handling */
    private static final SingletonLoader<HistoryLibraryBridge> INSTANCE_HOLDER =
            new SingletonLoader<>("rpm", new HistoryLibraryBridge());

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
     * Returns the SNARK verification key in use by this library.
     * <p>
     * <b>Important:</b> If this changes, the ledger id must also change.
     */
    public native byte[] snarkVerificationKey();

    /**
     * Returns a new Schnorr key pair.
     */
    public native byte[] newSchnorrKeyPair();

    /**
     * Signs a message with a Schnorr private key. In Hiero TSS, this will always be the concatenation
     * of an address book hash and the associated metadata.
     *
     * @param message the message
     * @param privateKey the private key
     * @return the signature
     */
    public native byte[] signSchnorr(final byte[] message, final byte[] privateKey);

    /**
     * Checks that a signature on a message verifies under a Schnorr public key.
     *
     * @param signature the signature
     * @param message the message
     * @param publicKey the public key
     * @return true if the signature is valid; false otherwise
     */
    public native boolean verifySchnorr(final byte[] signature, final byte[] message, final byte[] publicKey);

    /**
     * Computes the hash of the given address book with the same algorithm used by the SNARK circuit.
     * @param addressBook the address book
     * @return the hash of the address book
     */
    public native byte[] hashAddressBook(final byte[] addressBook);

    /**
     * Returns a SNARK recursively proving the target address book and associated metadata belong to the given ledger
     * id's chain of trust that includes the given source address book, based on its own proof of belonging. (Unless the
     * source address book hash <i>is</i> the ledger id, which is the base case of the recursion).
     * <p>
     * The {@code nodeIds} and  {@code sourceSignatures} arrays together model the higher level
     * {@code Map<Long, Bytes> sourceSignatures}, and use arrays for performance reasons.
     *
     * @param ledgerId the ledger id, the concatenation of the genesis address book hash and the SNARK verification key
     * @param sourceProof if not null, the proof the source address book is in the ledger id's chain of trust
     * @param sourceAddressBook the source roster
     * @param nodeIds nodeIds for the signatures in sourceSignatures
     * @param sourceSignatures the source address book signatures on the target address book hash and its metadata
     * @param targetAddressBookHash the hash of the target address book
     * @param targetMetadata the metadata of the target address book
     * @return the SNARK proving the target address book and metadata belong to the ledger id's chain of trust
     */
    public native byte[] proveChainOfTrust(
            final byte[] ledgerId,
            final byte[] sourceProof,
            final byte[] sourceAddressBook,
            final long[] nodeIds,
            final byte[][] sourceSignatures,
            final byte[] targetAddressBookHash,
            final byte[] targetMetadata);

    /**
     * Verifies the given SNARK proves the given address book hash and associated metadata belong to the given
     * ledger id's chain of trust
     * @param ledgerId the ledger id
     * @param addressBookHash the hash of the address book
     * @param metadata the metadata associated to the address book
     * @param proof the SNARK proving the address book hash and metadata belong to the ledger id's chain of trust
     * @return true if the proof is valid; false otherwise
     */
    public native boolean verifyChainOfTrust(
            final byte[] ledgerId, final byte[] addressBookHash, final byte[] metadata, final byte[] proof);
}
