// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import com.hedera.common.nativesupport.SingletonLoader;

/**
 * A JNI Bridge for the HintsLibrary implementation as defined at
 * https://github.com/hashgraph/hedera-services/blob/main/hedera-node/hedera-app/src/main/java/com/hedera/node/app/hints/HintsLibrary.java .
 */
public class HintsLibraryBridge {
    /** Instance Holder for lazy loading and concurrency handling */
    private static final SingletonLoader<HintsLibraryBridge> INSTANCE_HOLDER =
            new SingletonLoader<>("hints", new HintsLibraryBridge());

    static {
        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        HintsLibraryBridge.class
                .getModule()
                .addOpens(INSTANCE_HOLDER.getNativeLibraryPackageName(), SingletonLoader.class.getModule());
    }

    private HintsLibraryBridge() {
        // private constructor to ensure singleton
    }

    /**
     * Returns the singleton instance of this library adapter.
     *
     * @return the singleton instance of this library adapter.
     */
    public static HintsLibraryBridge getInstance() {
        return INSTANCE_HOLDER.getInstance();
    }

    ///////////////////////////////////////////////////////////////////////////
    //                    CRS management methods
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Generates a new CRS object for the given number of signers.
     * @param signersNum the number of signers
     * @return the CRS object
     */
    public native byte[] initCRS(long signersNum);

    /**
     * Update a previous CRS object with a new contribution.
     * @param prevCRS the previous CRS object
     * @param random the random contribution of 128 bits (16 bytes)
     * @return the updated CRS object and a concatenated contribution proof for the update
     */
    public native byte[] updateCRS(final byte[] prevCRS, final byte[] random);

    /**
     * Verifies an updated CRS object.
     * @param prevCRS the previous CRS object
     * @param nextCRS the updated CRS object
     * @param contributionProof the contribution proof
     * @return true if the updated CRS object is valid, false otherwise
     */
    public native boolean verifyCRS(final byte[] prevCRS, final byte[] nextCRS, final byte[] contributionProof);

    ///////////////////////////////////////////////////////////////////////////
    //                          HinTS APIs
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Generates a new BLS key pair.
     * @return the key pair
     */
    public native byte[] newBlsKeyPair();

    /**
     * Computes the hints for the given public key and number of parties.
     *
     * @param crs the CRS object
     * @param blsPrivateKey the private key
     * @param partyId the party id
     * @param n the number of parties
     * @return the hints
     */
    public native byte[] computeHints(final byte[] crs, final byte[] blsPrivateKey, int partyId, int n);

    /**
     * Validates the hinTS public key for the given number of parties.
     *
     * @param crs the CRS object
     * @param hintsPublicKey the hinTS key
     * @param partyId the party id
     * @param n the number of parties
     * @return true if the hints are valid; false otherwise
     */
    public native boolean validateHintsKey(final byte[] crs, final byte[] hintsPublicKey, int partyId, int n);

    /**
     * Runs the hinTS preprocessing algorithm on the given validated hint keys and party weights for the given number
     * of parties. The output includes,
     * <ol>
     *     <li>The linear size aggregation key to use in combining partial signatures on a message with a provably
     *     well-formed aggregate public key.</li>
     *     <li>The succinct verification key to use when verifying an aggregate signature.</li>
     * </ol>
     * The parties, hintsPublicKeys, and weights model the original {@code Map<Integer, Bytes> hintsPublicKeys} and {@code
     * Map<Integer, Long> weights} input arguments and use arrays for performance reasons.
     * @param crs the CRS object
     * @param parties the party ids for the indices in hintsPublicKeys and weights
     * @param hintsPublicKeys the valid hinTS keys by party id
     * @param weights the weights by party id
     * @param n the number of parties
     * @return the preprocessed keys
     */
    public native byte[] preprocess(
            final byte[] crs, final int[] parties, final byte[][] hintsPublicKeys, final long[] weights, int n);

    /**
     * Signs a message with a BLS private key.
     *
     * @param message the message
     * @param privateKey the private key
     * @return the signature
     */
    public native byte[] signBls(final byte[] message, final byte[] privateKey);

    /**
     * Checks that a signature on a message verifies under a BLS public key.
     *
     * @param crs the CRS object
     * @param signature the signature
     * @param message the message
     * @param publicKey the public key
     * @return true if the signature is valid; false otherwise
     */
    public native boolean verifyBls(
            final byte[] crs, final byte[] signature, final byte[] message, final byte[] publicKey);

    /**
     * Aggregates the signatures for party ids using hinTS aggregation and verification keys.
     *
     * @param crs the CRS object
     * @param aggregationKey the aggregation key
     * @param verificationKey the verification key
     * @param parties the party ids for the partialSignatures array
     * @param partialSignatures the partial signatures by party id
     * @return the aggregated signature
     */
    public native byte[] aggregateSignatures(
            final byte[] crs,
            final byte[] aggregationKey,
            final byte[] verificationKey,
            final int[] parties,
            final byte[][] partialSignatures);

    /**
     * Checks an aggregate signature on a message verifies under a hinTS verification key, where
     * this is only true if the aggregate signature has weight exceeding the specified threshold
     * or total weight stipulated in the verification key.
     *
     * @param crs the CRS object
     * @param signature the aggregate signature
     * @param message the message
     * @param verificationKey the verification key
     * @param thresholdNumerator the numerator of a fraction of total weight the signature must have
     * @param thresholdDenominator the denominator of a fraction of total weight the signature must have
     * @return true if the signature is valid; false otherwise
     */
    public native boolean verifyAggregate(
            final byte[] crs,
            final byte[] signature,
            final byte[] message,
            final byte[] verificationKey,
            long thresholdNumerator,
            long thresholdDenominator);
}
