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
     * Generates a new CRS object for the given number of signers plus 1.
     * <p>
     * The provided signersNum argument must be greater than the maximum number of nodes
     * that the network supports by at least 1. For example, if the network supports up to 1023 nodes,
     * then the signersNum argument must be equal to at least 1024. It's mathematically
     * okay to have the singersNum much larger than the current number of nodes in the network,
     * however, this will result in a larger space required to store the CRS.
     *
     * @param signersNum the number of signers plus 1
     * @return the CRS object
     */
    public byte[] initCRS(short signersNum) {
        // Support a degenerate case of 0 signers, or a normal case with more signers. Otherwise, error out.
        if (signersNum < 1) {
            return null;
        }
        return initCRSImpl(signersNum);
    }

    private native byte[] initCRSImpl(short signersNum);

    /**
     * Update a previous CRS object with a new contribution.
     * @param prevCRS the previous CRS object
     * @param random the random contribution of 256 bits (32 bytes)
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
     * Generates a new secret key.
     * @param random 32 random bytes
     * @return the secret key, or null on error
     */
    public native byte[] generateSecretKey(final byte[] random);

    /**
     * Computes the hints for the given secret key and number of parties.
     *
     * @param crs the CRS object
     * @param secretKey the secret key
     * @param partyId the party id
     * @param n the number of parties
     * @return the hints
     */
    public byte[] computeHints(final byte[] crs, final byte[] secretKey, int partyId, int n) {
        if (!validateCRS(crs, n) || !validatePartyId(partyId, n) || secretKey == null) {
            return null;
        }
        return computeHintsImpl(crs, secretKey, partyId, n);
    }

    private native byte[] computeHintsImpl(final byte[] crs, final byte[] secretKey, int partyId, int n);

    /**
     * Validates the hinTS public key for the given number of parties.
     *
     * @param crs the CRS object
     * @param hintsPublicKey the hinTS key
     * @return true if the hints are valid; false otherwise
     */
    public boolean validateHintsKey(final byte[] crs, final byte[] hintsPublicKey, int partyId, int n) {
        if (!validateCRS(crs, n) || !validatePartyId(partyId, n) || hintsPublicKey == null) {
            return false;
        }
        return validateHintsKeyImpl(crs, hintsPublicKey, partyId, n);
    }

    private native boolean validateHintsKeyImpl(final byte[] crs, final byte[] hintsPublicKey, int partyId, int n);

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
     * <p>
     * NOTE: this preprocess() method needs to learn about weights and hints of all the parties that could possibly
     * take part in signing, even though some of the parties may not always contribute their partial signatures,
     * e.g. if the nodes are down, or the latency is high, and we only see signatures that we've received so far.
     * This is needed so that the verifyAggregate() method can consider the proper signing threshold when verifying
     * an aggregate signature.
     * <p>
     * NOTE: the maximum number of parties is equal to n-1. E.g. if n is equal to 4, then the parties, hintsPublicKeys, and
     * weights can contain at most 3 elements. Otherwise, the HinTS algorithms won't produce correct results.
     *
     * @param crs the CRS object
     * @param parties the party ids for the indices in hintsPublicKeys and weights
     * @param hintsPublicKeys the valid hinTS keys by party id
     * @param weights the weights by party id
     * @param n the number of parties
     * @return the preprocessed keys
     */
    public AggregationAndVerificationKeys preprocess(
            final byte[] crs, final int[] parties, final byte[][] hintsPublicKeys, final long[] weights, int n) {
        // Basic sanity
        if (!validateCRS(crs, n) || parties == null || hintsPublicKeys == null || weights == null) {
            return null;
        }
        // ensure the arrays modeling the map are good and satisfy the maximum size constraint
        if (parties.length >= n || hintsPublicKeys.length != parties.length || weights.length != parties.length) {
            return null;
        }
        // ensure all the partiIds, hintsPublicKeys, and weights make sense
        for (int i = 0; i < parties.length; i++) {
            if (!validatePartyId(parties[i], n)) {
                return null;
            }
            if (hintsPublicKeys[i] == null || weights[i] < 0) {
                return null;
            }
        }
        return preprocessImpl(crs, parties, hintsPublicKeys, weights, n);
    }

    private native AggregationAndVerificationKeys preprocessImpl(
            final byte[] crs, final int[] parties, final byte[][] hintsPublicKeys, final long[] weights, int n);

    /**
     * Signs a message with a BLS private key.
     *
     * @param message the message
     * @param privateKey the private key
     * @return the signature
     */
    public byte[] signBls(final byte[] message, final byte[] privateKey) {
        if (message == null || message.length == 0 || privateKey == null || privateKey.length == 0) {
            return null;
        }
        return signBlsImpl(message, privateKey);
    }

    private native byte[] signBlsImpl(final byte[] message, final byte[] privateKey);

    /**
     * Checks that a signature on a message verifies under a BLS public key.
     *
     * @param signature the signature
     * @param message the message
     * @param aggregationKey the extended public key
     * @param partyId the party id whose public key from the aggregationKey should be used for verifying the signature
     * @return true if the signature is valid; false otherwise
     */
    public boolean verifyBls(
            final byte[] signature, final byte[] message, final byte[] aggregationKey, final int partyId) {
        if (signature == null
                || signature.length == 0
                || message == null
                || message.length == 0
                || aggregationKey == null
                || aggregationKey.length == 0) {
            return false;
        }
        return verifyBlsImpl(signature, message, aggregationKey, partyId);
    }

    private native boolean verifyBlsImpl(
            final byte[] signature, final byte[] message, final byte[] aggregationKey, final int partyId);

    /**
     * Checks that a batch of signatures on a message verifies under a BLS public key.
     *
     * @param message the message
     * @param aggregationKey the extended public key
     * @param parties the party ids for the partialSignatures array
     * @param partialSignatures the partial signatures by party id
     * @return true if the signature is valid; false otherwise
     */
    public boolean verifyBlsBatch(
            final byte[] message, final byte[] aggregationKey, final int[] parties, final byte[][] partialSignatures) {
        if (message == null
                || message.length == 0
                || aggregationKey == null
                || aggregationKey.length == 0
                || parties == null
                || parties.length == 0
                || partialSignatures == null
                || partialSignatures.length == 0
                || parties.length != partialSignatures.length) {
            return false;
        }
        return verifyBlsBatchImpl(message, aggregationKey, parties, partialSignatures);
    }

    private native boolean verifyBlsBatchImpl(
            final byte[] message, final byte[] aggregationKey, final int[] parties, final byte[][] partialSignatures);

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
    public byte[] aggregateSignatures(
            final byte[] crs,
            final byte[] aggregationKey,
            final byte[] verificationKey,
            final int[] parties,
            final byte[][] partialSignatures) {
        if (crs == null
                || crs.length == 0
                || aggregationKey == null
                || aggregationKey.length == 0
                || verificationKey == null
                || verificationKey.length == 0
                || parties == null
                || parties.length == 0
                || partialSignatures == null
                || partialSignatures.length == 0
                || parties.length != partialSignatures.length) {
            return null;
        }
        return aggregateSignaturesImpl(crs, aggregationKey, verificationKey, parties, partialSignatures);
    }

    private native byte[] aggregateSignaturesImpl(
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
     * @param signature the aggregate signature
     * @param message the message
     * @param verificationKey the verification key
     * @param thresholdNumerator the numerator of a fraction of total weight the signature must have
     * @param thresholdDenominator the denominator of a fraction of total weight the signature must have
     * @return true if the signature is valid; false otherwise
     */
    public boolean verifyAggregate(
            final byte[] signature,
            final byte[] message,
            final byte[] verificationKey,
            long thresholdNumerator,
            long thresholdDenominator) {
        if (signature == null
                || signature.length == 0
                || message == null
                || message.length == 0
                || verificationKey == null
                || verificationKey.length == 0
                || thresholdNumerator <= 0L
                || thresholdDenominator <= 0L) {
            return false;
        }
        return verifyAggregateImpl(signature, message, verificationKey, thresholdNumerator, thresholdDenominator);
    }

    private native boolean verifyAggregateImpl(
            final byte[] signature,
            final byte[] message,
            final byte[] verificationKey,
            long thresholdNumerator,
            long thresholdDenominator);

    // Returns true if the n is a positive power of two, and the crs isn't null and its length matches or is greater
    // than the n.
    private static boolean validateCRS(final byte[] crs, final int n) {
        return n > 0 && (n & (n - 1)) == 0 && crs != null && crs.length >= (304 + n * 288);
    }

    private static int inferNFromCRSLength(final byte[] crs) {
        if (crs == null) {
            return -1;
        }
        return (crs.length - 304) / 288;
    }

    // Returns true if 0 <= partiyId < n.
    private static boolean validatePartyId(final int partyId, final int n) {
        return partyId >= 0 && partyId < n;
    }
}
