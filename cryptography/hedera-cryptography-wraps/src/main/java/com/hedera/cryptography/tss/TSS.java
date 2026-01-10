// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.tss;

import com.hedera.cryptography.hints.HintsLibraryBridge;
import com.hedera.cryptography.wraps.WRAPSLibraryBridge;
import java.util.Arrays;

/**
 * Convenience API for Threshold Signature Scheme (TSS) verification.
 */
public final class TSS {

    private static final int HINTS_VERIFICATION_KEY_LENGTH = 1288;
    private static final int HINTS_SIGNATURE_LENGTH = 1632;
    private static final int COMPRESSED_WRAPS_PROOF_LENGTH = 704;
    private static final int AGGREGATE_SCHNORR_SIGNATURE_LENGTH = 64;

    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();
    private static final WRAPSLibraryBridge WRAPS = WRAPSLibraryBridge.getInstance();

    /** A mutable array of Schnorr public keys. */
    private static byte[][] schnorrPublicKeys;

    private TSS() {}

    /**
     * A convenience method to prepare a `tssSignature` composite array.
     *
     * @param hintsVerificationKey `HintsLibraryBridge.preprocess().verificationKey()`
     * @param hintsSignature `HintsLibraryBridge.aggregateSignatures()`
     * @param abProof either `WRAPSLibraryBridge.constructWrapsProof().compressed()`, or
     *                `WRAPSLibraryBridge.runSigningProtocolPhase(SigningProtocolPhase.Aggregate)`
     * @return the composite `tssSignature` array which is a simple concatenation of the input arrays in their
     *         respective order
     * @throws IllegalArgumentException if any of the arguments are malformed
     */
    public static byte[] composeSignature(
            final byte[] hintsVerificationKey, final byte[] hintsSignature, final byte[] abProof)
            throws IllegalArgumentException {
        if (hintsVerificationKey == null || hintsVerificationKey.length != HINTS_VERIFICATION_KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "`hintsVerificationKey` must have a length of " + HINTS_VERIFICATION_KEY_LENGTH);
        }
        if (hintsSignature == null || hintsSignature.length != HINTS_SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("`hintsSignature` must have a length of " + HINTS_SIGNATURE_LENGTH);
        }
        if (abProof == null
                || (abProof.length != COMPRESSED_WRAPS_PROOF_LENGTH
                        && abProof.length != AGGREGATE_SCHNORR_SIGNATURE_LENGTH)) {
            throw new IllegalArgumentException("`abProof` must have a length of " + COMPRESSED_WRAPS_PROOF_LENGTH
                    + " or " + AGGREGATE_SCHNORR_SIGNATURE_LENGTH);
        }

        final byte[] array = Arrays.copyOf(
                hintsVerificationKey, hintsVerificationKey.length + hintsSignature.length + abProof.length);
        System.arraycopy(hintsSignature, 0, array, hintsVerificationKey.length, hintsSignature.length);
        System.arraycopy(abProof, 0, array, hintsVerificationKey.length + hintsSignature.length, abProof.length);
        return array;
    }

    /**
     * Sets the Schnorr public keys to the specified array. This method DOES NOT create a defensive copy
     * of the data. Therefore, the client code is fully responsible for keeping the keys immutable.
     * Also, the client code is fully responsible for thread-safety of this method with respect to calling
     * the `TSS.verifyTSS()` method that may use the Schnorr public keys when a WRAPS proof hasn't been provided.
     * @param schnorrPublicKeys the Schnorr public keys
     */
    public static void setSchnorrPublicKeys(byte[][] schnorrPublicKeys) {
        TSS.schnorrPublicKeys = schnorrPublicKeys;
    }

    /**
     * A convenience API to verify a `tssSignature` on a `message` with a given `ledgerId`.
     * <p>
     * The `ledgerId` identifies a specific network that signed the `message` and is a hash of the genesis AddressBook
     * as computed by the `WRAPSLibraryBridge.hashAddressBook()`.
     * <p>
     * The `tssSignature` is a composite array which is a simple concatenation of a `hints_verification_key`,
     * `hints_signature`, and an AddressBook proof data. See `TSS.composeSignature()` above for details.
     * <p>
     * The `message` is a message that has been signed via `HintsLibraryBridge.signBls()` prior to calling
     * the `HintsLibraryBridge.aggregateSignatures()` that produced the above `hints_signature`.
     * In Hiero networks, the `message` is likely a "block_root_hash".
     * <p>
     * The `ledgerId` is generally verified via the provided WRAPS compressed proof using a WRAPS verification key
     * currently installed in the library. During a network genesis, the WRAPS proof may be unavailable for the first
     * few blocks, in which case the WRAPS proof in the `tssSignature` is replaced with an `aggregate_schnorr_signature`
     * that has a different length. When this is the case, this method will check if the `aggregate_schnorr_signature`
     * is valid for the `ledgerId` as a message that was signed, using the Schnorr public keys set via a call to the
     * `TSS.setSchnorrPublicKeys()` method. If the client didn't set any keys before calling `TSS.verifyTSS(), then
     * the verification will fail and return false. While it's okay not to set the keys if the client code is certain
     * that only real WRAPS proofs will be used for verification, it is still STRONGLY recommended to set the Schnorr
     * keys unconditionally just in case.
     * <p>
     * The `message` is verified against the provided `hints_signature` using the default threshold of strictly greater
     * than 1/2 of the network weight. See the three arguments version of the `HintsLibraryBridge.verifyAggregate()`
     * for details.
     *
     * @param ledgerId genesis_ab_hash
     * @param tssSignature hints_verification_key || hints_signature || [wraps_proof | aggregate_schnorr_signature]
     * @param message a message
     * @return true if both the message and the ledgerId verify successfully with the respective signatures and proofs.
     * @throws IllegalStateException if the `tssSignature` provides `aggregate_schnorr_signature` instead of
     *                                  `wraps_proof`, but Schnorr public keys haven't been provided via a call to
     *                                  `TSS.setSchnorrPublicKeys()` yet
     * @throws IllegalArgumentException if any of the arguments are malformed
     */
    public static boolean verifyTSS(final byte[] ledgerId, final byte[] tssSignature, final byte[] message)
            throws IllegalStateException, IllegalArgumentException {
        // First, check constraints
        if (ledgerId == null || ledgerId.length != 32) {
            throw new IllegalArgumentException("`ledgerId` must be a 32 bytes array, instead got "
                    + (ledgerId == null ? null : (ledgerId.length + "")));
        }
        if (tssSignature == null || tssSignature.length <= HINTS_VERIFICATION_KEY_LENGTH + HINTS_SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("`tssSignature` is too short. Expected more than "
                    + (HINTS_VERIFICATION_KEY_LENGTH + HINTS_SIGNATURE_LENGTH)
                    + " bytes, instead got " + (tssSignature == null ? null : (tssSignature.length + "")));
        }
        if (message == null || message.length == 0) {
            throw new IllegalArgumentException("`message` must be a non-empty array");
        }

        // Then check if the `ledgerId` verifies:
        final byte[] hintsVerificationKey = Arrays.copyOfRange(tssSignature, 0, HINTS_VERIFICATION_KEY_LENGTH);
        final byte[] abProof = Arrays.copyOfRange(
                tssSignature, HINTS_VERIFICATION_KEY_LENGTH + HINTS_SIGNATURE_LENGTH, tssSignature.length);
        if (abProof.length == COMPRESSED_WRAPS_PROOF_LENGTH) {
            if (!WRAPS.verifyCompressedProof(abProof, ledgerId, hintsVerificationKey)) {
                return false;
            }
        } else if (abProof.length == AGGREGATE_SCHNORR_SIGNATURE_LENGTH) {
            if (TSS.schnorrPublicKeys == null) {
                throw new IllegalStateException("Schnorr public keys haven't been provided");
            }

            // We sign a rotation message with Schnorr signatures, so we have to prepare it first:
            final byte[] hintsKeyHash = WRAPS.hashArray(hintsVerificationKey);
            final byte[] rotationMessage = Arrays.copyOf(ledgerId, ledgerId.length + hintsKeyHash.length);
            System.arraycopy(hintsKeyHash, 0, rotationMessage, ledgerId.length, hintsKeyHash.length);

            if (!WRAPS.verifySignature(TSS.schnorrPublicKeys, rotationMessage, abProof)) {
                return false;
            }
        } else {
            throw new IllegalArgumentException(
                    "The AddressBook proof part of the `tssSignature` is neither a compressed WRAPS proof"
                            + " with length "
                            + COMPRESSED_WRAPS_PROOF_LENGTH + ", nor an aggregate Schnorr signature with length "
                            + AGGREGATE_SCHNORR_SIGNATURE_LENGTH + ". Instead, its length is "
                            + abProof.length);
        }

        // Finally check if the `message` verifies via hinTS:
        final byte[] hintsSignature = Arrays.copyOfRange(
                tssSignature, HINTS_VERIFICATION_KEY_LENGTH, HINTS_VERIFICATION_KEY_LENGTH + HINTS_SIGNATURE_LENGTH);
        return HINTS.verifyAggregate(hintsSignature, message, hintsVerificationKey);
    }
}
