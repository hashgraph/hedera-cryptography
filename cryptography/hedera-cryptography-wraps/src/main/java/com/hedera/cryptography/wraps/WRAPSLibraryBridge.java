// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.wraps;

import com.hedera.common.nativesupport.SingletonLoader;
import java.io.File;
import java.util.Arrays;
import java.util.Set;

/**
 * A JNI bridge for the WRAPS 2.0 library APIs that allow participants to generate and verify recursive proofs for AddressBooks.
 */
public class WRAPSLibraryBridge {
    /** Instance Holder for lazy loading and concurrency handling */
    private static final SingletonLoader<WRAPSLibraryBridge> INSTANCE_HOLDER =
            new SingletonLoader<>("wraps", new WRAPSLibraryBridge());

    /** The max theoretical sum of weights all nodes together can have, which is 2^63-1 because we use signed long. */
    private static final long MAX_SUM_OF_WEIGHTS = Long.MAX_VALUE;

    static {
        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        WRAPSLibraryBridge.class
                .getModule()
                .addOpens(INSTANCE_HOLDER.getNativeLibraryPackageName(), SingletonLoader.class.getModule());
    }

    private WRAPSLibraryBridge() {
        // private constructor to ensure singleton
    }

    /**
     * Returns the singleton instance of this library adapter.
     * <p>
     * An optional TSS_LIB_WRAPS_SWAP_FILE environment variable may be defined to point to a file name
     * that will be used as a memory-on-disk for the WRAPS 2.0 native code.
     * The size of the file is hard-coded in the native code as a static constant due to Rust language specifics.
     * See src/main/rust/wraps/src/alloc.rs for the definitions.
     * If the env var is undefined, or the file cannot be open/created/resized, or any other errors occur,
     * then the library will use the system RAM only.
     *
     * @return the singleton instance of this library adapter.
     */
    public static WRAPSLibraryBridge getInstance() {
        return INSTANCE_HOLDER.getInstance();
    }

    /**
     * Checks if proof construction and verification is potentially supported.
     * Both the operations build crypto keys from binary artifacts read from disk
     * at the path specified by the TSS_LIB_WRAPS_ARTIFACTS_PATH environment variable.
     * If the variable is unset or empty, or the specified path doesn't contain
     * the expected files, then this method returns false.
     * Note that only absolute paths are supported. The path MUST NOT contain double periods at all.
     * @return true if `constructWrapsProof` and `verifyCompressedProof` are operational
     */
    public static boolean isProofSupported() {
        final String path = System.getenv("TSS_LIB_WRAPS_ARTIFACTS_PATH");
        if (path == null || path.isBlank()) {
            return false;
        }
        // Don't support relative paths because absolute paths are safer.
        // In fact, we don't support unusual file or dir names with double periods at all:
        if (path.contains("..")) {
            return false;
        }
        File dir = new File(path);
        if (!dir.exists() || !dir.isDirectory()) {
            return false;
        }
        final Set<String> files = Set.of(dir.list());
        if (!files.equals(Set.of("decider_pp.bin", "decider_vp.bin", "nova_pp.bin", "nova_vp.bin"))) {
            return false;
        }
        return true;
    }

    // ------------------------------------------------------------------------------------------------------
    // DEFINITIONS BELOW MUST MATCH THEIR NATIVE CODE COUNTER-PARTS (see src/rust/wraps/src/lib.rs):
    // ------------------------------------------------------------------------------------------------------

    /** Size of a random seed. */
    public static final int ENTROPY_SIZE = 32;

    /** Signing protocol phase. */
    public enum SigningProtocolPhase {
        R1,
        R2,
        R3,
        Aggregate
    }

    // ------------------------------------------------------------------------------------------------------
    // END OF DEFINITIONS MATCHING THE NATIVE CODE.
    // ------------------------------------------------------------------------------------------------------

    // The following constants aren't explicitly defined in native code, but these are the sizes that we see:
    private static final int ROUND1_MESSAGE_SIZE = 40;
    private static final int ROUND2_3_MESSAGE_SIZE = 72;

    /**
     * Derives a Schnorr keypair deterministically from the provided entropy.
     * @param seed ENTROPY_SIZE-byte entropy used to sample the private key deterministically.
     * @return a Schnorr keypair, or null if the seed isn't ENTROPY_SIZE bytes long or an error occurs
     */
    public SchnorrKeys generateSchnorrKeys(final byte[] seed) {
        if (seed == null || seed.length != ENTROPY_SIZE) {
            return null;
        }
        return generateSchnorrKeysImpl(seed);
    }

    private native SchnorrKeys generateSchnorrKeysImpl(byte[] seed);

    private static final byte[][] EMPTY_BYTE_ARRAY_2 = new byte[0][];

    /**
     * Executes a single phase of the threshold Schnorr signing protocol.
     * @param phase Which protocol phase to execute (R1, R2, R3, or Aggregate).
     * @param instanceEntropy Participant-specific randomness reused across rounds.
     * @param messageToSign Byte message that rounds R3/Aggregate must attest.
     * @param schnorrPrivateKey Optional private key required only during phases R1-R3. null in Aggregate.
     * @param schnorrPublicKeys Participants' public keys; must be present for phases beyond R1.
     * @param round1Messages Messages collected from prior rounds.
     * @param round2Messages Messages collected from prior rounds.
     * @param round3Messages Messages collected from prior rounds.
     * @return either a round message for R1...R3, or a signature for Aggregate
     */
    public byte[] runSigningProtocolPhase(
            final SigningProtocolPhase phase,
            final byte[] instanceEntropy,
            final byte[] messageToSign,
            final byte[] schnorrPrivateKey,
            byte[][] schnorrPublicKeys,
            byte[][] round1Messages,
            byte[][] round2Messages,
            byte[][] round3Messages) {
        if (phase == null || messageToSign == null) {
            return null;
        }

        // Just to simplify the API usage and the native bridge implementation:
        if (schnorrPublicKeys == null) {
            schnorrPublicKeys = EMPTY_BYTE_ARRAY_2;
        }
        if (round1Messages == null) {
            round1Messages = EMPTY_BYTE_ARRAY_2;
        }
        if (round2Messages == null) {
            round2Messages = EMPTY_BYTE_ARRAY_2;
        }
        if (round3Messages == null) {
            round3Messages = EMPTY_BYTE_ARRAY_2;
        }

        if (phase != SigningProtocolPhase.Aggregate) {
            if (schnorrPrivateKey == null || instanceEntropy == null || instanceEntropy.length != ENTROPY_SIZE) {
                return null;
            }
        }

        if (phase == SigningProtocolPhase.R1) {
            if (!Arrays.equals(schnorrPublicKeys, EMPTY_BYTE_ARRAY_2)
                    || !Arrays.equals(round1Messages, EMPTY_BYTE_ARRAY_2)
                    || !Arrays.equals(round2Messages, EMPTY_BYTE_ARRAY_2)
                    || !Arrays.equals(round3Messages, EMPTY_BYTE_ARRAY_2)) {
                return null;
            }
        } else if (phase == SigningProtocolPhase.R2) {
            if (!validateRoundMessages(round1Messages, ROUND1_MESSAGE_SIZE)
                    || !Arrays.equals(round2Messages, EMPTY_BYTE_ARRAY_2)
                    || !Arrays.equals(round3Messages, EMPTY_BYTE_ARRAY_2)) {
                return null;
            }
            if (schnorrPublicKeys.length == 0
                    || schnorrPublicKeys.length != round1Messages.length
                    || !WRAPSLibraryBridge.validateSchnorrPublicKeys(schnorrPublicKeys)) {
                return null;
            }
        } else if (phase == SigningProtocolPhase.R3) {
            if (!validateRoundMessages(round1Messages, ROUND1_MESSAGE_SIZE)
                    || !validateRoundMessages(round2Messages, ROUND2_3_MESSAGE_SIZE)
                    || !Arrays.equals(round3Messages, EMPTY_BYTE_ARRAY_2)) {
                return null;
            }
            if (schnorrPublicKeys.length == 0
                    || schnorrPublicKeys.length != round1Messages.length
                    || schnorrPublicKeys.length != round2Messages.length
                    || !WRAPSLibraryBridge.validateSchnorrPublicKeys(schnorrPublicKeys)) {
                return null;
            }
        } else if (phase == SigningProtocolPhase.Aggregate) {
            if (schnorrPrivateKey != null || instanceEntropy != null) {
                return null;
            }
            if (!validateRoundMessages(round1Messages, ROUND1_MESSAGE_SIZE)
                    || !validateRoundMessages(round2Messages, ROUND2_3_MESSAGE_SIZE)
                    || !validateRoundMessages(round3Messages, ROUND2_3_MESSAGE_SIZE)) {
                return null;
            }
            if (schnorrPublicKeys.length == 0
                    || schnorrPublicKeys.length != round1Messages.length
                    || schnorrPublicKeys.length != round2Messages.length
                    || schnorrPublicKeys.length != round3Messages.length
                    || !WRAPSLibraryBridge.validateSchnorrPublicKeys(schnorrPublicKeys)) {
                return null;
            }
        } else {
            // Shouldn't normally happen. Just to catch the case if we ever introduce a new phase.
            throw new IllegalArgumentException("Unknown phase: " + phase);
        }

        return runSigningProtocolPhaseImpl(
                phase.ordinal(),
                instanceEntropy,
                messageToSign,
                schnorrPrivateKey,
                schnorrPublicKeys,
                round1Messages,
                round2Messages,
                round3Messages);
    }

    private native byte[] runSigningProtocolPhaseImpl(
            int phaseOrdinal,
            byte[] instanceEntropy,
            byte[] messageToSign,
            byte[] schnorrPrivateKey,
            byte[][] schnorrPublicKeys,
            byte[][] round1Messages,
            byte[][] round2Messages,
            byte[][] round3Messages);

    /**
     * Verifies an aggregated Schnorr signature against the supplied public keys.
     * @param schnorrPublicKeys Subset of participant public keys who collectively signed the message
     * @param messageToSign Message bytes that were signed
     * @param signature Aggregated Schnorr signature to validate
     * @return true if verified successfully, false otherwise or if errors occur
     */
    public boolean verifySignature(byte[][] schnorrPublicKeys, final byte[] messageToSign, final byte[] signature) {
        if (schnorrPublicKeys == null
                || messageToSign == null
                || signature == null
                || schnorrPublicKeys.length == 0
                || messageToSign.length == 0
                || signature.length == 0
                || !WRAPSLibraryBridge.validateSchnorrPublicKeys(schnorrPublicKeys)) {
            return false;
        }

        return verifySignatureImpl(schnorrPublicKeys, messageToSign, signature);
    }

    private native boolean verifySignatureImpl(
            byte[][] schnorrPublicKeys, final byte[] messageToSign, final byte[] signature);

    /**
     * Computes the Poseidon hash of an address book. This is expected to only be used to compute the ledger ID.
     * As of 10/20/2025, the address book size is limited to 128 nodes (see MAX_AB_SIZE in Rust code.)
     * @param schnorrPublicKeys Schnorr public keys for nodes in the address book
     * @param weights corresponding non-negative weights of the nodes in the address book
     * @return a hash of the address book, or null if errors occur
     */
    public byte[] hashAddressBook(final byte[][] schnorrPublicKeys, final long[] weights) {
        if (schnorrPublicKeys == null
                || weights == null
                || schnorrPublicKeys.length != weights.length
                || !WRAPSLibraryBridge.validateWeightsSum(weights)
                || !WRAPSLibraryBridge.validateSchnorrPublicKeys(schnorrPublicKeys)) {
            return null;
        }
        return hashAddressBookImpl(schnorrPublicKeys, weights);
    }

    private native byte[] hashAddressBookImpl(byte[][] schnorrPublicKeys, long[] weights);

    /**
     * A convenience API to compute the Poseidon hash of an arbitrary non-null and non-empty array.
     * @param array a non-null and non-empty array of bytes
     * @return a hash of the array, or null if errors occur
     */
    public native byte[] hashArray(byte[] array);

    /**
     * Constructs a rotation message by concatenating the hash of the next address book with the hash
     * of the hinTS VerificationKey.
     * @param schnorrPublicKeys Schnorr public keys for nodes in the next address book
     * @param weights corresponding non-negative weights of the nodes in the address book
     * @param hintsVerificationKey the hinTS VerificationKey
     * @return
     */
    public byte[] formatRotationMessage(byte[][] schnorrPublicKeys, long[] weights, byte[] hintsVerificationKey) {
        if (schnorrPublicKeys == null
                || weights == null
                || schnorrPublicKeys.length != weights.length
                || !WRAPSLibraryBridge.validateWeightsSum(weights)
                || hintsVerificationKey == null
                || hintsVerificationKey.length == 0
                || !WRAPSLibraryBridge.validateSchnorrPublicKeys(schnorrPublicKeys)) {
            return null;
        }
        return formatRotationMessageImpl(schnorrPublicKeys, weights, hintsVerificationKey);
    }

    private native byte[] formatRotationMessageImpl(
            byte[][] schnorrPublicKeys, long[] weights, byte[] hintsVerificationKey);

    /**
     * Creates the first proof for the genesis AddressBook when both prev and next AddressBooks are the same
     * and the tssVerificationKey is 1288 zeros, and prevProof is null.
     * Produces both the incremental Nova proof and the compressed decider proof when the AddressBooks differ
     * and the tssVerificationKey is real, and the prevProof is present.
     * <p>
     * Note: Nova and Decider keys are managed internally in the native code for performance reasons.
     *
     * @param genesisAddressBookHash genesis AddressBook hash
     * @param prevSchnorrPublicKeys keys for the previous (aka current) AB
     * @param prevWeights weights for the previous (aka current) AB
     * @param nextSchnorrPublicKeys keys for the next AB, or the current AB to generate initial proof
     * @param nextWeights weights for the next AB, or the current AB to generate initial proof
     * @param prevProof previous proof, or null to generate the initial proof
     * @param tssVerificationKey hinTS VerificationKey, or 1288 zeros to generate the initial proof
     * @param aggregateSignature aggregate Schnorr signature on the rotation message
     * @param signers a boolean mask to mark signers of the aggregate signature from the current AB
     * @return a Proof in both uncompressed and compressed forms as byte arrays
     */
    public Proof constructWrapsProof(
            byte[] genesisAddressBookHash,
            byte[][] prevSchnorrPublicKeys,
            long[] prevWeights,
            byte[][] nextSchnorrPublicKeys,
            long[] nextWeights,
            byte[] prevProof,
            byte[] tssVerificationKey,
            byte[] aggregateSignature,
            boolean[] signers) {
        if (!isProofSupported()) {
            return null;
        }
        // Note: prevProof may be null
        if (genesisAddressBookHash == null
                || genesisAddressBookHash.length == 0
                || prevSchnorrPublicKeys == null
                || prevWeights == null
                || prevSchnorrPublicKeys.length == 0
                || prevSchnorrPublicKeys.length != prevWeights.length
                || !WRAPSLibraryBridge.validateWeightsSum(prevWeights)
                || nextSchnorrPublicKeys == null
                || nextWeights == null
                || nextSchnorrPublicKeys.length == 0
                || nextSchnorrPublicKeys.length != nextWeights.length
                || !WRAPSLibraryBridge.validateWeightsSum(nextWeights)
                || tssVerificationKey == null
                || tssVerificationKey.length == 0
                || aggregateSignature == null
                || aggregateSignature.length == 0
                || signers == null
                || signers.length != prevSchnorrPublicKeys.length
                || !WRAPSLibraryBridge.validateSchnorrPublicKeys(prevSchnorrPublicKeys)
                || !WRAPSLibraryBridge.validateSchnorrPublicKeys(nextSchnorrPublicKeys)) {
            return null;
        }

        return constructWrapsProofImpl(
                genesisAddressBookHash,
                prevSchnorrPublicKeys,
                prevWeights,
                nextSchnorrPublicKeys,
                nextWeights,
                prevProof,
                tssVerificationKey,
                aggregateSignature,
                signers);
    }

    private native Proof constructWrapsProofImpl(
            byte[] genesisAddressBookHash,
            byte[][] prevSchnorrPublicKeys,
            long[] prevWeights,
            byte[][] nextSchnorrPublicKeys,
            long[] nextWeights,
            byte[] prevProof,
            byte[] tssVerificationKey,
            byte[] aggregateSignature,
            boolean[] signers);

    /**
     * Checks a compressed WRAPS proof against a compressed verification key.
     * <p>
     * Note: Nova and Decider keys are managed internally in the native code for performance reasons.
     *
     * @param compressedProof Compressed proof bundle returned by `constructWrapsProof()`
     * @param genesisAddressBookHash genesis AddressBook hash
     * @param tssVerificationKey hinTS VerificationKey, or 1288 zeros for the initial proof
     * @return true if the decider successfully verifies the proof, false if not or if errors occur
     */
    public boolean verifyCompressedProof(
            byte[] compressedProof, byte[] genesisAddressBookHash, byte[] tssVerificationKey) {
        if (!isProofSupported()) {
            return false;
        }
        if (genesisAddressBookHash == null
                || genesisAddressBookHash.length == 0
                || tssVerificationKey == null
                || tssVerificationKey.length == 0
                || compressedProof == null
                || compressedProof.length == 0) {
            return false;
        }
        return verifyCompressedProofImpl(compressedProof, genesisAddressBookHash, tssVerificationKey);
    }

    private native boolean verifyCompressedProofImpl(
            byte[] compressedProof, byte[] genesisAddressBookHash, byte[] tssVerificationKey);

    /** Check if the sum of weights doesn't exceed MAX_SUM_OF_WEIGHTS. */
    private static boolean validateWeightsSum(final long weights[]) {
        try {
            long sum = 0;
            for (int i = 0; i < weights.length; i++) {
                if (weights[i] < 0) {
                    return false;
                }
                // Math.addExact() throws ArithmeticException if the sum overflows
                sum = Math.addExact(sum, weights[i]);
            }
            return sum <= MAX_SUM_OF_WEIGHTS;
        } catch (final ArithmeticException e) {
            return false;
        }
    }

    private static boolean validateSchnorrPublicKeys(final byte[][] schnorrPublicKeys) {
        for (int i = 0; i < schnorrPublicKeys.length; i++) {
            if (schnorrPublicKeys[i] == null || schnorrPublicKeys[i].length != 64) {
                return false;
            }
        }
        return true;
    }

    private static boolean validateRoundMessages(final byte[][] roundMessages, final int size) {
        for (int i = 0; i < roundMessages.length; i++) {
            if (roundMessages[i] == null || roundMessages[i].length != size) {
                return false;
            }
        }
        return true;
    }
}
