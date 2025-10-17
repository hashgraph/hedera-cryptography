// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.wraps;

import com.hedera.common.nativesupport.SingletonLoader;
import java.util.Arrays;

/**
 * A JNI bridge for the WRAPS 2.0 library APIs that allow participants to generate and verify recursive proofs for AddressBooks.
 */
public class WRAPSLibraryBridge {
    /** Instance Holder for lazy loading and concurrency handling */
    private static final SingletonLoader<WRAPSLibraryBridge> INSTANCE_HOLDER =
            new SingletonLoader<>("wraps", new WRAPSLibraryBridge());

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
     *
     * @return the singleton instance of this library adapter.
     */
    public static WRAPSLibraryBridge getInstance() {
        return INSTANCE_HOLDER.getInstance();
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
            if (!Arrays.equals(round2Messages, EMPTY_BYTE_ARRAY_2)
                    || !Arrays.equals(round3Messages, EMPTY_BYTE_ARRAY_2)) {
                return null;
            }
            if (schnorrPublicKeys.length == 0 || schnorrPublicKeys.length != round1Messages.length) {
                return null;
            }
        } else if (phase == SigningProtocolPhase.R3) {
            if (!Arrays.equals(round3Messages, EMPTY_BYTE_ARRAY_2)) {
                return null;
            }
            if (schnorrPublicKeys.length == 0
                    || schnorrPublicKeys.length != round1Messages.length
                    || schnorrPublicKeys.length != round2Messages.length) {
                return null;
            }
        } else if (phase == SigningProtocolPhase.Aggregate) {
            if (schnorrPrivateKey != null || instanceEntropy != null) {
                return null;
            }
            if (schnorrPublicKeys.length == 0
                    || schnorrPublicKeys.length != round1Messages.length
                    || schnorrPublicKeys.length != round2Messages.length
                    || schnorrPublicKeys.length != round3Messages.length) {
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
}
