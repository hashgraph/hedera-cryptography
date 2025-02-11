// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

/**
 * Holds the signing and verifying Schnorr keys as byte arrays.
 */
public record SigningAndVerifyingSchnorrKeys(byte[] signingKey, byte[] verifyingKey) {}
