// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

/**
 * Holds the proving and verifying Snark keys as byte arrays.
 */
public record ProvingAndVerifyingSnarkKeys(byte[] provingKey, byte[] verifyingKey) {}
