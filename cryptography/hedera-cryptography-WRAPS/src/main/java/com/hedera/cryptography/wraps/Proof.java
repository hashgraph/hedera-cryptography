// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.wraps;

/**
 * Represents both uncompressed and compressed versions of a proof.
 * @param uncompressed bytes of the uncompressed proof
 * @param compressed bytes of the compressed proof
 */
public record Proof(byte[] uncompressed, byte[] compressed) {}
