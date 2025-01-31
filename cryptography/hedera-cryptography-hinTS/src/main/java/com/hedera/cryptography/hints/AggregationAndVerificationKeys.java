// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

/**
 * Holds the results of the HinTS preprocessing method.
 * This includes:
 * <ol>
 *     <li>The linear size aggregation key to use in combining partial signatures on a message with a provably
 *     well-formed aggregate public key.</li>
 *     <li>The succinct verification key to use when verifying an aggregate signature.</li>
 * </ol>
 */
public record AggregationAndVerificationKeys(byte[] verificationKey, byte[] aggregationKey) {}
