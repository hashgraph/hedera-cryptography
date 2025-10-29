// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.wraps;

/** Holds Schnorr private and public keys as byte arrays. */
public record SchnorrKeys(byte[] privateKey, byte[] publicKey) {}
