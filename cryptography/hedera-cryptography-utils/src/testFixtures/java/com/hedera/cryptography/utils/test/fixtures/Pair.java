// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.utils.test.fixtures;

public record Pair<T, S>(T left, S right) {
    public static <T, S> Pair<T, S> of(T left, S right) {
        return new Pair<>(left, right);
    }
}
