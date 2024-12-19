package com.hedera.cryptography.utils.test.fixtures;

@FunctionalInterface
public interface QuadConsumer<T, U, V, W> {
    void accept(T t, U u, V v, W w);
}