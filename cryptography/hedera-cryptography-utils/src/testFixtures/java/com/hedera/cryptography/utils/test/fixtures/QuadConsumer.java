// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.utils.test.fixtures;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.Objects;

/**
 * Represents an operation that accepts four input arguments and returns no result. This is a functional interface whose
 * functional method is {@link #accept(Object, Object, Object, Object)}.
 *
 * <p>This is a <a href="package-summary.html">functional interface</a>
 * whose functional method is {@link #accept(Object, Object, Object, Object)}.
 *
 * @param <T> the type of the first argument to the operation
 * @param <U> the type of the second argument to the operation
 * @param <V> the type of the third argument to the operation
 * @param <W> the type of the fourth argument to the operation
 */
@FunctionalInterface
public interface QuadConsumer<T, U, V, W> {

    /**
     * Performs this operation on the given arguments.
     *
     * @param t the first input argument
     * @param u the second input argument
     * @param v the third input argument
     * @param w the fourth input argument
     * @throws NullPointerException if any argument is null and this consumer does not accept null arguments
     */
    void accept(@Nullable T t, @Nullable U u, @Nullable V v, @Nullable W w);

    /**
     * Returns a composed {@code QuadConsumer} that performs, in sequence, this operation followed by the {@code after}
     * operation.
     *
     * @param after the operation to perform after this operation
     * @return a composed {@code QuadConsumer} that performs in sequence this operation followed by the {@code after}
     * operation
     * @throws NullPointerException if {@code after} is null
     */
    @NonNull
    default QuadConsumer<T, U, V, W> andThen(
            @NonNull final QuadConsumer<? super T, ? super U, ? super V, ? super W> after) {
        Objects.requireNonNull(after, "after cannot be null");
        return (t, u, v, w) -> {
            accept(t, u, v, w);
            after.accept(t, u, v, w);
        };
    }
}
