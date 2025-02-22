// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport.internal;

import java.util.HashSet;
import java.util.Set;

/**
 * A utility class to run a given action only once for a given key, handling concurrent calls.
 *
 * @param <T> The type of the key
 */
public class RunOnlyOnce<T> {
    /** A set of keys which have already ran */
    private final Set<T> alreadyRan;

    /**
     * Constructor
     */
    public RunOnlyOnce() {
        alreadyRan = new HashSet<>();
    }

    /**
     * Run the provided action only once for the given key. If the action has already been run for the key, the Runnable
     * will not be invoked. If the runnable throws an exception, it will be propagated and considered as if the action
     * was not run.
     *
     * @param key      The key to run the action for
     * @param runnable The action to run
     */
    public synchronized void runIfNeeded(final T key, final Runnable runnable) {
        if (alreadyRan.contains(key)) {
            return;
        }
        runnable.run();
        alreadyRan.add(key);
    }
}
