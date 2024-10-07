package com.hedera.common.nativesupport.internal;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.HashSet;
import java.util.Set;

public class RunOnlyOnce<T> {
    /** A set of keys which have already ran */
    private final Set<T> alreadyRan = new HashSet<>();

    public synchronized void runIfNeeded(
            @NonNull final T key,
            @NonNull final Runnable runnable) {
        if (alreadyRan.contains(key)) {
            return;
        }
        runnable.run();
        alreadyRan.add(key);
    }
}
