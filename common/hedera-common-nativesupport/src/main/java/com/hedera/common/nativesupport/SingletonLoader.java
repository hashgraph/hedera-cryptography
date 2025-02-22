// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A convenience class to load a singleton instance of a native library. It does not load the library until the first
 * call to {@link #getInstance()} is made. It ensures that the library is loaded only once. It is thread-safe.
 *
 * @param <T> the type of the singleton instance
 */
public class SingletonLoader<T> {
    private final NativeLibrary nativeLibrary;
    private final T instance;
    private final AtomicBoolean libraryLoaded = new AtomicBoolean(false);

    /**
     * Creates a new instance of the loader.
     *
     * @param libraryName the name of the library to load
     * @param instance    the singleton instance to use
     */
    public SingletonLoader(final String libraryName, final T instance) {
        this.nativeLibrary = NativeLibrary.withName(Objects.requireNonNull(libraryName));
        this.instance = Objects.requireNonNull(instance);
    }

    /**
     * Returns the singleton instance of the library. On the first call, it loads the native library.
     *
     * @return the singleton
     */
    public T getInstance() {
        if (!libraryLoaded.get()) {
            synchronized (this) {
                if (libraryLoaded.get()) {
                    return instance;
                }
                nativeLibrary.install(instance.getClass());
                libraryLoaded.set(true);
            }
        }
        return instance;
    }

    /**
     * Returns the package name of the native library is located. This is useful if you need to open the package
     * programmatically.
     *
     * @return the package name
     */
    public String getNativeLibraryPackageName() {
        return nativeLibrary.packageNameOfResource();
    }
}
