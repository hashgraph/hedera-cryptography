package com.hedera.common.nativesupport;

import java.util.function.Supplier;

public class SingletonLoader<T> {
    private final String libraryName;
    private final Class<T> clazz;
    private final Supplier<T> instanceSupplier;
    private volatile T instance;

    public SingletonLoader(final String libraryName, final Class<T> clazz, final Supplier<T> instanceSupplier) {
        this.libraryName = libraryName;
        this.clazz = clazz;
        this.instanceSupplier = instanceSupplier;
    }

    public T getInstance() {
        if (instance == null) {
            synchronized (this) {
                if (instance != null) {
                    return instance;
                }
                NativeLibrary.withName(libraryName).install(clazz);
                instance = instanceSupplier.get();
            }
        }
        return instance;
    }
}
