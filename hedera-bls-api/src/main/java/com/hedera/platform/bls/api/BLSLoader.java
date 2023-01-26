package com.hedera.platform.bls.api;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service for accessing an implementation of {@link BilinearMap}
 */
public final class BLSLoader {

    /**
     * The service loader
     */
    private static final ServiceLoader<BilinearMap> loader = ServiceLoader.load(BilinearMap.class);

    /**
     * Atomic boolean so that we don't repeatedly attempt to reload the resource
     */
    private static final AtomicBoolean initialized = new AtomicBoolean(false);

    /**
     * Hidden Constructor
     */
    private BLSLoader() {
    }

    /**
     * Obtain an instance of a {@link BilinearMap} implementation. This function returns the first implementation found
     * in the class path
     *
     * @return an instance of the {@link BilinearMap}
     * @throws java.util.NoSuchElementException if no {@link BilinearMap} implementation was found via the
     *                                          {@link  ServiceLoader} mechanism.
     */
    public static BilinearMap instance() {
        if (!initialized.get()) {
            loader.reload();
            initialized.set(true);
        }

        return loader.findFirst().orElseThrow();
    }
}
