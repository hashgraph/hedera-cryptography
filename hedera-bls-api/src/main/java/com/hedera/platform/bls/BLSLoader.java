package com.hedera.platform.bls;

import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

public final class BLSLoader {

    private static final ServiceLoader<BilinearMap> loader = ServiceLoader.load(BilinearMap.class);
    private static final AtomicBoolean initialized = new AtomicBoolean(false);

    private BLSLoader() {

    }

    /**
     * @return
     * @throws java.util.NoSuchElementException
     *         if no {@link BilinearMap} implementation was found via the {@link  ServiceLoader} mechanism.
     */
    public static BilinearMap instance() {
        if (!initialized.get()) {
            loader.reload();
            initialized.set(true);
        }

        return loader.findFirst().orElseThrow();
    }
}
