/*
 * Copyright (C) 2024 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hedera.cryptography.pairings.spi;

import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Curve;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Implementations of this API should provide a unique instance of this class.
 * This should return a {@link BilinearPairing} for a given {@link Curve} the implementation supports.
 * Initialization will be requested before providing the {@link BilinearPairing} instace,
 * Implementations should handle any necessary step (such as loading native libraries) during that process.
 * This class handles parallelism by synchronizing the method init method.
 * Implementations should consider that the Init method will be called only once
 */
public abstract class BilinearPairingProvider {

    /**
     * Atomic boolean to avoid repeated attempts to reload the resource.
     */
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    /**
     * Returns the {@link Curve} supported by the Pairing API implementation
     *
     * @return the supported {@link Curve}
     */
    public abstract Curve curve();

    /**
     * Returns the instance of the {@link BilinearPairing}
     *
     * @return the instance of the {@link BilinearPairing}
     */
    public abstract BilinearPairing pairing();

    /**
     * Implementations should include here all the steps necessary to load the library, e.g.,
     * perform native library loads.
     * This method will be called only once per instance and thread-safe guaranteed invocation.
     */
    protected abstract void doInit();

    /**
     * Performs the initialization steps of the library.
     */
    public BilinearPairingProvider init() {
        if (!initialized.getAndSet(true)) {
            synchronized (this) {
                if (!initialized.getAndSet(true)) {
                    this.doInit();
                }
            }
        }
        return this;
    }
}
