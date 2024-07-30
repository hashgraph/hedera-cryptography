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

package com.hedera.cryptography.pairings.api;

import static com.hedera.cryptography.pairings.api.BilinearPairings.InstanceHolder.LOADER;

import com.hedera.cryptography.pairings.spi.BilinearPairingProvider;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Utility class for finding implementations of a {@link BilinearPairing}.
 */
public final class BilinearPairings {

    static class InstanceHolder {
        // lazy initialize a loader and hold the instance so that BilinearPairings returns the same instance of
        // BilinearPairingProvider
        // every time findInstance is called
        static final ServiceLoader<BilinearPairingProvider> LOADER = ServiceLoader.load(BilinearPairingProvider.class);
    }
    /**
     * Private Constructor since this class should not be instantiated.
     */
    private BilinearPairings() {}

    /**
     * Obtain an instance of a {@link BilinearPairing} implementation which provides the given {@code curve}.
     *
     * @param curve the curve name for which to locate an implementation.
     * @return an instance of the {@link BilinearPairing} implementing the requested {@link Curve}
     */
    @NonNull
    public static BilinearPairing instanceFor(@NonNull final Curve curve) {
        return findInstance(curve).pairing();
    }

    /**
     * Locates a {@link BilinearPairingProvider} instance based on the searched {@link Curve}.
     * The provider is initialized before being returned.
     *
     * @param curve the curve value for which to locate an implementation.
     * @throws NullPointerException if the {@code curve} argument is a {@code null} reference.
     * @throws IllegalArgumentException if the {@code curve} argument is a blank or empty string.
     * @throws NoSuchElementException if no {@link BilinearPairing} implementation was found via the {@link ServiceLoader}
     *                                  mechanism.
     * @throws IllegalStateException if there was a problem initializing the provider.
     */
    @NonNull
    public static BilinearPairingProvider findInstance(@NonNull final Curve curve) {
        Objects.requireNonNull(curve, "curve must not be null");
        for (BilinearPairingProvider provider : LOADER) {
            if (curve == provider.curve()) {
                try {
                    return provider.init();
                } catch (Exception e) {
                    throw new IllegalStateException("Could not initialize provider " + provider, e);
                }
            }
        }

        throw new NoSuchElementException("A BilinearPairingProvider implementation for " + curve + " was not found.");
    }
}
