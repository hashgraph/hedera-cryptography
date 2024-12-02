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

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class for finding implementations of a {@link PairingFriendlyCurve}.
 */
public final class PairingFriendlyCurves {

    /**
     * Constructor
     */
    private PairingFriendlyCurves() {
        // private constructor for static access
    }

    /**
     * Cache so that every time findInstance is called returns the already created instance
     */
    private static final Map<Curve, PairingFriendlyCurve> CACHE = new ConcurrentHashMap<>();

    /**
     * Locates a {@link PairingFriendlyCurve} instance based on the searched {@link Curve}.
     * The provider is initialized before being returned.
     *
     * @param curve the curve value for which to locate an implementation.
     * @throws NullPointerException if the {@code curve} argument is a {@code null} reference.
     * @throws IllegalArgumentException if the {@code curve} argument is a blank or empty string.
     * @throws NoSuchElementException if no {@link PairingFriendlyCurve} implementation was found via the {@link ServiceLoader}
     *                                  mechanism.
     * @throws IllegalStateException if there was a problem initializing the provider.
     * @return the BilinearPairingProvider implementation corresponding to the curve.
     */
    @NonNull
    public static PairingFriendlyCurve findInstance(@NonNull final Curve curve) {
        Objects.requireNonNull(curve, "curve must not be null");
        PairingFriendlyCurve pairingFriendlyCurve = CACHE.computeIfAbsent(curve, curve1 -> {
            for (final PairingFriendlyCurve provider : ServiceLoader.load(PairingFriendlyCurve.class)) {
                if (curve == provider.curve()) {
                    return provider.init();
                }
            }
            return null;
        });

        if (pairingFriendlyCurve != null) {
            return pairingFriendlyCurve;
        }

        throw new NoSuchElementException(
                "A PairingFriendlyCurveProvider implementation for " + curve + " was not found.");
    }

    /**
     * Returns all loaded and supported curves.
     *
     * @return all loaded and supported curves
     */
    @NonNull
    public static Collection<Curve> allSupportedCurves() {
        List<Curve> supportedCurves = new ArrayList<>();
        for (final PairingFriendlyCurve provider : ServiceLoader.load(PairingFriendlyCurve.class)) {
            supportedCurves.add(provider.curve());
        }
        return supportedCurves;
    }
}
