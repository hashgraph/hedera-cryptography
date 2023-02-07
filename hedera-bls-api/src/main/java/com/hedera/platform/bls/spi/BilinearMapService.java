/*
 * Copyright (C) 2023 Hedera Hashgraph, LLC
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
package com.hedera.platform.bls.spi;

import com.hedera.platform.bls.api.BilinearMap;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Loader for accessing an implementation of the {@link BilinearMapProvider} SPI.
 */
public final class BilinearMapService {

    /**
     * The service loader instance.
     */
    private static final ServiceLoader<BilinearMapProvider> loader = ServiceLoader.load(BilinearMapProvider.class);

    /**
     * Atomic boolean so that we don't repeatedly attempt to reload the resource.
     */
    private static final AtomicBoolean initialized = new AtomicBoolean(false);

    /**
     * Private Constructor since this class should not be instantiated.
     */
    private BilinearMapService() {
    }

    /**
     * Obtain an instance of a {@link BilinearMapProvider} implementation. This function returns the first
     * {@link ProviderType#RUNTIME} implementation found via service discovery.
     *
     * @return an instance of the first {@link BilinearMapProvider} found via the {@link ServiceLoader} scan.
     * @throws java.util.NoSuchElementException if no {@link BilinearMapProvider} implementation was found via the
     *                                          {@link ServiceLoader} mechanism.
     */
    public static BilinearMapProvider defaultProvider() {
        initialize();
        return loader.stream()
            .filter(p -> ProviderType.RUNTIME.equals(p.get().providerType()))
            .map(ServiceLoader.Provider::get)
            .findFirst()
            .orElseThrow();
    }

    /**
     * Obtain an instance of a {@link BilinearMapProvider} implementation which provides the given algorithm
     * name/identifier. This version of the method disregards the {@link ProviderType} and will select the first
     * implementation matching the algorithm name.
     *
     * @param algorithm the algorithm name for which to locate an implementation.
     * @return an instance of the {@link BilinearMapProvider} implementing the requested {@code algorithm} which was
     * found via the {@link ServiceLoader} scan.
     */
    public static BilinearMapProvider providerOf(final String algorithm) {
        return findInstance(algorithm, null);
    }

    /**
     * Obtain an instance of a {@link BilinearMapProvider} implementation which provides the given algorithm
     * name/identifier. This version of the method will only return a {@link ProviderType#RUNTIME} type of the requested
     * algorithm.
     *
     * @param algorithm the algorithm name for which to locate an implementation.
     * @return an instance of the {@link BilinearMapProvider} implementing the requested {@code algorithm} which was
     * found via the {@link ServiceLoader} scan.
     */
    public static BilinearMapProvider runtimeProviderOf(final String algorithm) {
        return findInstance(algorithm, ProviderType.RUNTIME);
    }

    /**
     * Obtain an instance of a {@link BilinearMapProvider} implementation which provides the given algorithm
     * name/identifier and is of the specified provider type.
     *
     * @param algorithm    the algorithm name for which to locate an implementation.
     * @param providerType the type of provider to return
     * @return an instance of the {@link BilinearMapProvider} implementing the requested {@code algorithm} which was
     * found via the {@link ServiceLoader} scan.
     */
    public static BilinearMapProvider providerOf(final String algorithm, final ProviderType providerType) {
        return findInstance(algorithm, providerType);
    }

    /**
     * Obtain an instance of a {@link BilinearMap} implementation. This function returns the first
     * {@link ProviderType#RUNTIME} implementation found via service discovery.
     *
     * @return an instance of the first {@link BilinearMap} found via the {@link ServiceLoader} scan.
     * @throws java.util.NoSuchElementException if no {@link BilinearMap} implementation was found via the
     *                                          {@link ServiceLoader} mechanism.
     */
    public static BilinearMap defaultInstance() {
        return defaultProvider().map();
    }

    /**
     * Obtain an instance of a {@link BilinearMap} implementation which provides the given algorithm name/identifier.
     * This version of the method disregards the {@link ProviderType} and will select the first implementation matching
     * the algorithm name.
     *
     * @param algorithm the algorithm name for which to locate an implementation.
     * @return an instance of the {@link BilinearMap} implementing the requested {@code algorithm} which was found via
     * the {@link ServiceLoader} scan.
     */
    public static BilinearMap instanceOf(final String algorithm) {
        return findInstance(algorithm, null).map();
    }

    /**
     * Obtain an instance of a {@link BilinearMap} implementation which provides the given algorithm name/identifier.
     * This version of the method will only return a {@link ProviderType#RUNTIME} type of the requested algorithm.
     *
     * @param algorithm the algorithm name for which to locate an implementation.
     * @return an instance of the {@link BilinearMap} implementing the requested {@code algorithm} which was found via
     * the {@link ServiceLoader} scan.
     */
    public static BilinearMap runtimeInstanceOf(final String algorithm) {
        return findInstance(algorithm, ProviderType.RUNTIME).map();
    }

    /**
     * Obtain an instance of a {@link BilinearMap} implementation which provides the given algorithm name/identifier and
     * is of the specified provider type.
     *
     * @param algorithm    the algorithm name for which to locate an implementation.
     * @param providerType the type of provider to find
     * @return an instance of the {@link BilinearMap} implementing the requested {@code algorithm} which was found via
     * the {@link ServiceLoader} scan.
     */
    public static BilinearMap instanceOf(final String algorithm, final ProviderType providerType) {
        return findInstance(algorithm, providerType).map();
    }

    /**
     * Forces a service loader refresh and causes the {@link ServiceLoader} implementation to evict the internal cache
     * and lazily rescan.
     */
    public static void refresh() {
        loader.reload();
    }

    /**
     * Initialize this implementation once when called.
     */
    private static void initialize() {
        if (!initialized.get()) {
            loader.reload();
            initialized.set(true);
        }
    }

    /**
     * Locates a {@link BilinearMapProvider} instance based on the search criteria provided.
     *
     * @param algorithm    the algorithm name for which to locate an implementation.
     * @param providerType an optional {@link ProviderType} used to filter multiple versions of the same algorithm.
     * @throws NullPointerException     if the {@code algorithm} argument is a {@code null} reference.
     * @throws IllegalArgumentException if the {@code algorithm} argument is a blank or empty string.
     * @throws NoSuchElementException   if no {@link BilinearMap} implementation was found via the {@link ServiceLoader}
     *                                  mechanism.
     */
    private static BilinearMapProvider findInstance(final String algorithm, final ProviderType providerType) {
        Objects.requireNonNull(algorithm, "The algorithm argument must not be a null reference.");
        if (algorithm.isBlank()) {
            throw new IllegalArgumentException("The algorithm argument must not be a blank string.");
        }

        initialize();

        for (final BilinearMapProvider provider : loader) {
            if (algorithm.equals(provider.algorithm())) {
                if (providerType != null && !providerType.equals(provider.providerType())) {
                    continue;
                }

                return provider;
            }
        }

        throw new NoSuchElementException("The requested algorithm was not found.");
    }
}
