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
package com.hedera.platform.bls.impl.spi;

import com.hedera.platform.bls.api.BilinearMap;
import com.hedera.platform.bls.impl.Bls12381BilinearMap;
import com.hedera.platform.bls.spi.BilinearMapProvider;
import com.hedera.platform.bls.spi.ProviderType;
import com.hedera.platform.bls.spi.WellKnownAlgorithms;

/**
 * An implementation of {@link BilinearMapProvider} which returns an instance of {@link Bls12381BilinearMap}
 */
public class Bls12381Provider implements BilinearMapProvider {
    private static final BilinearMap map = new Bls12381BilinearMap();

    /**
     * {@inheritDoc}
     */
    @Override
    public String algorithm() {
        return WellKnownAlgorithms.Bls12_381;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ProviderType providerType() {
        return ProviderType.RUNTIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BilinearMap map() {
        return map;
    }
}
