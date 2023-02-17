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
package com.hedera.platform.bls.impl.test.spi;

import com.hedera.platform.bls.api.BilinearMap;
import com.hedera.platform.bls.api.Field;
import com.hedera.platform.bls.api.Group;
import com.hedera.platform.bls.api.GroupElement;
import com.hedera.platform.bls.spi.BilinearMapProvider;
import com.hedera.platform.bls.spi.ProviderType;
import com.hedera.platform.bls.spi.WellKnownAlgorithms;
import org.mockito.Mockito;

public class Bls12381MockProvider implements BilinearMapProvider {
    @Override
    public String algorithm() {
        return WellKnownAlgorithms.Bls12_381;
    }

    @Override
    public ProviderType providerType() {
        return ProviderType.MOCK;
    }

    @Override
    public BilinearMap map() {
        return Mockito.mock(Mock.class);
    }

    public static class Mock implements BilinearMap {

        @Override
        public Field field() {
            return null;
        }

        @Override
        public Group signatureGroup() {
            return null;
        }

        @Override
        public Group keyGroup() {
            return null;
        }

        @Override
        public boolean comparePairing(
                GroupElement signatureElement1,
                GroupElement keyElement1,
                GroupElement signatureElement2,
                GroupElement keyElement2) {
            return false;
        }

        @Override
        public byte[] displayPairing(GroupElement signatureElement, GroupElement keyElement) {
            return new byte[0];
        }
    }
}
