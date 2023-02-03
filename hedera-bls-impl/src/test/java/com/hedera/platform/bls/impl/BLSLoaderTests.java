/*
 * Copyright (C) 2022-2023 Hedera Hashgraph, LLC
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
package com.hedera.platform.bls.impl;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.hedera.platform.bls.api.BLSLoader;
import com.hedera.platform.bls.api.BilinearMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("BLSLoader Unit Tests")
class BLSLoaderTests {

    @Test
    @DisplayName("Get bilinear map instance")
    void getBilinearMapInstance() {
        final BilinearMap bilinearMap = BLSLoader.instance();

        assertNotNull(bilinearMap, "Returned bilinear map should not be null");
    }

    @Test
    @DisplayName("Get bilinear map instance multiple times")
    void getBilinearMapInstanceMultiple() {
        BilinearMap bilinearMap = BLSLoader.instance();
        bilinearMap = BLSLoader.instance();

        assertNotNull(bilinearMap, "Returned bilinear map should not be null");
    }
}
