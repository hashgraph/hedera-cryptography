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

package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class ArkworksSerializationInfoTest {

    @Test
    void unusedBitsCount() {
        assertEquals(2, ArkworksSerializationInfo.FIELD_ELEMENT.getUnusedBits().size(), "Field element should have 2 unused bits");
        assertEquals(2, ArkworksSerializationInfo.GROUP1_ELEMENT.getUnusedBits().size(), "Group1 element should have 2 unused bits");
        assertEquals(6, ArkworksSerializationInfo.GROUP2_ELEMENT.getUnusedBits().size(), "Group2 element should have 6 unused bits");
    }
}
