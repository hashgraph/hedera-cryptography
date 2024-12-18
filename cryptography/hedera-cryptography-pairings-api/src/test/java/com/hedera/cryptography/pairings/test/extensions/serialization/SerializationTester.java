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

package com.hedera.cryptography.pairings.test.extensions.serialization;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;

public record SerializationTester(
        @NonNull Serializer<FieldElement> fieldSerializer,
        @NonNull Serializer<GroupElement> groupSerializer,
        @NonNull Deserializer<FieldElement> fieldDeserializer,
        @NonNull Deserializer<GroupElement> group1Deserializer,
        @NonNull Deserializer<GroupElement> group2Deserializer) {

    public FieldElement serializeDeserialize(final FieldElement fieldElement) {
        return fieldDeserializer().deserialize(fieldSerializer().serialize(fieldElement));
    }

    public GroupElement serializeDeserializeGroup1(final GroupElement groupElement) {
        return group1Deserializer().deserialize(groupSerializer().serialize(groupElement));
    }

    public GroupElement serializeDeserializeGroup2(final GroupElement groupElement) {
        return group2Deserializer().deserialize(groupSerializer().serialize(groupElement));
    }
}
