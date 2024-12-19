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

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.extensions.serialization.DefaultFieldElementSerialization;
import com.hedera.cryptography.pairings.extensions.serialization.DefaultGroupElementSerialization;
import com.hedera.cryptography.pairings.extensions.serialization.EthereumSerialization;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Random;

/**
 * Helper class to test serialization and deserialization
 *
 * @param curve              the curve
 * @param fieldSerializer    the field serializer
 * @param groupSerializer    the group serializer
 * @param fieldDeserializer  the field deserializer
 * @param group1Deserializer the group1 deserializer
 * @param group2Deserializer the group2 deserializer
 */
public record SerializationTester(
        @NonNull PairingFriendlyCurve curve,
        @NonNull Serializer<FieldElement> fieldSerializer,
        @NonNull Serializer<GroupElement> groupSerializer,
        @NonNull Deserializer<FieldElement> fieldDeserializer,
        @NonNull Deserializer<GroupElement> group1Deserializer,
        @NonNull Deserializer<GroupElement> group2Deserializer) {

    /**
     * Create a serialization tester for the default serialization with the provided curve
     *
     * @param curve the curve
     * @return the serialization tester
     */
    @NonNull
    public static SerializationTester defaultSerialization(@NonNull final PairingFriendlyCurve curve) {
        return new SerializationTester(
                curve,
                DefaultFieldElementSerialization.getSerializer(),
                DefaultGroupElementSerialization.getSerializer(),
                DefaultFieldElementSerialization.getDeserializer(curve.field()),
                DefaultGroupElementSerialization.getDeserializer(curve.group1()),
                DefaultGroupElementSerialization.getDeserializer(curve.group2()));
    }

    /**
     * Create a serialization tester for the ethereum serialization with the provided curve
     *
     * @param curve the curve
     * @return the serialization tester
     */
    @NonNull
    public static SerializationTester ethereumSerialization(@NonNull final PairingFriendlyCurve curve) {
        final EthereumSerialization ethereumSerialization = new EthereumSerialization(curve);
        return new SerializationTester(
                curve,
                ethereumSerialization.fieldSerializer(),
                ethereumSerialization.groupSerializer(),
                ethereumSerialization.fieldDeserializer(),
                ethereumSerialization.groupDeserializer(curve.group1()),
                ethereumSerialization.groupDeserializer(curve.group2()));
    }

    /**
     * Serialize and deserialize a field element
     *
     * @param fieldElement the field element
     * @return the deserialized field element
     */
    @NonNull
    public FieldElement serializeDeserialize(@NonNull final FieldElement fieldElement) {
        return fieldDeserializer().deserialize(fieldSerializer().serialize(fieldElement));
    }

    /**
     * Serialize and deserialize a group element
     *
     * @param groupElement the group element
     * @return the deserialized group element
     */
    @NonNull
    public GroupElement serializeDeserializeGroup1(@NonNull final GroupElement groupElement) {
        return group1Deserializer().deserialize(groupSerializer().serialize(groupElement));
    }

    /**
     * Serialize and deserialize a group element
     *
     * @param groupElement the group element
     * @return the deserialized group element
     */
    @NonNull
    public GroupElement serializeDeserializeGroup2(@NonNull final GroupElement groupElement) {
        return group2Deserializer().deserialize(groupSerializer().serialize(groupElement));
    }

    public void testRandom(@NonNull final Random r) {
        final FieldElement fieldElement = curve.field().random(r);
        assertEquals(fieldElement, this.serializeDeserialize(fieldElement));

        final GroupElement group1Element = curve.group1().random(r);
        assertEquals(group1Element, this.serializeDeserializeGroup1(group1Element));

        final GroupElement group2Element = curve.group2().random(r);
        assertEquals(group2Element, this.serializeDeserializeGroup2(group2Element));
    }

    public void testZero() {
        final GroupElement group1Element = curve.group1().zero();
        assertEquals(group1Element, this.serializeDeserializeGroup1(group1Element));

        final GroupElement group2Element = curve.group2().zero();
        assertEquals(group2Element, this.serializeDeserializeGroup2(group2Element));
    }

    public void testGenerator() {
        final GroupElement group1Element = curve.group1().generator();
        assertEquals(group1Element, this.serializeDeserializeGroup1(group1Element));

        final GroupElement group2Element = curve.group2().generator();
        assertEquals(group2Element, this.serializeDeserializeGroup2(group2Element));
    }

    public void testAll(@NonNull final Random r) {
        testRandom(r);
        testZero();
        testGenerator();
    }
}
