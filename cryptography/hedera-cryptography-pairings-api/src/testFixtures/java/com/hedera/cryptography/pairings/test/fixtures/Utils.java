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

package com.hedera.cryptography.pairings.test.fixtures;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility functions to work with FieldElements and GroupElements
 */
public class Utils {

    /**
     * Creates a string representation of the following FieldElement
     * @param element an element to write as string
     * @return a string representation of the following FieldElement
     */
    public static @NonNull String toString(final @NonNull FieldElement element) {
        return Arrays.toString(unsigned(element.toBytes()));
    }

    /**
     * Creates a string representation of the following GroupElement
     * @param element an element to write as string
     * @return a string representation of the following GroupElement
     */
    public static @NonNull String toString(final @NonNull GroupElement element) {
        var half = element.size() / 2;
        var arr = unsigned(element.toBytes());
        return "[" + Arrays.toString(Arrays.copyOf(arr, half))
                + Arrays.toString(Arrays.copyOfRange(arr, half, arr.length)) + "]";
    }

    /**
     * Creates a string representation of the following list of FieldElement
     * @param element a list of elements to write as string
     * @return a string representation of the following list of  FieldElement
     */
    public static @NonNull String toStringFieldElements(final @NonNull List<FieldElement> element) {
        return element.stream()
                .map(e -> Arrays.toString(unsigned(e.toBytes())))
                .toList()
                .toString();
    }

    /**
     * Creates a string representation of the following list of GroupElement
     * @param element a list of elements to write as string
     * @return a string representation of the following list of  GroupElement
     */
    public static @NonNull String toStringGroupElements(final @NonNull List<GroupElement> element) {
        return element.stream()
                .map(e -> Arrays.toString(unsigned(e.toBytes())))
                .toList()
                .toString();
    }

    /**
     * Returns a byte[] as an unsigned int[].
     * Each element of the origina array is transformed used  {@link Byte#toUnsignedInt(byte)}
     * @param bytes the original byte array to reinterpret.
     * @return the reinterpreted array as unsigned values
     */
    public static @NonNull int[] unsigned(final @NonNull byte[] bytes) {
        int[] result = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            result[i] = Byte.toUnsignedInt(bytes[i]);
        }
        return result;
    }

    /**
     * Creates a byte array from an unsigned representation of int values
     * @param bytes the individual values
     * @return a byte[] array represented
     * @throws IllegalArgumentException if any of the values is negative or out of range to be represented by a byte
     */
    public static @NonNull byte[] fromUnsigned(final @NonNull int... bytes) {
        byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] < 0 || bytes[i] > 255) {
                throw new IllegalArgumentException();
            }
            result[i] = (byte) (bytes[i] & 0xFF);
        }
        return result;
    }

    /**
     * Creates a FieldElement instance out of the unsigned byte array representation of values
     * @param field the field this FieldElement will belong to
     * @param uBytes the unsigned byte[] values
     * @return a FieldElements value
     */
    public static @NonNull FieldElement fieldElement(final @NonNull Field field, final @NonNull int... uBytes) {
        return field.fromBytes(fromUnsigned(uBytes));
    }

    /**
     * Creates a GroupElement instance out of the unsigned byte array representation of values
     * @param group the group this GroupElement will belong to
     * @param uBytes the unsigned byte[] values
     * @return a GroupElement value
     */
    public static @NonNull GroupElement groupElement(Group group, int... uBytes) {
        return group.fromBytes(fromUnsigned(uBytes));
    }

    /**
     * Creates many FieldElement instance out of the unsigned byte array representation of values
     * @param field the field these FieldElements will belong to
     * @param uBytes the unsigned list of byte[] values
     * @return a list of FieldElements values
     */
    public static @NonNull List<FieldElement> fieldElements(
            final @NonNull Field field, final @NonNull int[]... uBytes) {
        final List<FieldElement> elements = new ArrayList<>();
        for (int[] elementUbyte : uBytes) {
            elements.add(fieldElement(field, elementUbyte));
        }
        return elements;
    }
}
