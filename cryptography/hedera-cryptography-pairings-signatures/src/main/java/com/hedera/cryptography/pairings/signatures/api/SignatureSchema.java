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

package com.hedera.cryptography.pairings.signatures.api;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.Objects;

/**
 * Represents predefined parameters that define the curve and the pairings group to use.
 */
public final class SignatureSchema {
    private final GroupAssignment groupAssignment;
    private final Curve curve;
    private final PairingFriendlyCurve pairingFriendlyCurve;

    /**
     * Constructor
     *
     * @param groupAssignment the group assignment
     * @param curve           the curve
     */
    private SignatureSchema(@NonNull final GroupAssignment groupAssignment, @NonNull final Curve curve) {
        this.groupAssignment = Objects.requireNonNull(groupAssignment, "groupAssignment must not be null");
        this.curve = Objects.requireNonNull(curve, "curve must not be null");
        this.pairingFriendlyCurve = PairingFriendlyCurves.findInstance(curve).pairingFriendlyCurve();
    }

    /**
     * Internal method
     *
     * @return the curve
     */
    @NonNull
    PairingFriendlyCurve getPairingFriendlyCurve() {
        return pairingFriendlyCurve;
    }

    /**
     * Internal method
     *
     * @return the group to use for PublicKey creation
     */
    @NonNull
    Group getPublicKeyGroup() {
        return groupAssignment == GroupAssignment.GROUP1_FOR_PUBLIC_KEY
                ? pairingFriendlyCurve.group1()
                : pairingFriendlyCurve.group2();
    }

    /**
     * Returns a signature scheme a curve and a groupAssignment
     *
     * @param bytes the array containing the representation in the first element
     * @return the SignatureSchema instance
     */
    @NonNull
    public static SignatureSchema create(final @Nullable byte[] bytes) {
        if (Objects.requireNonNull(bytes, "bytes must not be null").length == 0)
            throw new IllegalArgumentException("bytes must not be empty");
        return create(bytes[0]);
    }

    /**
     * Returns a signature scheme a curve and a groupAssignment
     *
     * @param groupAssignment the group assignment
     * @param curve           the curve
     * @return the SignatureSchema instance
     */
    @NonNull
    public static SignatureSchema create(@NonNull final Curve curve, @NonNull final GroupAssignment groupAssignment) {
        return new SignatureSchema(groupAssignment, curve);
    }

    /**
     * Returns a signature scheme out of a packed representation of this object
     *
     * @param idByte the group assignment
     * @return the SignatureSchema instance
     */
    @NonNull
    public static SignatureSchema create(final byte idByte) {
        byte curveId = BytePacker.unpackCurveType(idByte);
        final Curve curve = PairingFriendlyCurves.allSupportedCurves().stream()
                .filter(c -> c.getId() == curveId)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown curve id: " + idByte));
        return new SignatureSchema(BytePacker.unpackGroupAssignment(idByte), curve);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof final SignatureSchema schema)) {
            return false;
        }
        return groupAssignment == schema.groupAssignment && Objects.equals(curve, schema.curve);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupAssignment, curve);
    }

    /**
     * Get the ID byte representing this schema
     *
     * @return the ID byte
     */
    public byte getIdByte() {
        return BytePacker.pack(groupAssignment, curve.getId());
    }

    /**
     * Packs and unpacks the curve type and group assignment into a single byte
     */
    private static class BytePacker {
        private static final int G_ASSIGNMENT_MASK = 0b10000000; // 1 bit for GroupAssignment
        private static final int CURVE_MASK = 0b01111111; // 7 bits for curve type

        /**
         * Packs the group assignment and curve type into a single byte
         *
         * @param groupAssignment the group assignment
         * @param curveType       the curve type
         * @return the packed byte
         */
        public static byte pack(@NonNull final GroupAssignment groupAssignment, final byte curveType) {
            if (curveType < 0) {
                throw new IllegalArgumentException("Curve type must be between 0 and 127");
            }

            final int assignmentValue = groupAssignment.ordinal() << 7;
            return (byte) (assignmentValue | (curveType & CURVE_MASK));
        }

        /**
         * Unpacks the group assignment from a packed byte
         *
         * @param packedByte the packed byte
         * @return the group assignment
         */
        public static GroupAssignment unpackGroupAssignment(final byte packedByte) {
            final int schemaValue = (packedByte & G_ASSIGNMENT_MASK) >> 7;
            return GroupAssignment.values()[schemaValue];
        }

        /**
         * Unpacks the curve type from a packed byte
         *
         * @param packedByte the packed byte
         * @return the curve type
         */
        public static byte unpackCurveType(final byte packedByte) {
            return (byte) (packedByte & CURVE_MASK);
        }
    }
}
