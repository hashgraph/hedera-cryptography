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

package com.hedera.cryptography.bls;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import edu.umd.cs.findbugs.annotations.NonNull;
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
        this.pairingFriendlyCurve = PairingFriendlyCurves.findInstance(curve);
    }

    /**
     * Internal method
     *
     * @return the curve
     */
    @NonNull
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        return pairingFriendlyCurve;
    }

    /**
     * Internal method
     *
     * @return the group to use for PublicKey creation
     */
    @NonNull
    public Group getPublicKeyGroup() {
        return groupAssignment == GroupAssignment.SHORT_PUBLIC_KEYS
                ? pairingFriendlyCurve.group1()
                : pairingFriendlyCurve.group2();
    }

    /**
     * Internal method
     *
     * @return the group to use for Signature creation
     */
    @NonNull
    public Group getSignatureGroup() {
        return groupAssignment == GroupAssignment.SHORT_PUBLIC_KEYS
                ? pairingFriendlyCurve.group2()
                : pairingFriendlyCurve.group1();
    }
    /**
     * Returns the group assignment
     * @return the group assignment
     */
    public GroupAssignment getGroupAssignment() {
        return groupAssignment;
    }

    /**
     * Returns a {@link SignatureSchema} corresponding to a curve and a groupAssignment
     *
     * @param groupAssignment the group assignment
     * @param curve           the curve
     * @return the SignatureSchema instance
     */
    @NonNull
    public static SignatureSchema create(@NonNull final Curve curve, @NonNull final GroupAssignment groupAssignment) {
        return create(curve.getId(), groupAssignment);
    }

    public static SignatureSchema create(final int curveId, @NonNull final GroupAssignment groupAssignment) {
        final Curve curve = PairingFriendlyCurves.allSupportedCurves().stream()
                .filter(c -> c.getId() == curveId)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown curve id: " + curveId));
        return new SignatureSchema(groupAssignment, curve);
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
     * Returns the curve.
     * @return the curve
     */
    public Curve getCurve() {
        return curve;
    }
}
