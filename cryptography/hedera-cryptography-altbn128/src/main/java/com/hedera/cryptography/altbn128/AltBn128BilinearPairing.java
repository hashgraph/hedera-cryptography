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

import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingResult;
import edu.umd.cs.findbugs.annotations.NonNull;

public class AltBn128BilinearPairing implements BilinearPairing {
    private final Field field =new AltBn128Field(this);
    private final Group g1 =new AltBn128Group1(this);

    @NonNull
    @Override
    public Field field() {
        return this.field;
    }

    @NonNull
    @Override
    public Group getGroup1() {
        return g1;
    }

    @NonNull
    @Override
    public Group group2() {
        return null;
    }

    @NonNull
    @Override
    public Group getOtherGroup(@NonNull final Group group) {
        return null;
    }

    @NonNull
    @Override
    public PairingResult pairingBetween(@NonNull final GroupElement element1, @NonNull final GroupElement element2) {
        return null;
    }

    @Override
    public boolean comparePairings(
            @NonNull final GroupElement pairingAElement1,
            @NonNull final GroupElement pairingAElement2,
            @NonNull final GroupElement pairingBElement1,
            @NonNull final GroupElement pairingBElement2) {
        return false;
    }
}
