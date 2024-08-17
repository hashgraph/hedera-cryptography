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

import com.hedera.cryptography.altbn128.jni.AltBn128FieldElements;
import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import edu.umd.cs.findbugs.annotations.NonNull;

public class AltBn128Field implements Field {


    private final AltBn128BilinearPairing pairing;

    public AltBn128Field(@NonNull final AltBn128BilinearPairing pairing) {this.pairing = pairing;}

    @NonNull
    @Override
    public FieldElement elementFromLong(final long inputLong) {
       final byte[] representation = AltBn128FieldElements.getInstance().fieldElementsFromLong(inputLong);
        return new AltBn128FieldElement(representation, this);
    }

    @NonNull
    @Override
    public FieldElement randomElement(@NonNull final byte[] seed) {
        final byte[] representation = AltBn128FieldElements.getInstance().fieldElementsFromRandomSeed(seed);
        return new AltBn128FieldElement(representation, this);
    }

    @NonNull
    @Override
    public FieldElement elementFromBytes(@NonNull final byte[] representation) {
        return new AltBn128FieldElement( AltBn128FieldElements.getInstance().fieldElementsFromBytes(representation), this);
    }

    @Override
    public int getElementSize() {
        return AltBn128FieldElements.SIZE;
    }

    @Override
    public int getSeedSize() {
        return AltBn128FieldElements.SEED_SIZE;
    }

    @NonNull
    @Override
    public BilinearPairing getPairing() {
        return pairing;
    }
}
