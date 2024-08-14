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

import com.hedera.cryptography.altbn128.jni.AltBn128Bindings;
import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import edu.umd.cs.findbugs.annotations.NonNull;

public class AltBn128Field implements Field {

    private static final int SIZE = AltBn128Bindings.getInstance().fieldElementSize();
    private final AltBn128BilinearPairing pairing;

    public AltBn128Field(@NonNull final AltBn128BilinearPairing pairing) {this.pairing = pairing;}

    @NonNull
    @Override
    public FieldElement elementFromLong(final long inputLong) {
        byte[] output = new byte[SIZE];
        AltBn128Bindings.getInstance().fieldElementFromLong(inputLong, output);
        return new AltBn128FieldElement(output, this);
    }

    @NonNull
    @Override
    public FieldElement randomElement(@NonNull final byte[] seed) {
        throw new RuntimeException("Not Yet Implemented");
    }

    @NonNull
    @Override
    public FieldElement elementFromBytes(@NonNull final byte[] bytes) {
        throw new RuntimeException("Not Yet Implemented");
    }

    @Override
    public int getElementSize() {
        return SIZE;
    }

    @Override
    public int getSeedSize() {
        return 0;
    }

    @NonNull
    @Override
    public BilinearPairing getPairing() {
        return pairing;
    }
}
