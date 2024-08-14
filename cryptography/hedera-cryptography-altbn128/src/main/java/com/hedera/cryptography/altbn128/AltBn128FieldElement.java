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

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;

public class AltBn128FieldElement implements FieldElement {

    private final Field field;
    private final byte[] representation;

    public AltBn128FieldElement(@NonNull final byte[] output, @NonNull final Field field) {
        this.representation = output;
        this.field = field;
    }

    @NonNull
    @Override
    public Field getField() {
        return this.field;
    }

    @NonNull
    @Override
    public FieldElement add(@NonNull final FieldElement other) {
        return null;
    }

    @NonNull
    @Override
    public FieldElement subtract(@NonNull final FieldElement other) {
        return null;
    }

    @NonNull
    @Override
    public FieldElement multiply(@NonNull final FieldElement other) {
        return null;
    }

    @NonNull
    @Override
    public FieldElement power(@NonNull final BigInteger exponent) {
        return null;
    }

    @NonNull
    @Override
    public BigInteger toBigInteger() {
        return null;
    }

    @NonNull
    @Override
    public byte[] toBytes() {
        return new byte[this.field.getElementSize()];
    }
}
