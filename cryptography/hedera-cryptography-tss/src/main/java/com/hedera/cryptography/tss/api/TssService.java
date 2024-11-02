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

package com.hedera.cryptography.tss.api;

import com.hedera.cryptography.bls.SignatureSchema;

/**
 * A Threshold Signature Scheme Service.
 * <p>
 * Contract of TSS:
 * <ul>
 *     <li>Gets a genesis stage</li>
 *     <li>Gets a rekey stage</li>
 * </ul>
 * @implNote an instance of the service would require a source of randomness {@link java.util.Random}, and a{@link SignatureSchema}
 */
public interface TssService {

    /**
     * Returns the genesis stage.
     * In this stage all participants collaborate to discover a shared polynomial.
     *
     * @return the genesis stage.
     */
    TssServiceGenesisStage getGenesisStage();

    /**
     * Returns the rekey stage.
     * In this stage all participants recover keys belonging to an already established polynomial.
     *
     * @return the rekey stage.
     */
    TssServiceRekeyStage getRekeyStage();
}
