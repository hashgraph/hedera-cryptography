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

import static com.hedera.cryptography.bls.ByteArrayConversionUtils.deserializePairingSignature;
import static com.hedera.cryptography.bls.ByteArrayConversionUtils.serializePairingSignature;

import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 *  A Prototype implementation of PairingSignature.
 *  This class will live in a different project once the implementation of the pairings-signature-library is completed.
 *  The package and interface will remain constant.
 */
public record BlsSignature(@NonNull GroupElement signature, @NonNull SignatureSchema signatureSchema) {

    /**
     * Serializes this {@link BlsPrivateKey} into a byte array.
     *
     * @return the serialized form of this object
     */
    @NonNull
    public byte[] toBytes() {
        return serializePairingSignature(this);
    }

    /**
     * Returns a {@link BlsSignature} instance out of this object serialized form
     * @param bytes the serialized form of this object
     * @return a {@link BlsSignature} instance
     * @throws IllegalArgumentException if the key representation is invalid
     */
    @NonNull
    public static BlsSignature fromBytes(@NonNull final byte[] bytes) {
        return deserializePairingSignature(bytes);
    }

    /**
     * Verify a signed message with the known public key.
     * <p>
     * To verify a signature, we need to ensure that the message m was signed with the corresponding private key “sk”
     * for the given public key “pk”.
     * <p>
     * The signature is considered valid only if the pairing between the generator of the public key group and the
     * signature “σ” is equal to the pairing between the public key and the message hashed to the signature key group.
     * <p>
     * Mathematically, this verification can be expressed like this:
     * e(pk, H(m)) = e([sk]g1, H(m)) = e(g1, H(m))^(sk) = e(g1, [sk]H(m)) = e(g1, σ).
     *
     * @param publicKey the public key to verify with
     * @param message   the message that was signed
     * @return true if the signature is valid, false otherwise
     */
    public boolean verify(@NonNull final BlsPublicKey publicKey, @NonNull final byte[] message) {
        if (publicKey.signatureSchema() != signatureSchema) {
            throw new IllegalArgumentException("PublicKey does not match signatureSchema");
        }
        final Group signatureGroup = signatureSchema.getSignatureGroup();
        final Group publicKeyGroup = signatureSchema.getPublicKeyGroup();
        final PairingFriendlyCurve curve = signatureSchema.getPairingFriendlyCurve();
        final BilinearPairing a = curve.pairingBetween(publicKey.publicKey(), signatureGroup.fromHash(message));
        final BilinearPairing b = curve.pairingBetween(publicKeyGroup.generator(), signature);
        return a.compare(b);
    }
}
