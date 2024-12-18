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

package com.hedera.cryptography.tss.impl.groth21;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.tss.api.TssException;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssShareExtractor;
import com.hedera.cryptography.tss.impl.elgamal.ElGamalSubstitutionTable;
import com.hedera.cryptography.tss.impl.elgamal.ElGamalUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 *  An implementation of a {@link TssShareExtractor} for the groth21 TSS.
 * <ul>
 *     <li>Obtain the list of owned {@link TssPrivateShare} of the participant from the: {@link TssParticipantDirectory}</li>
 *     <li>Obtain the list of All {@link TssPublicShare} with a {@link TssParticipantDirectory}</li>
 * </ul>
 *
 * @param <S> privateKey Type
 * @param <P> publicKey Type
 */
class Groth21ShareExtractor<P, S> implements TssShareExtractor {

    private final SignatureSchema signatureSchema;
    private final List<Groth21Message> validTssMessages;
    private final TssParticipantDirectory participantDirectory;
    private final ElGamalSubstitutionTable<Byte, GroupElement> elGamalTable;
    private final List<FieldElement> shareElements;
    private final KeyExtractionHelper<P, S> keyExtractionHelper;
    private final StatusTracker tracker;
    private List<TssPrivateShare> privateShares;
    private List<TssPublicShare> publicShares;

    /**
     * Constructor
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @param validTssMessages a list of <strong>previously validated</strong> {@link Groth21Message}s
     * @param participantDirectory the candidate directory
     * @param keyExtractionHelper the helper object that will be used to transform and aggregate the different types of keys depending on the stage.
     * @throws IllegalArgumentException in case the list of {@link TssMessage} cannot be converted properly to {@link Groth21Message} instances
     */
    Groth21ShareExtractor(
            @NonNull final SignatureSchema signatureSchema,
            @NonNull final List<Groth21Message> validTssMessages,
            @NonNull final TssParticipantDirectory participantDirectory,
            @NonNull final KeyExtractionHelper<P, S> keyExtractionHelper) {
        this.signatureSchema = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
        this.validTssMessages = Objects.requireNonNull(validTssMessages, "validateTssMessages must not be null");
        this.participantDirectory =
                Objects.requireNonNull(participantDirectory, "participantDirectory must not be null");
        this.elGamalTable = ElGamalUtils.elGamalReverseSubstitutionTable(signatureSchema);
        this.shareElements = participantDirectory.getShareIds().stream()
                .map(signatureSchema.getPairingFriendlyCurve().field()::fromLong)
                .toList(); // Not crucial to be fast here, we can buy some declarativity.
        this.keyExtractionHelper = Objects.requireNonNull(keyExtractionHelper, "keyExtractionHelper must not be null");
        this.tracker = new StatusTracker();
    }

    @Override
    @NonNull
    public TssShareExtractionStatus status(long participantId) {
        final var totalShares = participantDirectory.getShareIds().size();
        final var ownedShares = participantDirectory.ownedShares(participantId).size();
        final var total = totalShares + ownedShares;
        final var completed = tracker.privateShares + tracker.publicShares;
        final var percent = completed / total * 100;
        final var elapsedTime = tracker.elapsedTime();
        final var remainingTime = total - completed > 0 ? elapsedTime / completed * (total - completed) : 0;

        return new Groth21ShareExtractionStatus(total - completed <= 0, (byte) (percent), elapsedTime, remainingTime);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public TssShareExtractor extract(@NonNull TssParticipantPrivateInfo privateInfo) {
        tracker.registerStartTime();
        if (privateShares == null) {
            privateShares = extractPrivateShares(privateInfo);
        }
        if (publicShares == null) {
            publicShares = extractPublicShares();
        }
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public synchronized List<TssPrivateShare> ownedPrivateShares(@NonNull TssParticipantPrivateInfo privateInfo) {
        if (privateShares == null) {
            tracker.registerPrivateSharesExtractionStartTime();
            privateShares = extractPrivateShares(privateInfo);
        }
        return privateShares;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public synchronized List<TssPublicShare> allPublicShares() {
        if (publicShares == null) {
            tracker.registerPublicSharesExtractionStartTime();
            publicShares = extractPublicShares();
        }
        return publicShares;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    private List<TssPrivateShare> extractPrivateShares(@NonNull final TssParticipantPrivateInfo privateInfo) {
        Objects.requireNonNull(privateInfo, "privateInfo must not be null");
        // First create the output list, will we produce an element per each owned share, thus the preset size
        final List<Integer> ownedShares = privateInfo.ownedShares(participantDirectory);
        final List<TssPrivateShare> privateShares = new ArrayList<>(ownedShares.size());
        // A temporal working list that will hold all the received points
        // we must have exactly # of messages received points, thus the fixed size
        final List<P> receivedPoints = new ArrayList<>(validTssMessages.size());
        for (final Integer share : ownedShares) { // Per each owned share in the dir
            // NOTE: if this part will be outsourced to a thread, creating a new iterator each time is negligible cost
            for (final Groth21Message message : validTssMessages) { // per each received message
                final byte[] decryptedShare =
                        ElGamalUtils.readCipherText( // do read the message, and decrypt the part intended to this
                                // participant
                                privateInfo.tssDecryptPrivateKey(),
                                message.cipherTable().sharedRandomness(),
                                elGamalTable,
                                message.cipherTable().getForShareId(share));
                if (decryptedShare == null) {
                    // this means that we could not decrypt the message
                    // either the message was not validated beforehand,
                    // or that there is a problem with the validation,
                    // or that  something changed after validating.
                    throw new TssException("Invalid TssMessage");
                }
                // Create a privateKey out of the recovered secret
                final BlsPrivateKey privateKey = new BlsPrivateKey(
                        signatureSchema.getPairingFriendlyCurve().field().fromBytes(decryptedShare), signatureSchema);
                // Transform the private key into S, and accumulate in the temporal collection
                receivedPoints.add(keyExtractionHelper.privateKey(message.generatingShare(), privateKey));
            }
            // Now that we collected all S, use the function to produce a BlsPrivateKey from the aggregation of the
            // collection
            privateShares.add(new TssPrivateShare(share, keyExtractionHelper.aggregatePrivateKey(receivedPoints)));
            tracker.increasePrivateShares();
            // Clean what you use, next loop reuse the list
            receivedPoints.clear();
        }

        return privateShares;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    private List<TssPublicShare> extractPublicShares() {
        // First create the output list, will we produce an element per each share, thus the preset size
        final List<TssPublicShare> publicShares = new ArrayList<>(shareElements.size());
        // A temporal working list that will hold all the received points
        // we must have exactly # of messages received points, thus the fixed size
        final List<S> receivedPublicKeys = new ArrayList<>(validTssMessages.size());
        for (int shareIndex = 0; shareIndex < shareElements.size(); shareIndex++) { // Per each shareIndex
            // NOTE: if this part will be outsourced to a thread, creating a new iterator each time is negligible cost
            for (final Groth21Message message : validTssMessages) { // per each received message
                final FieldElement shareElement =
                        shareElements.get(shareIndex); // get the FieldElement that correspond to the shareId
                // Given that the commitment is all the coefficients of the interpolation of the polynomial
                // multiplied for the generator point of the group, what we got is essentially a publicKey
                // evaluate the commitment to get the distributed publicKey
                final GroupElement pkElement = message.polynomialCommitment().evaluate(shareElement);
                // Create the key
                final BlsPublicKey pk = new BlsPublicKey(pkElement, signatureSchema);
                // Transform the key into P
                receivedPublicKeys.add(keyExtractionHelper.publicKey(message.generatingShare(), pk));
            }
            // Now that we collected all P, use the function to produce a BlsPrivateKey from the aggregation of the
            // collection
            publicShares.add(
                    new TssPublicShare(shareIndex + 1, keyExtractionHelper.aggregatePublicKey(receivedPublicKeys)));

            // Pay some extra time to clear the list, save some allocations, eventually will be its own
            // list if the work is outsourced to other threads
            receivedPublicKeys.clear(); // Clean what you use, next loop reuse the list
            tracker.increasePublicShares();
        }
        return publicShares;
    }

    /**
     * A class to keep track of the process.
     */
    private static class StatusTracker {
        private long startTime = -1;
        private int privateShares;
        private int publicShares;

        /**
         * Sets the startTime
         */
        public void registerPrivateSharesExtractionStartTime() {
            registerStartTime();
        }

        /**
         * Sets the startTime
         */
        public void registerPublicSharesExtractionStartTime() {
            registerStartTime();
        }

        /**
         * Sets the startTime
         */
        public void registerStartTime() {
            if (startTime > 0) {
                startTime = System.currentTimeMillis();
            }
        }

        /**
         * increases the number of extracted Private Shares
         */
        public void increasePrivateShares() {
            privateShares++;
        }

        /**
         * increases the number of extracted public Shares
         */
        public void increasePublicShares() {
            publicShares++;
        }

        /**
         * gets the elapsed time
         */
        public long elapsedTime() {
            return System.currentTimeMillis() - startTime;
        }
    }

    /**
     * Stage Monitoring record
     * @param isCompleted whether the process is completed or not.
     * @param percentComplete percent of completion of the share extraction process
     * @param elapsedTimeMs elapsed time
     * @param approximateRemainingTimeMs an approximation of the remaining effort.
     */
    private record Groth21ShareExtractionStatus(
            boolean isCompleted, byte percentComplete, long elapsedTimeMs, long approximateRemainingTimeMs)
            implements TssShareExtractionStatus {}
}
