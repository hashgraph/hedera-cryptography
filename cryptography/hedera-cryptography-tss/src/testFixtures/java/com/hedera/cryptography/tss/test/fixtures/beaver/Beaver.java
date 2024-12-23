// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.tss.test.fixtures.beaver;

import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.utils.test.fixtures.rng.SeededRandom;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.Objects;
import java.util.Random;

/**
 * A builder class for constructing and configuring tss test scenarios. This class serves as the main entry point for
 * creating committee configurations and TSS services for testing purposes.
 */
public class Beaver {
    private final Random rng;
    private CommitteeBuilder committeeBuilder;
    private TssService tssService;
    private TssParticipantDirectory committee;

    /**
     * Creates a new Beaver instance with a default SeededRandom random number generator.
     */
    public Beaver() {
        this(new SeededRandom());
    }

    /**
     * Creates a new Beaver instance with the specified random number generator.
     *
     * @param random The random number generator to use
     * @throws NullPointerException if random is null
     */
    public Beaver(@NonNull final SeededRandom random) {
        this.rng = Objects.requireNonNull(random, "random cannot be null");
    }

    /**
     * Returns the random number generator used by this instance.
     *
     * @return The random number generator
     */
    @NonNull
    Random getRng() {
        return rng;
    }

    /**
     * Creates a new CommitteeBuilder for configuring the TSS committee.
     *
     * @return A new CommitteeBuilder instance
     */
    @NonNull
    public CommitteeBuilder withCommittee() {
        return new CommitteeBuilder(this);
    }

    /**
     * Sets the committee builder and builds the committee configuration. This method is called internally by the
     * CommitteeBuilder.
     *
     * @param committeeBuilder The committee builder to set
     * @throws NullPointerException  if committeeBuilder is null or if committee creation fails
     * @throws IllegalStateException if the committee has already been set
     */
    void setCommitteeBuilder(@NonNull final CommitteeBuilder committeeBuilder) {
        if (this.committeeBuilder != null) {
            throw new IllegalStateException("Committee already set");
        }
        this.committeeBuilder = Objects.requireNonNull(committeeBuilder, "committeeBuilder cannot be null");
        committee = Objects.requireNonNull(committeeBuilder.build(), "committee cannot be created");
    }

    /**
     * Returns the configured TSS participant directory.
     *
     * @return The configured committee
     */
    @Nullable
    TssParticipantDirectory getCommittee() {
        return committee;
    }

    /**
     * Returns the current committee builder instance.
     *
     * @return The current committee builder
     * @throws NullPointerException if the committee builder hasn't been configured
     */
    @NonNull
    CommitteeBuilder getCommitteeBuilder() {
        return committeeBuilder;
    }

    /**
     * Sets the TSS service implementation to be used.
     *
     * @param tssService The TSS service implementation
     * @return This Beaver instance for method chaining
     * @throws NullPointerException if tssService is null
     */
    public Beaver withTssService(@NonNull final TssService tssService) {
        this.tssService = Objects.requireNonNull(tssService, "tssService cannot be null");
        return this;
    }

    /**
     * Returns the configured TSS service implementation.
     *
     * @return The TSS service implementation
     */
    @Nullable
    TssService getTssService() {
        return tssService;
    }

    /**
     * Creates a new genesis scenario for TSS testing.
     *
     * @return A new GenesisScenario instance
     */
    public GenesisScenario genesis() {
        return new GenesisScenario(this);
    }
}
