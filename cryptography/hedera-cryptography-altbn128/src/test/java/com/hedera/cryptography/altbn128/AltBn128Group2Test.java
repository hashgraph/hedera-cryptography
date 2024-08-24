package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.GroupElement;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;
import org.junit.jupiter.api.Test;

class AltBn128Group2Test {
    @Test
    void constructionSucceeds() {
        assertDoesNotThrow(AltBn128Group2::new);
    }

    @Test
    void createGroupElementZeroIsNotNull() {
        var group = new AltBn128Group2();
        assertNotNull(group.zero());
    }

    @Test
    void createGroupElementGeneratorIsNotNull() {
        var group = new AltBn128Group2();
        assertNotNull(group.generator());
    }

    @Test
    void createRandomGroupElementIsNotNull() {
        var group = new AltBn128Group2();
        Random rng = new SecureRandom();
        final byte[] seed = new byte[group.getSeedSize()];
        rng.nextBytes(seed);
        assertNotNull(group.random(seed));
    }

    @Test
    void createRandomGroupWithSmallerSeedThrowsException() {
        var group = new AltBn128Group2();
        final byte[] smallerSeed = new byte[group.getSeedSize() - 1];
        final byte[] largerSeed = new byte[group.getSeedSize() + 1];
        assertThrows(IllegalArgumentException.class, () -> group.random(smallerSeed));
        assertThrows(IllegalArgumentException.class, () -> group.random(largerSeed));
    }

    @Test
    void createGroupElementFromRandomIsNotNull() {
        var group = new AltBn128Group2();
        Random rng = new SecureRandom();
        ByteBuffer buffer = ByteBuffer.allocate(group.getSeedSize());
        rng.nextBytes(buffer.array());
        group.random(buffer.array());
        assertNotNull(buffer.array());
    }

    @Test
    void createGroupElementFromHashIsNotNull() {
        var group = new AltBn128Group2();
        Random rng = new SecureRandom();
        final byte[] message = new byte[1024];
        rng.nextBytes(message);

        assertNotNull(group.fromHash(message));
    }

    @Test
    void createRandomGroupElementAndGetAffineRepresentationIsNotNull() {
        var group = new AltBn128Group2();
        Random rng = new SecureRandom();
        final byte[] seed = new byte[group.getSeedSize()];
        rng.nextBytes(seed);
        final GroupElement random = group.random(seed);
        assertNotNull(random);
        assertNotNull(random.toBytes());
    }

    @Test
    void zeroPlusZeroIsZero() {
        var group = new AltBn128Group2();
        assertEquals(group.zero(), group.zero().add(group.zero()));
    }

    @Test
    void generatorTimesTwoEqualsGeneratorPlusGenerator() {
        var group = new AltBn128Group2();
        var field = new AltBn128Field();
        assertEquals(group.generator().multiply(field.fromLong(2)), group.generator().add(group.generator()));
    }

    @Test
    void generatorPlusZeroIsGenerator() {
        var group = new AltBn128Group2();
        assertEquals(group.generator(), group.generator().add(group.zero()));
        assertEquals(group.generator(), group.zero().add(group.generator()));
    }

    @Test
    void toAffineAndPointAgain() {
        var group = new AltBn128Group2();
        assertEquals(group.zero(), group.fromBytes(group.zero().toBytes()));
        assertEquals(group.generator(), group.fromBytes(group.generator().toBytes()));
    }


    @Test
    void equality() {
        var group = new AltBn128Group2();
        assertEquals(group.zero(),group.zero());
        final GroupElement zero = group.zero();
        assertTrue(zero.equals(zero));
        assertNotEquals(group.zero(), group.generator());
        assertNotEquals(group.generator(), group.zero());
        assertNotEquals(group.generator(), null);
        assertNotEquals(group.generator(), mock(GroupElement.class));
        assertNotEquals(mock(GroupElement.class),group.generator());
    }
}