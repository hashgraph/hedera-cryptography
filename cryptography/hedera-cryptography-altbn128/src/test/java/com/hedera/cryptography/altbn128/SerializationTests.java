package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.altbn128.adapter.jni.ArkBn254Adapter;
import com.hedera.cryptography.altbn128.facade.GroupFacade;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@WithRng
public class SerializationTests {

    @ParameterizedTest
    @EnumSource(ElementInfo.class)
    void unusedBitsAreUnset(final ElementInfo info, final Random rng) {
        final byte[] bytes = randomElementBytes(info, rng);
        final BitSet bitSet = BitSet.valueOf(bytes);

        for (final Integer unusedBit : info.getUnusedBits()) {
            assertFalse(bitSet.get(unusedBit));
        }
    }

    @ParameterizedTest
    @EnumSource(ElementInfo.class)
    void zeroElementBits(final ElementInfo info) {
        final byte[] bytes = zeroElementBytes(info);
        final BitSet bitSet = BitSet.valueOf(bytes);

        // if the element has flags, all bits should be zero except the zero flag bit
        for (int i = 0; i < bytes.length; i++) {
            if (info.hasFlags() && info.getZeroFlagBitIndex() == i) {
                assertTrue(bitSet.get(i));
            } else {
                assertFalse(bitSet.get(i));
            }
        }
    }

    @ParameterizedTest
    @EnumSource(
            value = ElementInfo.class,
            // Y coordinate flag is only present in group elements
            names = {"GROUP1_ELEMENT", "GROUP2_ELEMENT"})
    @Disabled("Flipping the flag does not affect equality in one case, but it does in the other")
    void equalsConsistencyYCoordinate(final ElementInfo info, final Random rng) {
        final byte[] bytes = randomElementBytes(info, rng);
        final BitSet bitSet = BitSet.valueOf(bytes);
        bitSet.flip(info.getYCoordinateFlagBitIndex());
        final byte[] flippedFlagBytes = bitSet.toByteArray();

        final GroupFacade groupFacade = getGroupFacade(info);
        assertFalse(groupFacade.equals(bytes, flippedFlagBytes));
        assertNotEquals(
                new AltBn128Group(info.getGroup()).fromBytes(bytes),
                new AltBn128Group(info.getGroup()).fromBytes(flippedFlagBytes)
        );
    }

    @ParameterizedTest
    @EnumSource(
            value = ElementInfo.class,
            // Y coordinate flag is only present in group elements
            names = {"GROUP1_ELEMENT", "GROUP2_ELEMENT"})
    @Disabled("Arkworks ignores all other bits if the zero bit flag is set")
    void equalsConsistencyZeroFlag(final ElementInfo info, final Random rng) {
        final byte[] bytes = randomElementBytes(info, rng);
        final BitSet bitSet = BitSet.valueOf(bytes);
        bitSet.flip(info.getZeroFlagBitIndex());
        final byte[] flippedFlagBytes = bitSet.toByteArray();
        final byte[] zeroElementBytes = zeroElementBytes(info);

        final GroupFacade groupFacade = getGroupFacade(info);
        assertFalse(groupFacade.equals(flippedFlagBytes, zeroElementBytes));
        assertNotEquals(
                new AltBn128Group(info.getGroup()).fromBytes(flippedFlagBytes),
                new AltBn128Group(info.getGroup()).fromBytes(zeroElementBytes)
        );
    }

    @ParameterizedTest
    @EnumSource(ElementInfo.class)
    @Disabled("Flipping unused bits in field elements does not throw an exception")
    void flippingUnusedBits(final ElementInfo info, final Random rng) {
        final byte[] bytes = randomElementBytes(info, rng);
        final BitSet bitSet = BitSet.valueOf(bytes);

        final List<Integer> unusedBits = new ArrayList<>(info.getUnusedBits().stream().toList());
        Collections.shuffle(unusedBits, rng);
        bitSet.flip(unusedBits.getFirst());

        final byte[] flippedBytes = bitSet.toByteArray();

        switch (info) {
            case FIELD_ELEMENT -> assertDoesNotThrow(() -> new AltBn128Field().fromBytes(flippedBytes));
            case GROUP1_ELEMENT -> assertThrows(IllegalArgumentException.class,
                    () -> new AltBn128Group(AltBN128CurveGroup.GROUP1).fromBytes(flippedBytes));
            case GROUP2_ELEMENT -> assertThrows(IllegalArgumentException.class,
                    () -> new AltBn128Group(AltBN128CurveGroup.GROUP2).fromBytes(flippedBytes));
        }
    }

    private static @NonNull byte[] randomElementBytes(final ElementInfo info, final Random rng) {
        return switch (info) {
            case FIELD_ELEMENT -> new AltBn128Field().random(rng).toBytes();
            case GROUP1_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP1).random(rng).toBytes();
            case GROUP2_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP2).random(rng).toBytes();
        };
    }

    private static @NonNull byte[] zeroElementBytes(final ElementInfo info) {
        return switch (info) {
            case FIELD_ELEMENT -> new AltBn128Field().zero().toBytes();
            case GROUP1_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP1).zero().toBytes();
            case GROUP2_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP2).zero().toBytes();
        };
    }

    private static @NonNull GroupFacade getGroupFacade(final ElementInfo info) {
        return new GroupFacade(
                info.getGroup().getId(),
                ArkBn254Adapter.getInstance(),
                ArkBn254Adapter.getInstance().fieldElementsSize());
    }
}
