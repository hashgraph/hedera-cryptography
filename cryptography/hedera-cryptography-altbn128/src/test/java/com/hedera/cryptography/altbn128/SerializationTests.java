package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.altbn128.adapter.jni.ArkBn254Adapter;
import com.hedera.cryptography.altbn128.facade.GroupFacade;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@WithRng
public class SerializationTests {

    @ParameterizedTest
    @EnumSource(SerializationInfo.class)
    void unusedBitsAreUnset(final SerializationInfo info, final Random rng) {
        final byte[] bytes = switch (info) {
            case FIELD_ELEMENT -> new AltBn128Field().random(rng).toBytes();
            case GROUP1_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP1).random(rng).toBytes();
            case GROUP2_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP2).random(rng).toBytes();
        };
        final BitSet bitSet = BitSet.valueOf(bytes);

        for (final Integer unusedBit : info.getUnusedBits()) {
            assertFalse(bitSet.get(unusedBit));
        }
    }

    @ParameterizedTest
    @EnumSource(SerializationInfo.class)
    void zeroElementBits(final SerializationInfo info) {
        final byte[] bytes = switch (info) {
            case FIELD_ELEMENT -> new AltBn128Field().zero().toBytes();
            case GROUP1_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP1).zero().toBytes();
            case GROUP2_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP2).zero().toBytes();
        };
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
            value = SerializationInfo.class,
            names = {"GROUP1_ELEMENT", "GROUP2_ELEMENT"})
    void flippingYCoordinateIrrelevant(final SerializationInfo info, final Random rng) {
        final byte[] bytes = switch (info) {
            case FIELD_ELEMENT -> throw new IllegalArgumentException("Field elements do not have a Y coordinate flag");
            case GROUP1_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP1).random(rng).toBytes();
            case GROUP2_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP2).random(rng).toBytes();
        };
        final BitSet bitSet = BitSet.valueOf(bytes);
        bitSet.flip(info.getYCoordinateFlagBitIndex());
        final byte[] flippedFlagBytes = bitSet.toByteArray();

        final GroupFacade groupFacade = new GroupFacade(
                info == SerializationInfo.GROUP1_ELEMENT ? AltBN128CurveGroup.GROUP1.getId()
                        : AltBN128CurveGroup.GROUP2.getId(),
                ArkBn254Adapter.getInstance(),
                ArkBn254Adapter.getInstance().fieldElementsSize());
        assertTrue(groupFacade.equals(bytes, flippedFlagBytes));
    }

    @ParameterizedTest
    @EnumSource(SerializationInfo.class)
    void flippingUnusedBits(final SerializationInfo info, final Random rng) {
        final byte[] bytes = switch (info) {
            case FIELD_ELEMENT -> new AltBn128Field().random(rng).toBytes();
            case GROUP1_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP1).random(rng).toBytes();
            case GROUP2_ELEMENT -> new AltBn128Group(AltBN128CurveGroup.GROUP2).random(rng).toBytes();
        };
        final BitSet bitSet = BitSet.valueOf(bytes);

        final List<Integer> unusedBits = new ArrayList<>(info.getUnusedBits().stream().toList());
        Collections.shuffle(unusedBits, rng);
        bitSet.flip(unusedBits.getFirst());

        final byte[] flippedBytes = bitSet.toByteArray();

        switch (info) {
            case FIELD_ELEMENT -> assertDoesNotThrow(() -> new AltBn128Field().fromBytes(flippedBytes).toBytes());
            case GROUP1_ELEMENT -> assertThrows(IllegalArgumentException.class,
                    () -> new AltBn128Group(AltBN128CurveGroup.GROUP1).fromBytes(flippedBytes).toBytes());
            case GROUP2_ELEMENT -> assertThrows(IllegalArgumentException.class,
                    () -> new AltBn128Group(AltBN128CurveGroup.GROUP2).fromBytes(flippedBytes).toBytes());
        }
    }
}
