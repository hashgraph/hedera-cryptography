package com.hedera.cryptography.pairings.test.extensions.serialization;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.extensions.serialization.DefaultFieldElementSerialization;
import com.hedera.cryptography.pairings.extensions.serialization.DefaultGroupElementSerialization;
import com.hedera.cryptography.pairings.extensions.serialization.EthereumSerialization;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@WithRng
public class SerializationTest {

    public static Stream<Arguments> arguments() {
        final PairingFriendlyCurve curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128);
        final EthereumSerialization ethereumSerialization = new EthereumSerialization(curve);
        return Stream.of(
                Arguments.of(
                        curve,
                        new SerializationTester(
                                ethereumSerialization.fieldSerializer(),
                                ethereumSerialization.groupSerializer(),
                                ethereumSerialization.fieldDeserializer(),
                                ethereumSerialization.groupDeserializer(curve.group1()),
                                ethereumSerialization.groupDeserializer(curve.group2())
                        )
                ),
                Arguments.of(
                        curve,
                        new SerializationTester(
                                DefaultFieldElementSerialization.getSerializer(),
                                DefaultGroupElementSerialization.getSerializer(),
                                DefaultFieldElementSerialization.getDeserializer(curve.field()),
                                DefaultGroupElementSerialization.getDeserializer(curve.group1()),
                                DefaultGroupElementSerialization.getDeserializer(curve.group2())
                        )
                )
        );
    }

    @ParameterizedTest
    @MethodSource("arguments")
    void serDesRandom(final PairingFriendlyCurve curve, final SerializationTester tester, final Random r) {
        final FieldElement fieldElement = curve.field().random(r);
        assertEquals(
                fieldElement,
                tester.serializeDeserialize(fieldElement)
        );

        final GroupElement group1Element = curve.group1().random(r);
        assertEquals(
                group1Element,
                tester.serializeDeserializeGroup1(group1Element)
        );

        final GroupElement group2Element = curve.group2().random(r);
        assertEquals(
                group2Element,
                tester.serializeDeserializeGroup2(group2Element)
        );
    }

    @ParameterizedTest
    @MethodSource("arguments")
    void serDesZero(final PairingFriendlyCurve curve, final SerializationTester tester) {
        final GroupElement group1Element = curve.group1().zero();
        assertEquals(
                group1Element,
                tester.serializeDeserializeGroup1(group1Element)
        );

        final GroupElement group2Element = curve.group2().zero();
        assertEquals(
                group2Element,
                tester.serializeDeserializeGroup2(group2Element)
        );
    }
}
