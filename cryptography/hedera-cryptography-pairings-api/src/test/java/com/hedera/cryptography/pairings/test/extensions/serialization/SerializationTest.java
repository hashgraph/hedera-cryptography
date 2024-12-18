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

    public static Stream<Arguments> serDesArguments() {
        final PairingFriendlyCurve curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128);
        final EthereumSerialization altBn128SerDes = new EthereumSerialization(curve);
        return Stream.of(
                Arguments.of(
                        curve,
                        new ElementsSerDes(
                                altBn128SerDes.fieldSerializer(),
                                altBn128SerDes.groupSerializer(),
                                altBn128SerDes.fieldDeserializer(),
                                altBn128SerDes.groupDeserializer(curve.group1()),
                                altBn128SerDes.groupDeserializer(curve.group2())
                        )
                ),
                Arguments.of(
                        curve,
                        new ElementsSerDes(
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
    @MethodSource("serDesArguments")
    void serDesRandom(final PairingFriendlyCurve curve, final ElementsSerDes serDes, final Random r) {
        final FieldElement fieldElement = curve.field().random(r);
        assertEquals(
                fieldElement,
                serDes.serializeDeserialize(fieldElement)
        );

        final GroupElement group1Element = curve.group1().random(r);
        assertEquals(
                group1Element,
                serDes.serializeDeserializeGroup1(group1Element)
        );

        final GroupElement group2Element = curve.group2().random(r);
        assertEquals(
                group2Element,
                serDes.serializeDeserializeGroup1(group2Element)
        );
    }
}
