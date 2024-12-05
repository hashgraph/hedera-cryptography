package com.hedera.cryptography.utils.serialization;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@WithRng
public class SerializationTest {

    public static Stream<Arguments> serDesArguments() {
        final PairingFriendlyCurve curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128);
        final EthereumAltBn128SerDes altBn128SerDes = new EthereumAltBn128SerDes(curve);
        return Stream.of(
                Arguments.of(
                        new ElementsSerDes(
                                altBn128SerDes.fieldSerializer(),
                                altBn128SerDes.groupSerializer(),
                                altBn128SerDes.fieldDeserializer(),
                                altBn128SerDes.groupDeserializer()
                        )
                )
        );
    }

    @ParameterizedTest
    @MethodSource("serDesArguments")
    void serDesRandom(final PairingFriendlyCurve curve, final ElementsSerDes serDes, final Random r){
        final FieldElement fieldElement = curve.field().random(r);
        assertEquals(
                fieldElement,
                serDes.serializeDeserialize(fieldElement)
        );

        final GroupElement group1Element = curve.group1().random(r);
        assertEquals(
                group1Element,
                serDes.serializeDeserialize(group1Element)
        );

        final GroupElement group2Element = curve.group2().random(r);
        assertEquals(
                group2Element,
                serDes.serializeDeserialize(group2Element)
        );
    }
}
