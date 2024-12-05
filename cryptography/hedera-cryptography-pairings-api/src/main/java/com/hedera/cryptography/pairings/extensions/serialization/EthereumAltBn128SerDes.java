package com.hedera.cryptography.pairings.extensions.serialization;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class EthereumAltBn128SerDes {
    private static final String P = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    private static final BigInteger P_BI = new BigInteger(P);
    private static final int NUMBER_BYTES = 32;

    private final PairingFriendlyCurve curve;

    public EthereumAltBn128SerDes(final PairingFriendlyCurve curve) {
        if (curve.curve() != Curve.ALT_BN128) {
            throw new IllegalArgumentException("This serialization is only for alt_bn128 curve");
        }
        this.curve = curve;
    }

    //TODO check curve type to be alt_bn128

    public byte[] serializeField(final FieldElement element) {
        return ensureLength(element.toBigInteger().toByteArray());
    }

    public byte[] serializeGroup(final GroupElement element) {
        final BigInteger[] bigInts = Stream.concat(element.getXCoordinate().stream(), element.getYCoordinate().stream())
                .toArray(BigInteger[]::new);
        final byte[] output = new byte[NUMBER_BYTES * bigInts.length];
        for (int i = 0; i < bigInts.length; i++) {
            final byte[] biBytes = bigInts[i].toByteArray();
            System.arraycopy(biBytes, 0, output, i * NUMBER_BYTES + (NUMBER_BYTES - biBytes.length), biBytes.length);
        }

        return output;
    }

    public FieldElement deserializeField(final byte[] bytes) {
        final BigInteger bi = new BigInteger(1, bytes);
        if (bi.compareTo(P_BI) >= 0) {
            throw new IllegalArgumentException("Serialized field element is bigger than the field modulus");
        }
        return curve.field().fromBigInteger(bi);
    }

    public GroupElement deserializeGroup(final byte[] bytes) {
        final Group group = switch (bytes.length) {
            case NUMBER_BYTES * 2 -> curve.group1();
            case NUMBER_BYTES * 4 -> curve.group2();
            default -> throw new IllegalArgumentException("Invalid group element bytes");
        };
        final List<BigInteger> bigInts = new ArrayList<>();
        for (int i = 0; i < bytes.length; i += NUMBER_BYTES) {
            bigInts.add(new BigInteger(1, bytes, i, NUMBER_BYTES));
        }
        if (bigInts.stream().allMatch(bi -> bi.equals(BigInteger.ZERO))) {
            return group.zero();
        }

        return group.fromCoordinates(
                bigInts.subList(0, bigInts.size() / 2),
                bigInts.subList(bigInts.size() / 2, bigInts.size())
        );
    }

    public Serializer<FieldElement> fieldSerializer() {
        return this::serializeField;
    }

    public Serializer<GroupElement> groupSerializer() {
        return this::serializeGroup;
    }

    public Deserializer<FieldElement> fieldDeserializer() {
        return this::deserializeField;
    }

    public Deserializer<GroupElement> groupDeserializer() {
        return this::deserializeGroup;
    }

    private static byte[] ensureLength(final byte[] bytes) {
        if (bytes.length == NUMBER_BYTES) {
            return bytes;
        }
        final byte[] result = new byte[32];
        System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
        return result;
    }
}
