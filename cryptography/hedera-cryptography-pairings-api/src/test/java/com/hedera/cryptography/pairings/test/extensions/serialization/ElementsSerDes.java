package com.hedera.cryptography.pairings.test.extensions.serialization;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;

public record ElementsSerDes(@NonNull Serializer<FieldElement> fieldSerializer,
                             @NonNull Serializer<GroupElement> groupSerializer,
                             @NonNull Deserializer<FieldElement> fieldDeserializer,
                             @NonNull Deserializer<GroupElement> group1Deserializer,
                             @NonNull Deserializer<GroupElement> group2Deserializer) {

    public FieldElement serializeDeserialize(final FieldElement fieldElement) {
        return fieldDeserializer().deserialize(fieldSerializer().serialize(fieldElement));
    }

    public GroupElement serializeDeserializeGroup1(final GroupElement groupElement) {
        return group1Deserializer().deserialize(groupSerializer().serialize(groupElement));
    }

    public GroupElement serializeDeserializeGroup2(final GroupElement groupElement) {
        return group2Deserializer().deserialize(groupSerializer().serialize(groupElement));
    }
}
