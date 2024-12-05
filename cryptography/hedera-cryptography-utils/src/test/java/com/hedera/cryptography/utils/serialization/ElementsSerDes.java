package com.hedera.cryptography.utils.serialization;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;

public record ElementsSerDes(@NonNull Serializer<FieldElement> fieldSerializer,
                             @NonNull Serializer<GroupElement> groupSerializer,
                             @NonNull Deserializer<FieldElement> fieldDeserializer,
                             @NonNull Deserializer<GroupElement> groupDeserializer) {

    public FieldElement serializeDeserialize(final FieldElement fieldElement) {
        return fieldDeserializer().deserialize(fieldSerializer().serialize(fieldElement));
    }

    public GroupElement serializeDeserialize(final GroupElement groupElement) {
        return groupDeserializer().deserialize(groupSerializer().serialize(groupElement));
    }
}
