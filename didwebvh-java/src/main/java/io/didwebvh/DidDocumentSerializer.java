package io.didwebvh;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;

/**
 * Jackson serializer for {@link DidDocument}.
 *
 * <p>Writes the underlying {@code JsonNode} tree directly to the generator.
 * This class lives in the {@code io.didwebvh} package so it can access the
 * package-private {@link DidDocument#asJsonNode()} method.
 */
public final class DidDocumentSerializer extends JsonSerializer<DidDocument> {

    @Override
    public void serialize(DidDocument value, JsonGenerator gen, SerializerProvider serializers)
            throws IOException {
        if (value == null) {
            gen.writeNull();
        } else {
            gen.writeTree(value.asJsonNode());
        }
    }
}
