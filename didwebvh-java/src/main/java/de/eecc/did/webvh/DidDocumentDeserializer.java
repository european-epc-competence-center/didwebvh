package de.eecc.did.webvh;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;

/**
 * Jackson deserializer for {@link DidDocument}.
 *
 * <p>Reads the current JSON value as a tree and wraps it in a {@code DidDocument}.
 * This class lives in the {@code de.eecc.did.webvh} package so it can access the
 * package-private {@link DidDocument#asJsonNode()} method (indirectly via the
 * public constructor).
 */
public final class DidDocumentDeserializer extends JsonDeserializer<DidDocument> {

    @Override
    public DidDocument deserialize(JsonParser p, DeserializationContext ctxt)
            throws IOException {
        return new DidDocument(p.readValueAsTree());
    }
}
