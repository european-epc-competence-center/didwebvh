package de.eecc.did.webvh.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Shared, configured {@link ObjectMapper} for the entire library.
 *
 * <p>Jackson's {@code ObjectMapper} is thread-safe after configuration and expensive
 * to create. This class provides a single instance used for all JSON serialization
 * and deserialization, ensuring consistent behaviour (e.g. {@code NON_NULL} inclusion)
 * across parsing, signing, and hashing.
 */
public final class JsonMapper {

    public static final ObjectMapper INSTANCE = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private JsonMapper() {}
}
