package io.didwebvh.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * JSON Canonicalization Scheme (JCS) per RFC 8785.
 *
 * <p>Produces byte-identical output for the same logical JSON, which is required
 * before hashing (SCID/entry-hash) or signing (Data Integrity proof).
 *
 * <p>Pipeline: Jackson serialises the {@link JsonNode} tree to compact JSON, then the
 * erdtman JCS library (RFC Appendix G reference impl) applies all four RFC 8785 rules:
 * no whitespace, string escaping, ES2019 number format, and UTF-16 key sorting.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8785">RFC 8785 — JCS</a>
 */
public final class JcsCanonicalizer {

    /** Thread-safe after construction; shared across all callers. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JcsCanonicalizer() {}

    /**
     * Returns the JCS-canonical UTF-8 byte representation of the given JSON node.
     *
     * @param node the JSON value to canonicalize (object, array, or primitive)
     * @return the canonical UTF-8 byte array
     * @throws IllegalArgumentException if serialization fails
     */
    public static byte[] canonicalize(JsonNode node) {
        try {
            String json = MAPPER.writeValueAsString(node);
            return new JsonCanonicalizer(json).getEncodedUTF8();
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to canonicalize JSON node", e);
        }
    }

    /**
     * Convenience wrapper returning the canonical form as a {@code String}.
     *
     * @param node the JSON value to canonicalize
     * @return the canonical string (valid compact JSON)
     */
    public static String canonicalizeToString(JsonNode node) {
        return new String(canonicalize(node), StandardCharsets.UTF_8);
    }
}
