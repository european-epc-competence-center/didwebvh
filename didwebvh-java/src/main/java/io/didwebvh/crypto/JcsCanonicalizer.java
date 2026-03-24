package io.didwebvh.crypto;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * JSON Canonicalization Scheme (JCS) per RFC 8785.
 *
 * <p>JCS is required by the {@code eddsa-jcs-2022} cryptosuite to produce a
 * deterministic byte representation of a JSON object before hashing or signing.
 * Object keys are sorted by Unicode codepoint; numbers use IEEE 754 ES2019
 * serialization; standard JSON escaping applies to strings.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8785">RFC 8785 — JCS</a>
 */
public final class JcsCanonicalizer {

    private JcsCanonicalizer() {}

    /**
     * Returns the JCS-canonical UTF-8 byte representation of the given JSON node.
     *
     * @param node the JSON object to canonicalize
     * @return the canonical byte array
     */
    public static byte[] canonicalize(JsonNode node) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Returns the JCS-canonical UTF-8 string of the given JSON node.
     *
     * @param node the JSON object to canonicalize
     * @return the canonical string
     */
    public static String canonicalizeToString(JsonNode node) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
