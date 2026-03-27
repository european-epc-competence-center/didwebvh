package io.didwebvh.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link JcsCanonicalizer} verifying RFC 8785 compliance.
 *
 * <p>Tests build input via {@code createObjectNode}/{@code createArrayNode} or parse
 * a JSON string with {@code readTree} (the production path for data arriving from the wire).
 * Never use {@code JsonNode#toString()} for wire-format JSON — it is a debug method, not
 * a serializer.
 *
 * <p>Run with {@code -Djcs.test.verbose=true} to print Jackson-compact vs. JCS-canonical
 * output for each test case.
 */
class JcsCanonicalizerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final boolean JCS_TEST_VERBOSE = Boolean.getBoolean("jcs.test.verbose");

    private static void logJcsBeforeAfter(JsonNode node) throws Exception {
        if (!JCS_TEST_VERBOSE) return;
        System.out.println("JCS before (Jackson compact): " + MAPPER.writeValueAsString(node));
        System.out.println("JCS after  (RFC 8785):        " + JcsCanonicalizer.canonicalizeToString(node));
    }

    // -------------------------------------------------------------------------
    // Rule 4: Key sorting (RFC 8785 §3.2.3) — most critical property for did:webvh
    // -------------------------------------------------------------------------

    @Test
    void canonicalize_sortsTopLevelObjectKeys() throws Exception {
        ObjectNode input = MAPPER.createObjectNode();
        input.put("z", 1);
        input.put("a", 2);

        logJcsBeforeAfter(input);
        assertThat(JcsCanonicalizer.canonicalizeToString(input))
                .isEqualTo("{\"a\":2,\"z\":1}");
    }

    @Test
    void canonicalize_sortsNestedObjectKeysRecursively() throws Exception {
        // RFC 8785 §3.2.3: child objects must also have their properties sorted.
        ObjectNode inner = MAPPER.createObjectNode();
        inner.put("y", 2);
        inner.put("x", 1);
        ObjectNode input = MAPPER.createObjectNode();
        input.set("z", inner);
        input.put("a", 3);

        logJcsBeforeAfter(input);
        assertThat(JcsCanonicalizer.canonicalizeToString(input))
                .isEqualTo("{\"a\":3,\"z\":{\"x\":1,\"y\":2}}");
    }

    @Test
    void canonicalize_preservesArrayElementOrder() throws Exception {
        // RFC 8785 §3.2.3: array element order MUST NOT be changed.
        ArrayNode input = MAPPER.createArrayNode();
        input.add(3);
        input.add(1);
        input.add(2);

        logJcsBeforeAfter(input);
        assertThat(JcsCanonicalizer.canonicalizeToString(input))
                .isEqualTo("[3,1,2]");
    }

    @Test
    void canonicalize_sortsObjectsInsideArrays() throws Exception {
        // RFC 8785 §3.2.3: objects nested inside arrays must also have sorted keys.
        ObjectNode element = MAPPER.createObjectNode();
        element.put("c", 3);
        element.put("b", 2);
        element.put("a", 1);
        ArrayNode input = MAPPER.createArrayNode();
        input.add(element);

        logJcsBeforeAfter(input);
        assertThat(JcsCanonicalizer.canonicalizeToString(input))
                .isEqualTo("[{\"a\":1,\"b\":2,\"c\":3}]");
    }

    // -------------------------------------------------------------------------
    // Rule 1: No whitespace (RFC 8785 §3.2.1)
    // -------------------------------------------------------------------------

    @Test
    void canonicalize_removesAllWhitespaceBetweenTokens() throws Exception {
        ObjectNode input = MAPPER.createObjectNode();
        input.put("a", 1);
        input.put("b", 2);

        logJcsBeforeAfter(input);
        assertThat(JcsCanonicalizer.canonicalizeToString(input))
                .isEqualTo("{\"a\":1,\"b\":2}");
    }

    // -------------------------------------------------------------------------
    // Rule 2: String escaping (RFC 8785 §3.2.2.2)
    // -------------------------------------------------------------------------

    @Test
    void canonicalize_escapesControlCharsCorrectly() throws Exception {
        // Group A (five short forms): U+0008→\b  U+0009→\t  U+000A→\n  U+000C→\f  U+000D→\r
        // Group B (all other U+0000–U+001F): six-char backslash-uXXXX sequence (lowercase hex).
        // U+000F (group B) must become \u000f; U+000A (group A) must become \n.
        ObjectNode input = MAPPER.createObjectNode();
        input.put("ctrl", "\u000f\n");

        logJcsBeforeAfter(input);
        assertThat(JcsCanonicalizer.canonicalizeToString(input))
                .isEqualTo("{\"ctrl\":\"\\u000f\\n\"}");
    }

    @Test
    void canonicalize_unicodeAboveControlRange_passedThroughAsRawUtf8() throws Exception {
        // RFC 8785 §3.2.2.2: characters outside U+0000–U+001F (except \ and ") pass through
        // as raw UTF-8. € (U+20AC) must appear as bytes E2 82 AC, not as \u20ac.
        ObjectNode input = MAPPER.createObjectNode();
        input.put("currency", "€");

        logJcsBeforeAfter(input);
        byte[] result = JcsCanonicalizer.canonicalize(input);

        assertThat(result).contains((byte) 0xe2, (byte) 0x82, (byte) 0xac);
        assertThat(new String(result, StandardCharsets.UTF_8)).doesNotContain("\\u20ac");
    }

    // -------------------------------------------------------------------------
    // Idempotency
    // -------------------------------------------------------------------------

    @Test
    void canonicalize_isIdempotent() throws Exception {
        // Canonicalizing already-canonical JSON must produce the same bytes.
        // This matches the production verify path: bytes arrive from the network,
        // are parsed, then canonicalized again for signature verification.
        ObjectNode inner = MAPPER.createObjectNode();
        inner.put("y", 2);
        inner.put("x", 1);
        ObjectNode input = MAPPER.createObjectNode();
        input.put("z", 1);
        input.set("a", inner);

        logJcsBeforeAfter(input);
        byte[] once = JcsCanonicalizer.canonicalize(input);
        byte[] twice = JcsCanonicalizer.canonicalize(
                MAPPER.readTree(new String(once, StandardCharsets.UTF_8)));

        assertThat(twice).isEqualTo(once);
    }

    // -------------------------------------------------------------------------
    // Rule 4: UTF-16 key sort order — RFC §3.2.3 example
    // -------------------------------------------------------------------------

    @Test
    void canonicalize_sortsKeysByUtf16CodeUnitValue() throws Exception {
        // RFC 8785 §3.2.3: keys sorted by UTF-16 code unit value (= Java String.compareTo).
        //
        //   Key          | UTF-16 value(s)         | Expected position
        //   \r           | U+000D  =    13          | 1st
        //   "1"          | U+0031  =    49          | 2nd
        //   \u0080       | U+0080  =   128          | 3rd
        //   \u00f6 (ö)   | U+00F6  =   246          | 4th
        //   \u20ac (€)   | U+20AC  =  8364          | 5th
        //   😀           | D83D DE00 (55357,56832)  | 6th  (first surrogate unit 55357)
        //   \ufb33 (דּ)   | U+FB33  = 64307          | 7th
        ObjectNode input = MAPPER.createObjectNode();
        input.put("\u20ac",       "Euro Sign");
        input.put("\r",           "Carriage Return");
        input.put("\ufb33",       "Hebrew Letter Dalet With Dagesh");
        input.put("1",            "One");
        input.put("\ud83d\ude00", "Emoji: Grinning Face");
        input.put("\u0080",       "Control");
        input.put("\u00f6",       "Latin Small Letter O With Diaeresis");

        logJcsBeforeAfter(input);
        String canonical = JcsCanonicalizer.canonicalizeToString(input);
        List<String> keys = new ArrayList<>();
        MAPPER.readTree(canonical).fieldNames().forEachRemaining(keys::add);

        assertThat(keys).containsExactly(
                "\r",             // U+000D  =    13
                "1",              // U+0031  =    49
                "\u0080",         // U+0080  =   128
                "\u00f6",         // U+00F6  =   246
                "\u20ac",         // U+20AC  =  8364
                "\ud83d\ude00",   // D83D    = 55357 (first surrogate unit)
                "\ufb33"          // U+FB33  = 64307
        );
    }

    // -------------------------------------------------------------------------
    // RFC 8785 §3.2.4 comprehensive sample — exact byte match
    // -------------------------------------------------------------------------

    @Test
    void canonicalize_rfc8785ComprehensiveSample_exactBytes() throws Exception {
        // RFC §3.2.4 end-to-end vector: all four rules exercised simultaneously.
        // Input is parsed with readTree to mirror the production path (bytes from wire).
        String inputJson =
                "{\"numbers\":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"
                + "\"string\":\"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\","
                + "\"literals\":[null, true, false]}";

        JsonNode input = MAPPER.readTree(inputJson);
        logJcsBeforeAfter(input);
        byte[] result = JcsCanonicalizer.canonicalize(input);

        // 118 canonical UTF-8 bytes from RFC 8785 §3.2.4.
        byte[] expected = {
                // {"literals":[null,tr
                0x7b, 0x22, 0x6c, 0x69, 0x74, 0x65, 0x72, 0x61, 0x6c, 0x73,
                0x22, 0x3a, 0x5b, 0x6e, 0x75, 0x6c, 0x6c, 0x2c, 0x74, 0x72,
                // ue,false],"numbers":
                0x75, 0x65, 0x2c, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x5d, 0x2c,
                0x22, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x22, 0x3a,
                // [333333333.3333333,1
                0x5b, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x2e, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x2c, 0x31,
                // e+30,4.5,0.002,1e-27
                0x65, 0x2b, 0x33, 0x30, 0x2c, 0x34, 0x2e, 0x35, 0x2c, 0x30,
                0x2e, 0x30, 0x30, 0x32, 0x2c, 0x31, 0x65, 0x2d, 0x32, 0x37,
                // ],"string":"€$  (e2 82 ac = € as raw UTF-8) then \u000f start (5c 75 30 30)
                0x5d, 0x2c, 0x22, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x22,
                0x3a, 0x22, (byte) 0xe2, (byte) 0x82, (byte) 0xac, 0x24, 0x5c, 0x75, 0x30, 0x30,
                // 0f\nA'B\"\\\\\"\/"}  (30 66 = \u000f end; 5c 6e = \n; 5c 22 = \"; 5c 5c 5c 5c = \\; 2f = / not escaped)
                0x30, 0x66, 0x5c, 0x6e, 0x41, 0x27, 0x42, 0x5c, 0x22,
                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x22, 0x2f, 0x22, 0x7d
        };

        assertThat(result).isEqualTo(expected);
    }
}
