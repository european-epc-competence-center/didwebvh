package de.eecc.did.webvh.resolve;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.eecc.did.webvh.api.DidWebVh;
import de.eecc.did.webvh.api.ResolveOptions;
import de.eecc.did.webvh.api.ResolveResult;
import de.eecc.did.webvh.log.LogParser;
import de.eecc.did.webvh.model.DidLog;
import de.eecc.did.webvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Local reproduction of ONE official negative test-suite vector
 * ({@code negative-versiontime-non-monotonic}) using the EXACT files committed in
 * swcurran/didwebvh-test-suite, to answer empirically:
 *
 * <ol>
 *   <li>Does {@code resolveFromLog} throw, or return an error in {@code didResolutionMetadata}?</li>
 *   <li>Does our output match the suite's expected {@code resolutionResult.json}
 *       ({@code didDocument: null}, {@code error: "invalidDid"})?</li>
 *   <li>What would the java-eecc test-suite adapter's negative branch record, and why?</li>
 * </ol>
 */
class NegativeVectorReproTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String BASE = "/negative-suite/negative-versiontime-non-monotonic/";

    @Test
    void reproduceNegativeVectorAndCompareHarnessLogic() throws Exception {
        String rawJsonl = load(BASE + "did.jsonl");
        String expectedJson = load(BASE + "resolutionResult.json");
        JsonNode expected = MAPPER.readTree(expectedJson);

        DidLog negLog = LogParser.parse(rawJsonl);
        // This is EXACTLY how the test-suite adapter picks the DID: from the log's own genesis "id".
        String did = negLog.first().state().path("id").asText(null);

        System.out.println("\n==================== NEGATIVE VECTOR REPRO ====================");
        System.out.println("vector : negative-versiontime-non-monotonic (from swcurran/didwebvh-test-suite)");
        System.out.println("did    : " + did);
        System.out.println("expected resolutionResult.json:");
        System.out.println("    didDocument            = " + expected.get("didDocument"));
        System.out.println("    didResolutionMetadata  = " + expected.get("didResolutionMetadata"));

        // ---- Replicate the java-eecc adapter's NEGATIVE branch VERBATIM -------------------
        // try { resolveFromLog(...); fail++ "resolver accepted invalid log"; }
        // catch (Exception e) { pass++; }
        String harnessOutcome;
        boolean threw;
        ResolveResult result = null;
        try {
            result = DidWebVh.resolveFromLog(
                    did, negLog,
                    ResolveOptions.builder().verifier(Ed25519TestFixture.verifier()).build());
            threw = false;
            harnessOutcome = "FAIL  (\"resolver accepted invalid log\")";
        } catch (Exception e) {
            threw = true;
            harnessOutcome = "PASS  (caught " + e.getClass().getSimpleName() + ")";
        }

        System.out.println("\n---- What actually happened in the library ----");
        System.out.println("resolveFromLog threw an exception? " + threw);
        if (result != null) {
            System.out.println("result.isSuccess()                 = " + result.isSuccess());
            System.out.println("result.document()                  = " + result.document());
            System.out.println("result.resolutionMetadata().error()= "
                    + result.resolutionMetadata().error());
            if (result.resolutionMetadata().problemDetails() != null) {
                System.out.println("problemDetails.detail              = "
                        + result.resolutionMetadata().problemDetails().detail());
            }
        }

        System.out.println("\n---- Adapter logic comparison ----");
        System.out.println("java-eecc adapter (catch == pass)  would record: " + harnessOutcome);
        boolean correctlyRejected = result != null
                && !result.isSuccess()
                && result.resolutionMetadata() != null
                && result.resolutionMetadata().error() != null;
        System.out.println("correct adapter (metadata check)   would record: "
                + (correctlyRejected ? "PASS  (error=" + result.resolutionMetadata().error() + ")" : "FAIL"));
        System.out.println("===============================================================\n");

        // ---- The empirical findings, as assertions --------------------------------------
        // 1. The library does NOT throw — it returns a result (this is what defeats the adapter).
        assertThat(threw)
                .as("resolveFromLog must NOT throw; it returns errors in didResolutionMetadata")
                .isFalse();

        // 2. The library DID reject the invalid log: null document + invalidDid error.
        assertThat(result.document())
                .as("didDocument must be null for a rejected log")
                .isNull();
        assertThat(result.resolutionMetadata().error())
                .as("error code must be invalidDid")
                .isEqualTo("invalidDid");

        // 3. Our output matches the suite's own expected resolutionResult.json exactly.
        assertThat(expected.get("didDocument").isNull()).isTrue();
        assertThat(expected.get("didResolutionMetadata").get("error").asText())
                .isEqualTo(result.resolutionMetadata().error());
    }

    private static String load(String path) throws Exception {
        try (InputStream is = NegativeVectorReproTest.class.getResourceAsStream(path)) {
            assertThat(is).as("resource on classpath: " + path).isNotNull();
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
