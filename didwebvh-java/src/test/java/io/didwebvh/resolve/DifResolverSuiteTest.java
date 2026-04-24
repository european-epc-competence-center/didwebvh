package io.didwebvh.resolve;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;
import io.didwebvh.log.LogParser;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.ResolutionMetadata;
import io.didwebvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Runs the official DIF did:webvh resolver interoperability test suite against
 * our {@link LogBasedResolver}.
 *
 * <p>Test data sourced from
 * <a href="https://github.com/decentralized-identity/didwebvh-test-suite">
 * decentralized-identity/didwebvh-test-suite</a>.
 *
 * <p>Each test case specifies a log directory, a DID URL (possibly with query
 * parameters like {@code ?versionId=...} or {@code ?versionNumber=...}), and
 * expected outcome (status + metadata assertions).
 *
 * <p>Witness validation is not yet implemented — test cases that require it
 * are documented but skipped.
 */
class DifResolverSuiteTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SUITE_JSON = "/dif-test-suite/resolver-suite.json";
    private static final String LOGS_BASE = "/dif-test-suite/logs/";

    /**
     * Test cases that require witness validation (not yet implemented).
     * Identified by their DID URL to keep the skip logic transparent.
     */
    private static final Set<String> WITNESS_DEPENDENT_TESTS = Set.of(
            // missing-witness: latest resolution and versionNumber=3 require witness validation
            "did:webvh:QmcASXkJMnprWNJCbyJ5394tCv8JDfrGptUmbCBoy4UtHE:domain.example[missing-witness]",
            "did:webvh:QmcASXkJMnprWNJCbyJ5394tCv8JDfrGptUmbCBoy4UtHE:domain.example?versionNumber=3[missing-witness]"
    );

    private static LogBasedResolver resolver;
    private static List<TestCase> allTestCases;

    @BeforeAll
    static void loadSuite() throws IOException {
        resolver = new LogBasedResolver();
        try (InputStream is = DifResolverSuiteTest.class.getResourceAsStream(SUITE_JSON)) {
            assertThat(is).as("resolver-suite.json must be on classpath").isNotNull();
            allTestCases = parseTestCases(MAPPER.readTree(is));
        }
    }

    static Stream<TestCase> testCases() throws IOException {
        if (allTestCases == null) {
            try (InputStream is = DifResolverSuiteTest.class.getResourceAsStream(SUITE_JSON)) {
                allTestCases = parseTestCases(MAPPER.readTree(is));
            }
        }
        return allTestCases.stream();
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("testCases")
    void resolverSuiteTest(TestCase tc) throws IOException {
        String skipKey = tc.didUrl + "[" + tc.logName + "]";
        Assumptions.assumeFalse(WITNESS_DEPENDENT_TESTS.contains(skipKey),
                "Witness validation not implemented — skipping: " + tc);

        String jsonl = loadResource(LOGS_BASE + tc.logName + "/did.jsonl");
        DidLog didLog = LogParser.parse(jsonl);

        ResolveOptions.Builder optBuilder = ResolveOptions.builder()
                .verifier(Ed25519TestFixture.verifier());

        if (tc.versionId != null) {
            optBuilder.versionId(tc.versionId);
        }
        if (tc.versionNumber != null) {
            optBuilder.versionNumber(tc.versionNumber);
        }

        ResolveResult result = resolver.resolve(tc.did, didLog, optBuilder.build());

        if ("ok".equals(tc.expectedStatus)) {
            assertThat(result.document())
                    .as("Expected successful resolution for: %s", tc)
                    .isNotNull();
            assertDocumentMetadata(tc, result.metadata());
        } else {
            assertThat(result.document())
                    .as("Expected error resolution for: %s", tc)
                    .isNull();
            assertResolutionMetadata(tc, result.metadata());
        }
    }

    // -------------------------------------------------------------------------
    // Metadata assertions — only checks fields present in the expected output
    // -------------------------------------------------------------------------

    private void assertDocumentMetadata(TestCase tc, ResolutionMetadata actual) {
        Map<String, Object> expected = tc.expectedDocumentMetadata;
        if (expected == null) return;

        if (expected.containsKey("versionId")) {
            assertThat(actual.versionId())
                    .as("versionId for: %s", tc)
                    .isEqualTo(expected.get("versionId"));
        }
        if (expected.containsKey("versionNumber")) {
            assertThat(actual.versionNumber())
                    .as("versionNumber for: %s", tc)
                    .isEqualTo(((Number) expected.get("versionNumber")).intValue());
        }
        if (expected.containsKey("versionTime")) {
            assertThat(actual.versionTime())
                    .as("versionTime for: %s", tc)
                    .isEqualTo(expected.get("versionTime"));
        }
        if (expected.containsKey("created")) {
            assertThat(actual.created())
                    .as("created for: %s", tc)
                    .isEqualTo(expected.get("created"));
        }
        if (expected.containsKey("updated")) {
            assertThat(actual.updated())
                    .as("updated for: %s", tc)
                    .isEqualTo(expected.get("updated"));
        }
    }

    private void assertResolutionMetadata(TestCase tc, ResolutionMetadata actual) {
        Map<String, Object> expected = tc.expectedResolutionMetadata;
        if (expected == null) return;

        if (expected.containsKey("error")) {
            assertThat(actual.error())
                    .as("error code for: %s", tc)
                    .isEqualTo(expected.get("error"));
        }
    }

    // -------------------------------------------------------------------------
    // Test case parsing
    // -------------------------------------------------------------------------

    private static List<TestCase> parseTestCases(JsonNode suiteArray) {
        List<TestCase> cases = new ArrayList<>();
        for (JsonNode node : suiteArray) {
            cases.add(parseTestCase(node));
        }
        return cases;
    }

    private static TestCase parseTestCase(JsonNode node) {
        String logName = node.get("log").asText();
        String didUrl = node.get("did_url").asText();
        String status = node.get("status").asText();

        String did = didUrl.contains("?") ? didUrl.substring(0, didUrl.indexOf('?')) : didUrl;
        Map<String, String> queryParams = parseQueryParams(didUrl);

        String versionId = queryParams.get("versionId");
        Integer versionNumber = queryParams.containsKey("versionNumber")
                ? Integer.parseInt(queryParams.get("versionNumber"))
                : null;

        Map<String, Object> docMeta = null;
        if (node.has("didDocumentMetadata")) {
            docMeta = MAPPER.convertValue(node.get("didDocumentMetadata"),
                    new TypeReference<Map<String, Object>>() {});
        }

        Map<String, Object> resMeta = null;
        if (node.has("didResolutionMetadata")) {
            resMeta = MAPPER.convertValue(node.get("didResolutionMetadata"),
                    new TypeReference<Map<String, Object>>() {});
        }

        boolean conflicting = versionId != null && versionNumber != null;
        return new TestCase(logName, didUrl, did, versionId, versionNumber,
                status, docMeta, resMeta, conflicting);
    }

    private static Map<String, String> parseQueryParams(String didUrl) {
        int qIdx = didUrl.indexOf('?');
        if (qIdx < 0) return Map.of();

        Map<String, String> params = new LinkedHashMap<>();
        String query = didUrl.substring(qIdx + 1);
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                params.put(pair.substring(0, eq), pair.substring(eq + 1));
            }
        }
        return params;
    }

    private static String loadResource(String path) throws IOException {
        try (InputStream is = DifResolverSuiteTest.class.getResourceAsStream(path)) {
            if (is == null) {
                fail("Test resource not found: " + path);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // -------------------------------------------------------------------------
    // Test case record
    // -------------------------------------------------------------------------

    record TestCase(
            String logName,
            String didUrl,
            String did,
            String versionId,
            Integer versionNumber,
            String expectedStatus,
            Map<String, Object> expectedDocumentMetadata,
            Map<String, Object> expectedResolutionMetadata,
            boolean hasConflictingFilters
    ) {
        @Override
        public String toString() {
            String filter = "";
            if (hasConflictingFilters) filter = " [CONFLICTING_FILTERS]";
            else if (versionId != null) filter = " ?versionId=" + versionId;
            else if (versionNumber != null) filter = " ?versionNumber=" + versionNumber;
            return logName + filter + " → " + expectedStatus;
        }
    }
}
