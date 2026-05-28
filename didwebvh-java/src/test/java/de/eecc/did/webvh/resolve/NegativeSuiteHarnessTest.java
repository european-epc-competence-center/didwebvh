package de.eecc.did.webvh.resolve;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.eecc.did.webvh.api.DidWebVh;
import de.eecc.did.webvh.api.ResolveOptions;
import de.eecc.did.webvh.api.ResolveResult;
import de.eecc.did.webvh.log.LogParser;
import de.eecc.did.webvh.model.DidLog;
import de.eecc.did.webvh.witness.WitnessProofCollection;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Local copy of the java-eecc test-suite harness ({@code TestVectors.java}) negative-test
 * logic, run against ALL committed negative vectors from swcurran/didwebvh-test-suite.
 *
 * <p>The ONLY change from the upstream harness is in the LOG-BASED negative branch
 * (see {@link #runLogBased}): the upstream code decides a negative test passed solely by
 * whether {@code resolveFromLog} THREW. Because the spec-conformant eecc library returns
 * errors in {@code didResolutionMetadata} instead of throwing, that branch is fixed here to
 * treat "rejected" as: an exception was thrown OR the result is not successful and carries an
 * {@code error} code. The URL-only branch is left exactly as upstream (parser must throw),
 * so genuine syntax-validation gaps still surface.
 *
 * <p>This test is report-first: it prints a full table of upstream-verdict vs fixed-verdict
 * for every vector, then asserts that no log-based negative is silently accepted.
 */
class NegativeSuiteHarnessTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path SUITE = Paths.get("src/test/resources/negative-suite");
    private static final Pattern DID_IN_SCRIPT = Pattern.compile("\"(did:webvh:[^\"]+)\"");

    private record Row(String scenario, String type, String expected,
                       String upstreamVerdict, String fixedVerdict, String libraryResult) {}

    @Test
    void runAllNegativeVectorsThroughFixedHarness() throws Exception {
        assertThat(Files.isDirectory(SUITE))
                .as("negative-suite resources present at " + SUITE.toAbsolutePath())
                .isTrue();

        List<Path> scenarios;
        try (Stream<Path> s = Files.list(SUITE)) {
            scenarios = s.filter(Files::isDirectory).sorted().collect(Collectors.toList());
        }

        List<Row> rows = new ArrayList<>();
        for (Path dir : scenarios) {
            String name = dir.getFileName().toString();
            String expectedError = readExpectedError(dir);
            String rawJsonl = Files.readString(dir.resolve("did.jsonl")).strip();
            rows.add(rawJsonl.isEmpty()
                    ? runUrlOnly(dir, name, expectedError)
                    : runLogBased(dir, name, expectedError, rawJsonl));
        }

        printTable(rows);

        // The harness-bug category: every LOG-BASED invalid log MUST be rejected by the
        // library (exception or error metadata). If any is silently accepted, that's a real
        // implementation gap, not a harness artifact — fail loudly so we notice.
        List<String> silentlyAccepted = rows.stream()
                .filter(r -> r.type.equals("LOG") && r.fixedVerdict.startsWith("FAIL"))
                .map(r -> r.scenario)
                .collect(Collectors.toList());
        assertThat(silentlyAccepted)
                .as("log-based invalid logs that the library wrongly ACCEPTED")
                .isEmpty();
    }

    /** FIXED log-based branch: rejected == exception thrown OR (!isSuccess && error != null). */
    private Row runLogBased(Path dir, String name, String expectedError, String rawJsonl) {
        String upstreamVerdict;
        String fixedVerdict;
        String libraryResult;
        try {
            DidLog log = LogParser.parse(rawJsonl);
            String did = log.first().state().path("id").asText(null);

            ResolveOptions.Builder rb = ResolveOptions.builder();
            Path witness = dir.resolve("did-witness.json");
            if (Files.exists(witness)) {
                rb.witnessProofs(WitnessProofCollection.parse(Files.readString(witness)));
            }

            ResolveResult result = DidWebVh.resolveFromLog(did, log, rb.build());

            // --- upstream logic: no throw == "accepted" == FAIL ---
            upstreamVerdict = "FAIL (resolver accepted invalid log)";

            // --- fixed logic: inspect resolution metadata ---
            boolean rejected = !result.isSuccess()
                    && result.resolutionMetadata() != null
                    && result.resolutionMetadata().error() != null;
            if (rejected) {
                String detail = result.resolutionMetadata().problemDetails() != null
                        ? result.resolutionMetadata().problemDetails().detail() : "";
                fixedVerdict = "PASS";
                libraryResult = "doc=null, error=" + result.resolutionMetadata().error()
                        + " — " + detail;
            } else {
                fixedVerdict = "FAIL (truly accepted)";
                libraryResult = "isSuccess=" + result.isSuccess()
                        + ", error=" + (result.resolutionMetadata() == null ? "?"
                        : result.resolutionMetadata().error());
            }
        } catch (Exception e) {
            upstreamVerdict = "PASS (threw " + e.getClass().getSimpleName() + ")";
            fixedVerdict = "PASS";
            libraryResult = "threw " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        return new Row(name, "LOG", expectedError, upstreamVerdict, fixedVerdict, libraryResult);
    }

    /** URL-only branch: UNCHANGED from upstream — parser MUST throw for every DID. */
    private Row runUrlOnly(Path dir, String name, String expectedError) throws Exception {
        List<String> dids = extractDids(dir.resolve("script.yaml"));
        String accepted = null;
        for (String did : dids) {
            try {
                DidUrlTransformer.toLogUrl(did);
                accepted = did; // parser did NOT reject an invalid DID
                break;
            } catch (Exception ignored) {
                // correctly rejected
            }
        }
        String verdict = (accepted == null) ? "PASS" : "FAIL (parser accepted invalid DID)";
        String detail = (accepted == null)
                ? "all " + dids.size() + " DID(s) rejected by parser"
                : "accepted: " + accepted;
        // URL branch is identical upstream and fixed.
        return new Row(name, "URL", expectedError, verdict, verdict, detail);
    }

    private static String readExpectedError(Path dir) throws Exception {
        JsonNode rr = MAPPER.readTree(dir.resolve("resolutionResult.json").toFile());
        JsonNode rm = rr.path("didResolutionMetadata");
        return rm.has("error") ? rm.get("error").asText() : "?";
    }

    private static List<String> extractDids(Path scriptYaml) throws Exception {
        List<String> dids = new ArrayList<>();
        if (!Files.exists(scriptYaml)) return dids;
        Matcher m = DID_IN_SCRIPT.matcher(Files.readString(scriptYaml));
        while (m.find()) dids.add(m.group(1));
        return dids;
    }

    private static void printTable(List<Row> rows) {
        System.out.println("\n================ NEGATIVE SUITE — FIXED HARNESS (all 16 vectors) ================");
        System.out.printf("%-38s %-4s %-17s %-42s %-22s%n",
                "scenario", "type", "expected", "upstream-harness verdict", "FIXED verdict");
        System.out.println("-".repeat(128));
        int upstreamPass = 0, fixedPass = 0;
        for (Row r : rows) {
            System.out.printf("%-38s %-4s %-17s %-42s %-22s%n",
                    r.scenario, r.type, r.expected, r.upstreamVerdict, r.fixedVerdict);
            if (r.upstreamVerdict.startsWith("PASS")) upstreamPass++;
            if (r.fixedVerdict.startsWith("PASS")) fixedPass++;
        }
        System.out.println("-".repeat(128));
        System.out.printf("UPSTREAM harness: %d/%d pass    FIXED harness: %d/%d pass%n",
                upstreamPass, rows.size(), fixedPass, rows.size());
        System.out.println("\n---- library detail per vector ----");
        for (Row r : rows) {
            System.out.printf("  %-38s -> %s%n", r.scenario, r.libraryResult);
        }
        System.out.println("================================================================================\n");
    }
}
