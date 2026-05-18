package de.eecc.did.webvh.resolve;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.eecc.did.webvh.api.ResolveOptions;
import de.eecc.did.webvh.api.ResolveResult;
import de.eecc.did.webvh.exception.DidWebVhException;
import de.eecc.did.webvh.log.LogParser;
import de.eecc.did.webvh.log.LogValidator;
import de.eecc.did.webvh.model.DidLog;
import de.eecc.did.webvh.model.DidLogEntry;
import de.eecc.did.webvh.model.Parameters;
import de.eecc.did.webvh.support.Ed25519TestFixture;
import de.eecc.did.webvh.witness.WitnessProofCollection;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Reproduces the failing vectors reported in
 * https://github.com/european-epc-competence-center/didwebvh/issues/1
 *
 * <p>Vectors were fetched from
 * https://github.com/swcurran/didwebvh-test-suite/tree/main/vectors and copied into
 * {@code src/test/resources/witness-suite/}. Each test resolves the foreign-impl log
 * with our resolver and logs the outcome so the failure mode is visible in the build log.
 *
 * <p>This is an investigation harness — tests do not assert. Look at the captured log
 * lines to see what our resolver reports.
 *
 * <h2>Expected outcomes per vector (see docs/work.md §P2)</h2>
 *
 * <p>All {@code witness-update*} vectors share the log shape
 * {@code v1: witness={threshold:2, witnesses:[A,B]} → v2: witness={threshold:1, witnesses:[A]}}.
 * Under the spec-literal "prev config governs the rotation entry" rule that this resolver
 * implements:
 *
 * <ul>
 *   <li>{@code witness-update-python} — proofs A+B at v1, A at v2; expected {@code invalidDid}.
 *       Our resolver agrees: v2 governed by A+B threshold=2, only A signed v2 → 1 &lt; 2.</li>
 *   <li>{@code witness-update-ts} — same proofs; upstream expects success, we report
 *       {@code invalidDid}. The TS generator encodes the permissive "new config governs"
 *       interpretation; under spec-literal the vector is under-witnessed at v2.</li>
 *   <li>{@code witness-update-java} (ivir3zam) — same as TS. Upstream expects success;
 *       ivir3zam's validator uses the merged-current config, which is the same interpretation.</li>
 *   <li>{@code witness-update-rust} — proofs at v2 only (A+B); upstream expects success.
 *       Our resolver rejects on a separate spec violation: the Rust generator emits witness
 *       {@code id} as a bare multibase key (e.g. {@code z6Mkrv5…}) instead of a
 *       {@code did:key:} DID. Spec §Witness Lists requires {@code did:key}.</li>
 *   <li>{@code witness-threshold-rust} — single entry; same Rust-generator
 *       witness-{@code id} problem.</li>
 *   <li>{@code witness-update-java-eecc} — self-generated under the previous (buggy)
 *       rotation interpretation. Entries 1 and 2 also share the same {@code versionTime}
 *       because they were generated before the {@code computeVersionTime} fix in commit
 *       {@code 374e73e}. Will reject on entry 2 until regenerated.</li>
 * </ul>
 *
 * <p>Disabled on CI: these tests exist for manual investigation and depend on external
 * vectors that are still in flux upstream. Re-enable locally by removing the
 * {@code @Disabled} annotation.
 */
@Disabled("investigation harness — enable locally to inspect cross-impl resolution outcomes")
class WitnessTestSuiteReproTest {

    private static final Logger log = LoggerFactory.getLogger(WitnessTestSuiteReproTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String BASE = "/witness-suite/";

    // Expected: invalidDid under spec-literal (rotation governed by prev config).
    // Upstream expects success → diverges; ivir3zam validator uses curr config for rotation.
    @Test
    @DisplayName("witness-update — java-impl (ivir3zam) generated log")
    void witnessUpdate_java() throws Exception {
        runVector("witness-update-java");
    }

    // Expected: invalidDid — Rust generator emits non-did:key witness id (spec violation),
    // rejected at parameter validation before witness check is reached.
    @Test
    @DisplayName("witness-update — rust-impl-generated log")
    void witnessUpdate_rust() throws Exception {
        runVector("witness-update-rust");
    }

    // Expected: invalidDid under spec-literal (rotation governed by prev config).
    // Upstream expects success → diverges; TS only validates witness at the last entry
    // using the merged-current config.
    @Test
    @DisplayName("witness-update — ts-impl-generated log")
    void witnessUpdate_ts() throws Exception {
        runVector("witness-update-ts");
    }

    // Expected: invalidDid — same Rust generator bug (non-did:key witness id).
    @Test
    @DisplayName("witness-threshold — rust-impl-generated log")
    void witnessThreshold_rust() throws Exception {
        runVector("witness-threshold-rust");
    }

    // Expected: log-validation failure on entry 2 — generated under the old (buggy) rotation
    // interpretation AND before the versionTime auto-advance fix (commit 374e73e), so v1 and v2
    // share the same versionTime. Needs regeneration.
    @Test
    @DisplayName("witness-update — java-eecc self-generated log")
    void witnessUpdate_javaEecc() throws Exception {
        runVector("witness-update-java-eecc");
    }

    // Expected: invalidDid (and upstream agrees) — under spec-literal v2 is governed by
    // A+B threshold=2 but only A signed v2.
    @Test
    @DisplayName("witness-update — python-impl-generated log")
    void witnessUpdate_python() throws Exception {
        runVector("witness-update-python");
    }

    private void runVector(String name) throws Exception {
        log.info("================ {} ================", name);
        String jsonl = load(BASE + name + "/did.jsonl");
        String witnessJson = loadOptional(BASE + name + "/did-witness.json");
        String expectedJson = loadOptional(BASE + name + "/resolutionResult.json");

        String expectedDid = extractDid(expectedJson);
        log.info("expected DID: {}", expectedDid);

        DidLog didLog = LogParser.parse(jsonl);
        log.info("parsed {} log entries", didLog.entries().size());

        // Drill-down: walk each entry through LogValidator so we can see the precise
        // rejection reason if the resolver later reports "No valid entries in the DID log".
        LogValidator validator = new LogValidator(Ed25519TestFixture.verifier());
        Parameters activeParams = null;
        DidLogEntry previous = null;
        for (int i = 0; i < didLog.entries().size(); i++) {
            DidLogEntry entry = didLog.entries().get(i);
            try {
                activeParams = validator.validateEntry(entry, previous, activeParams);
                log.info("  validateEntry {} OK", i + 1);
                previous = entry;
            } catch (DidWebVhException ex) {
                log.error("  validateEntry {} REJECTED: {}: {}", i + 1,
                        ex.getClass().getSimpleName(), ex.getMessage());
            }
        }

        for (int i = 0; i < didLog.entries().size(); i++) {
            var e = didLog.entries().get(i);
            log.info("  entry {} versionId={} versionTime={} params.witness={}",
                    i + 1, e.versionId(), e.versionTime(),
                    e.parameters() != null ? e.parameters().witness() : null);
        }

        ResolveOptions.Builder optBuilder = ResolveOptions.builder()
                .verifier(Ed25519TestFixture.verifier());
        if (witnessJson != null) {
            WitnessProofCollection proofs = WitnessProofCollection.parse(witnessJson);
            optBuilder.witnessProofs(proofs);
            log.info("loaded witness proofs: {} entries", proofs.entries().size());
        } else {
            log.info("no did-witness.json present");
        }

        try {
            ResolveResult result = new LogBasedResolver().resolve(expectedDid, didLog, optBuilder.build());
            if (result.document() != null) {
                log.info("RESOLVED OK -> versionId={}", result.documentMetadata().versionId());
            } else {
                log.warn("RESOLUTION RETURNED ERROR -> {}", result.resolutionMetadata());
            }
        } catch (Exception ex) {
            log.error("RESOLUTION THREW {}: {}", ex.getClass().getSimpleName(), ex.getMessage());
        }
        log.info("=========================================");
    }

    private static String extractDid(String resolutionResultJson) throws Exception {
        if (resolutionResultJson == null) return null;
        JsonNode root = MAPPER.readTree(resolutionResultJson);
        JsonNode doc = root.get("didDocument");
        return doc != null && doc.has("id") ? doc.get("id").asText() : null;
    }

    private static String load(String path) throws Exception {
        try (InputStream is = WitnessTestSuiteReproTest.class.getResourceAsStream(path)) {
            if (is == null) {
                throw new IllegalStateException("missing test resource: " + path);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String loadOptional(String path) throws Exception {
        try (InputStream is = WitnessTestSuiteReproTest.class.getResourceAsStream(path)) {
            return is == null ? null : new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
