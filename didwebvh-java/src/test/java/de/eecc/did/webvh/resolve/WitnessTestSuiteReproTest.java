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
 */
class WitnessTestSuiteReproTest {

    private static final Logger log = LoggerFactory.getLogger(WitnessTestSuiteReproTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String BASE = "/witness-suite/";

    @Test
    @DisplayName("witness-update — java-impl-generated log")
    void witnessUpdate_java() throws Exception {
        runVector("witness-update-java");
    }

    @Test
    @DisplayName("witness-update — rust-impl-generated log")
    void witnessUpdate_rust() throws Exception {
        runVector("witness-update-rust");
    }

    @Test
    @DisplayName("witness-update — ts-impl-generated log")
    void witnessUpdate_ts() throws Exception {
        runVector("witness-update-ts");
    }

    @Test
    @DisplayName("witness-threshold — rust-impl-generated log")
    void witnessThreshold_rust() throws Exception {
        runVector("witness-threshold-rust");
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
