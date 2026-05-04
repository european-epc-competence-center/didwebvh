package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.*;
import io.didwebvh.crypto.DataIntegrity;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.WitnessParameter;
import io.didwebvh.model.proof.DataIntegrityProof;
import io.didwebvh.operation.CreateOperation;
import io.didwebvh.operation.DeactivateOperation;
import io.didwebvh.operation.UpdateOperation;
import io.didwebvh.support.Ed25519TestFixture;
import io.didwebvh.witness.WitnessProofCollection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LogBasedResolverTest {

    //private static final Logger log = LoggerFactory.getLogger(LogBasedResolverTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DOMAIN = "example.com";

    private Ed25519TestFixture fixture;
    private LogBasedResolver resolver;

    @BeforeEach
    void setUp() {
        fixture = Ed25519TestFixture.generate();
        resolver = new LogBasedResolver();
    }

    private ResolveOptions defaultOptions() {
        return ResolveOptions.builder()
                .verifier(Ed25519TestFixture.verifier())
                .build();
    }

    private ObjectNode initialDocument() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
        doc.put("id", "did:webvh:{SCID}:" + DOMAIN);
        return doc;
    }

    private CreateResult createDid() {
        return CreateOperation.create(
                CreateOptions.builder()
                        .domain(DOMAIN)
                        .initialDocument(initialDocument())
                        .updateKeys(List.of(fixture.publicKeyMultibase()))
                        .signer(fixture.signer())
                        .build());
    }

    private UpdateResult updateDid(DidLog log, String scid) {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
        doc.put("id", "did:webvh:" + scid + ":" + DOMAIN);
        doc.put("updated", "true");
        return UpdateOperation.update(
                UpdateOptions.builder()
                        .log(log)
                        .updatedDocument(doc)
                        .signer(fixture.signer())
                        .build());
    }

    private String scidFrom(DidLog log) {
        return log.first().parameters().scid();
    }

    private String didFrom(DidLog log) {
        return "did:webvh:" + scidFrom(log) + ":" + DOMAIN;
    }

    /**
     * Creates a single witness proof entry for the given versionId, signed by {@code witness}.
     * This is the format expected inside {@code did-witness.json}.
     */
    private WitnessProofCollection.Entry proofFrom(Ed25519TestFixture witness, String versionId) {
        String vmId = "did:key:" + witness.publicKeyMultibase() + "#" + witness.publicKeyMultibase();
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("versionId", versionId);
        DataIntegrityProof proof = DataIntegrity.createProof(doc, vmId, witness.signer());
        return new WitnessProofCollection.Entry(versionId, List.of(proof));
    }

    // -------------------------------------------------------------------------
    // Latest version resolution
    // -------------------------------------------------------------------------

    @Nested
    class LatestVersion {

        @Test
        void resolveFromSingleEntryLog() {
            CreateResult created = createDid();
            ResolveResult result = resolver.resolve(created.did(), created.log(), defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.did()).isEqualTo(created.did());
            assertThat(result.document()).isNotNull();
            assertThat(result.metadata().versionId()).isEqualTo(created.log().latest().versionId());
            assertThat(result.metadata().scid()).isEqualTo(scidFrom(created.log()));
            assertThat(result.metadata().deactivated()).isFalse();
            assertThat(result.metadata().error()).isNull();
        }

        @Test
        void resolveFromMultiEntryLog() {
            CreateResult created = createDid();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateDid(created.log(), scid);

            ResolveResult result = resolver.resolve(created.did(), updated.log(), defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.document()).isNotNull();
            assertThat(result.metadata().versionId()).isEqualTo(updated.log().latest().versionId());
            assertThat(result.metadata().created()).isEqualTo(created.log().first().versionTime());
            assertThat(result.metadata().updated()).isEqualTo(updated.log().latest().versionTime());
        }

        @Test
        void metadataContainsCreatedAndUpdatedTimestamps() {
            CreateResult created = createDid();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateDid(created.log(), scid);

            ResolveResult result = resolver.resolve(created.did(), updated.log(), defaultOptions());

            assertThat(result.metadata().created()).isEqualTo(created.log().first().versionTime());
            assertThat(result.metadata().updated()).isEqualTo(updated.log().latest().versionTime());
        }
    }

    // -------------------------------------------------------------------------
    // Version filters
    // -------------------------------------------------------------------------

    @Nested
    class VersionFilters {

        @Test
        void resolveByVersionId() {
            CreateResult created = createDid();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateDid(created.log(), scid);
            String genesisVersionId = created.log().first().versionId();

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionId(genesisVersionId)
                    .build();

            ResolveResult result = resolver.resolve(created.did(), updated.log(), options);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.metadata().versionId()).isEqualTo(genesisVersionId);
        }

        @Test
        void resolveByVersionNumber() {
            CreateResult created = createDid();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateDid(created.log(), scid);

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionNumber(1)
                    .build();

            ResolveResult result = resolver.resolve(created.did(), updated.log(), options);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.metadata().versionId()).isEqualTo(created.log().first().versionId());
        }

        @Test
        void resolveByVersionTime() {
            CreateResult created = createDid();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateDid(created.log(), scid);

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionTime(Instant.now())
                    .build();

            ResolveResult result = resolver.resolve(created.did(), updated.log(), options);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.metadata().versionId()).isEqualTo(updated.log().latest().versionId());
        }

        @Test
        void versionIdNotFound_returnsErrorMetadata() {
            CreateResult created = createDid();

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionId("999-nonexistent")
                    .build();

            ResolveResult result = resolver.resolve(created.did(), created.log(), options);

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.document()).isNull();
            assertThat(result.metadata().error()).isEqualTo("notFound");
        }

        @Test
        void versionNumberNotFound_returnsErrorMetadata() {
            CreateResult created = createDid();

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionNumber(999)
                    .build();

            ResolveResult result = resolver.resolve(created.did(), created.log(), options);

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("notFound");
        }

        @Test
        void multipleFilters_returnsNotFoundError() {
            CreateResult created = createDid();

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionId("1-abc")
                    .versionNumber(1)
                    .build();

            ResolveResult result = resolver.resolve(created.did(), created.log(), options);

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("notFound");
        }
    }

    // -------------------------------------------------------------------------
    // Deactivation
    // -------------------------------------------------------------------------

    @Nested
    class Deactivation {

        @Test
        void deactivatedDid_returnsNullDocumentWithMetadata() {
            CreateResult created = createDid();
            DeactivateResult deactivated = DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(created.log())
                            .signer(fixture.signer())
                            .build());

            ResolveResult result = resolver.resolve(created.did(), deactivated.log(), defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.document()).isNull();
            assertThat(result.metadata().deactivated()).isTrue();
            assertThat(result.metadata().error()).isNull();
        }

        @Test
        void deactivatedDid_historicalVersionStillResolvable() {
            CreateResult created = createDid();
            DeactivateResult deactivated = DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(created.log())
                            .signer(fixture.signer())
                            .build());

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionNumber(1)
                    .build();

            ResolveResult result = resolver.resolve(created.did(), deactivated.log(), options);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.document()).isNotNull();
            assertThat(result.metadata().deactivated()).isTrue();
        }
    }

    // -------------------------------------------------------------------------
    // Error handling
    // -------------------------------------------------------------------------

    @Nested
    class ErrorHandling {

        @Test
        void emptyLog_returnsErrorMetadata() {
            ResolveResult result = resolver.resolve("did:webvh:abc:example.com",
                    DidLog.empty(), defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void tamperedLog_returnsErrorMetadata() {
            CreateResult created = createDid();

            DidLogEntry original = created.log().first();
            DidLogEntry tampered = new DidLogEntry(
                    original.versionId(),
                    original.versionTime(),
                    original.parameters(),
                    MAPPER.createObjectNode().put("id", "tampered"),
                    original.proof());

            List<DidLogEntry> entries = new ArrayList<>();
            entries.add(tampered);
            DidLog tamperedLog = new DidLog(entries);

            ResolveResult result = resolver.resolve(created.did(), tamperedLog, defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void scidMismatch_returnsErrorMetadata() {
            CreateResult created = createDid();
            // Use a DID with a completely different SCID than what is in the log
            String wrongDid = "did:webvh:tampered:" + DOMAIN;

            ResolveResult result = resolver.resolve(wrongDid, created.log(), defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
            assertThat(result.metadata().problemDetails().detail()).contains("does not match SCID in log");
        }

        @Test
        void nullVerifier_usesDefaultVerifier_andSucceeds() {
            CreateResult created = createDid();
            ResolveOptions options = ResolveOptions.builder().build();

            ResolveResult result = resolver.resolve(created.did(), created.log(), options);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.document()).isNotNull();
        }

        @Test
        void nullDid_throwsNullPointer() {
            CreateResult created = createDid();

            assertThatThrownBy(() -> resolver.resolve(null, created.log(), defaultOptions()))
                    .isInstanceOf(NullPointerException.class);
        }

        @Test
        void nullLog_throwsNullPointer() {
            assertThatThrownBy(() -> resolver.resolve("did:webvh:abc:example.com",
                    null, defaultOptions()))
                    .isInstanceOf(NullPointerException.class);
        }

    @Test
    void errorResultContainsProblemDetails() {
        ResolveResult result = resolver.resolve("did:webvh:abc:example.com",
                DidLog.empty(), defaultOptions());

        assertThat(result.metadata().problemDetails()).isNotNull();
        assertThat(result.metadata().problemDetails().type()).isEqualTo("about:blank");
        assertThat(result.metadata().problemDetails().detail()).isNotBlank();
    }
    }

    // -------------------------------------------------------------------------
    // Witness epoch transitions
    // -------------------------------------------------------------------------

    /**
     * Tests the epoch-based witness verification model (spec §8.2).
     *
     * <p>When the witness configuration changes mid-log, every distinct config epoch must
     * independently satisfy its own threshold. A proof from the <em>new</em> witness set
     * is not sufficient to cover entries that were governed by the <em>old</em> witness set.
     *
     * <p>The log built by {@link #buildThreeEntryLog()} has this shape:
     * <pre>
     * Entry 1 (v1): parameters.witness = {A, threshold:1}
     *               active config for v1 = A  (genesis uses its own config)
     *
     * Entry 2 (v2): parameters.witness = {B, threshold:1}
     *               active config for v2 = A  (B only becomes active AFTER this entry is published)
     *
     * Entry 3 (v3): parameters.witness = {}   (witnesses turned off)
     *               active config for v3 = B  (B became active after v2 was published)
     * </pre>
     *
     * <p>This produces two epochs:
     * <ul>
     *   <li>Epoch A: {@code lastVersion=2}. A witness from config A must have signed v&ge;2.</li>
     *   <li>Epoch B: {@code lastVersion=3}. A witness from config B must have signed v&ge;3.</li>
     * </ul>
     *
     * <p>Both epochs must pass independently. B signing v3 does NOT cover epoch A,
     * because B is not listed in config A.
     */
    @Nested
    class WitnessEpochTransition {

        private Ed25519TestFixture witnessA;
        private Ed25519TestFixture witnessB;

        @BeforeEach
        void setUpWitnesses() {
            witnessA = Ed25519TestFixture.generate();
            witnessB = Ed25519TestFixture.generate();
        }

        private WitnessParameter configA() {
            return new WitnessParameter(1, List.of(
                    new WitnessParameter.WitnessEntry("did:key:" + witnessA.publicKeyMultibase())));
        }

        private WitnessParameter configB() {
            return new WitnessParameter(1, List.of(
                    new WitnessParameter.WitnessEntry("did:key:" + witnessB.publicKeyMultibase())));
        }

        /**
         * Builds the three-entry log described in the class-level javadoc.
         *
         * @return log whose entries are [v1: witness=A, v2: witness=B, v3: witness=off]
         */
        private DidLog buildThreeEntryLog() {
            // v1: genesis, witness config = A
            CreateResult created = CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .initialDocument(initialDocument())
                            .updateKeys(List.of(fixture.publicKeyMultibase()))
                            .signer(fixture.signer())
                            .witness(configA())
                            .build());

            String scid = scidFrom(created.log());

            // v2: switch witness config to B (A is still active for this entry)
            ObjectNode doc2 = MAPPER.createObjectNode();
            doc2.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc2.put("id", "did:webvh:" + scid + ":" + DOMAIN);
            UpdateResult updated2 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(doc2)
                            .signer(fixture.signer())
                            .witness(configB())
                            .build());

            // v3: turn witnesses off (B is still active for this entry)
            ObjectNode doc3 = MAPPER.createObjectNode();
            doc3.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc3.put("id", "did:webvh:" + scid + ":" + DOMAIN);
            UpdateResult updated3 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(updated2.log())
                            .updatedDocument(doc3)
                            .signer(fixture.signer())
                            .witness(new WitnessParameter(null, null))
                            .build());

            return updated3.log();
        }

        @Test
        void succeedsWhenBothEpochsAreSatisfied() {
            DidLog log = buildThreeEntryLog();
            String versionId2 = log.entries().get(1).versionId(); // v2
            String versionId3 = log.entries().get(2).versionId(); // v3

            // Epoch A (lastVersion=2): A signs v2 → covers v2 ≥ 2 ✓
            // Epoch B (lastVersion=3): B signs v3 → covers v3 ≥ 3 ✓
            WitnessProofCollection proofs = new WitnessProofCollection(List.of(
                    proofFrom(witnessA, versionId2),
                    proofFrom(witnessB, versionId3)));

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(proofs)
                    .build());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.document()).isNotNull();
        }

        @Test
        void failsWhenOnlyNewWitnessSignsButOldEpochIsUnsatisfied() {
            // Security regression test: the original bug allowed an attacker who controlled
            // witness B to turn off witnesses (v3) and have B sign v3. The old single-frontier
            // check would pass because frontier=3 >= lastWitnessedVersion=3. The epoch-based
            // check correctly rejects this because epoch A (lastVersion=2) has no proof from A.
            DidLog log = buildThreeEntryLog();
            String versionId3 = log.entries().get(2).versionId();

            WitnessProofCollection proofs = new WitnessProofCollection(List.of(
                    proofFrom(witnessB, versionId3)));

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(proofs)
                    .build());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void failsWhenOnlyOldEpochSatisfiedButNewEpochMissing() {
            // A signs v2 (epoch A satisfied) but B never signs anything.
            // Epoch B (lastVersion=3) is not satisfied → must fail.
            DidLog log = buildThreeEntryLog();
            String versionId2 = log.entries().get(1).versionId();

            WitnessProofCollection proofs = new WitnessProofCollection(List.of(
                    proofFrom(witnessA, versionId2)));

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(proofs)
                    .build());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void failsWhenNoProofsProvided() {
            DidLog log = buildThreeEntryLog();

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .build());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void historicalVersion1_requiresNoProofBecauseNoEpochApplies() {
            // The full log has epoch A (lastVersion=2) and epoch B (lastVersion=3).
            // When resolving v1 (atVersion=1), both epochs have lastVersion > 1 and are
            // skipped entirely. No epochs apply, so no proofs are required.
            DidLog log = buildThreeEntryLog();

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionNumber(1)
                    .build());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.metadata().versionNumber()).isEqualTo(1);
        }

        @Test
        void historicalVersion2_succeedsWhenEpochASatisfied() {
            // Resolving v2 (atVersion=2):
            //   Epoch A: lastVersion=2 ≤ 2 → checked. A must have signed v≥2.
            //   Epoch B: lastVersion=3 > 2 → skipped.
            DidLog log = buildThreeEntryLog();
            String versionId2 = log.entries().get(1).versionId();

            WitnessProofCollection proofs = new WitnessProofCollection(List.of(
                    proofFrom(witnessA, versionId2)));

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(proofs)
                    .versionNumber(2)
                    .build());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.metadata().versionNumber()).isEqualTo(2);
        }

        @Test
        void historicalVersion2_failsWhenEpochAProofMissing() {
            // Resolving v2 (atVersion=2): epoch A (lastVersion=2) is checked but no proofs given.
            DidLog log = buildThreeEntryLog();

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionNumber(2)
                    .build());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }
    }

    // -------------------------------------------------------------------------
    // Witness activation from empty
    // -------------------------------------------------------------------------

    /**
     * Tests the spec rule that when witnesses are activated from an empty state
     * ({@code {}} → non-empty), the change is <em>immediately active</em> — the
     * same log entry that introduces the witnesses must itself be witnessed.
     *
     * <p>Log shape:
     * <pre>
     * Entry 1 (v1): parameters.witness = {}   (no witnesses)
     * Entry 2 (v2): parameters.witness = {W, threshold:1}
     *               active config for v2 = W  (activation from empty is immediate)
     * </pre>
     *
     * <p>This produces one epoch:
     * <ul>
     *   <li>Epoch W: {@code lastVersion=2}. Witness W must have signed v≥2.</li>
     * </ul>
     */
    @Nested
    class WitnessActivationFromEmpty {

        private Ed25519TestFixture witnessFixture;

        @BeforeEach
        void setUpWitness() {
            witnessFixture = Ed25519TestFixture.generate();
        }

        private WitnessParameter witnessConfig() {
            return new WitnessParameter(1, List.of(
                    new WitnessParameter.WitnessEntry("did:key:" + witnessFixture.publicKeyMultibase())));
        }

        /**
         * Builds a two-entry log: v1 has no witnesses, v2 activates witnesses.
         */
        private DidLog buildTwoEntryLogWithActivation() {
            // v1: genesis, no witnesses
            CreateResult created = CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .initialDocument(initialDocument())
                            .updateKeys(List.of(fixture.publicKeyMultibase()))
                            .signer(fixture.signer())
                            .build());

            String scid = scidFrom(created.log());

            // v2: activate witnesses (config becomes active immediately for this entry)
            ObjectNode doc2 = MAPPER.createObjectNode();
            doc2.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc2.put("id", "did:webvh:" + scid + ":" + DOMAIN);
            UpdateResult updated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(doc2)
                            .signer(fixture.signer())
                            .witness(witnessConfig())
                            .build());

            return updated.log();
        }

        @Test
        void succeedsWhenWitnessProofProvidedForActivationEntry() {
            DidLog log = buildTwoEntryLogWithActivation();
            String versionId2 = log.entries().get(1).versionId(); // v2

            // Epoch W (lastVersion=2): W signs v2 → covers v2 ≥ 2 ✓
            WitnessProofCollection proofs = new WitnessProofCollection(List.of(
                    proofFrom(witnessFixture, versionId2)));

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(proofs)
                    .build());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.document()).isNotNull();
        }

        @Test
        void failsWhenNoWitnessProofProvidedForActivationEntry() {
            DidLog log = buildTwoEntryLogWithActivation();

            // No proofs given — epoch W (lastVersion=2) is unsatisfied → must fail
            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .build());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void historicalVersion1_requiresNoProofBecauseNoEpochApplies() {
            DidLog log = buildTwoEntryLogWithActivation();

            // Epoch W has lastVersion=2. When resolving v1 (atVersion=1),
            // lastVersion > atVersion so the epoch is skipped.
            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionNumber(1)
                    .build());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.metadata().versionNumber()).isEqualTo(1);
        }

        @Test
        void historicalVersion2_succeedsWhenProofProvided() {
            DidLog log = buildTwoEntryLogWithActivation();
            String versionId2 = log.entries().get(1).versionId();

            WitnessProofCollection proofs = new WitnessProofCollection(List.of(
                    proofFrom(witnessFixture, versionId2)));

            ResolveResult result = resolver.resolve(didFrom(log), log, ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(proofs)
                    .versionNumber(2)
                    .build());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.metadata().versionNumber()).isEqualTo(2);
        }
    }

    // -------------------------------------------------------------------------
    // Witness deactivation
    // -------------------------------------------------------------------------

    @Nested
    class WitnessDeactivation {

        private Ed25519TestFixture witnessFixture;

        @BeforeEach
        void setUpWitness() {
            witnessFixture = Ed25519TestFixture.generate();
        }

        private WitnessParameter witnessConfig() {
            return new WitnessParameter(1, List.of(
                    new WitnessParameter.WitnessEntry("did:key:" + witnessFixture.publicKeyMultibase())));
        }

        @Test
        void resolve_withWitnessDeactivation_succeedsWhenProofProvided() {
            CreateResult created = createDidWithWitness();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateWithWitnessOff(created.log(), scid);

            // Epoch A (lastVersion=2): witness signs v2, covering v2 ≥ 2 ✓
            String versionId2 = updated.log().latest().versionId();
            WitnessProofCollection witnessProofs = new WitnessProofCollection(List.of(
                    proofFrom(witnessFixture, versionId2)));

            ResolveResult result = resolver.resolve(created.did(), updated.log(), ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(witnessProofs)
                    .build());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.document()).isNotNull();
        }

        @Test
        void resolve_withWitnessDeactivation_failsWhenProofMissing() {
            CreateResult created = createDidWithWitness();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateWithWitnessOff(created.log(), scid);

            ResolveResult result = resolver.resolve(created.did(), updated.log(), ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .build());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void resolve_historicalVersionBeforeDeactivation_succeedsWhenProofProvided() {
            CreateResult created = createDidWithWitness();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateWithWitnessOff(created.log(), scid);

            // Provide a proof for v2 so the epoch is satisfied, then resolve the earlier v1.
            String versionId2 = updated.log().latest().versionId();
            WitnessProofCollection witnessProofs = new WitnessProofCollection(List.of(
                    proofFrom(witnessFixture, versionId2)));

            ResolveResult result = resolver.resolve(created.did(), updated.log(), ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(witnessProofs)
                    .versionNumber(1)
                    .build());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.document()).isNotNull();
        }

        private CreateResult createDidWithWitness() {
            return CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .initialDocument(initialDocument())
                            .updateKeys(List.of(fixture.publicKeyMultibase()))
                            .signer(fixture.signer())
                            .witness(witnessConfig())
                            .build());
        }

        private UpdateResult updateWithWitnessOff(DidLog log, String scid) {
            ObjectNode doc = MAPPER.createObjectNode();
            doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc.put("id", "did:webvh:" + scid + ":" + DOMAIN);
            doc.put("updated", "true");
            return UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(log)
                            .updatedDocument(doc)
                            .signer(fixture.signer())
                            .witness(new WitnessParameter(null, null))
                            .build());
        }
    }
}
