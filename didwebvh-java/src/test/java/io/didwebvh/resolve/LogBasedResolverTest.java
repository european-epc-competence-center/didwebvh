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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LogBasedResolverTest {

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

        private WitnessProofCollection.Entry createWitnessProof(String versionId) {
            String vmId = "did:key:" + witnessFixture.publicKeyMultibase() + "#" + witnessFixture.publicKeyMultibase();
            ObjectNode doc = MAPPER.createObjectNode();
            doc.put("versionId", versionId);
            DataIntegrityProof proof = DataIntegrity.createProof(doc, vmId, witnessFixture.signer());
            return new WitnessProofCollection.Entry(versionId, List.of(proof));
        }

        @Test
        void resolve_withWitnessDeactivation_succeedsWhenProofProvided() {
            CreateResult created = createDidWithWitness();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateWithWitnessOff(created.log(), scid);

            String versionId2 = updated.log().latest().versionId();
            WitnessProofCollection witnessProofs = new WitnessProofCollection(List.of(
                    createWitnessProof(versionId2)));

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(witnessProofs)
                    .build();

            ResolveResult result = resolver.resolve(created.did(), updated.log(), options);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.document()).isNotNull();
        }

        @Test
        void resolve_withWitnessDeactivation_failsWhenProofMissing() {
            CreateResult created = createDidWithWitness();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateWithWitnessOff(created.log(), scid);

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .build();

            ResolveResult result = resolver.resolve(created.did(), updated.log(), options);

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void resolve_historicalVersionBeforeDeactivation_succeedsWhenProofProvided() {
            CreateResult created = createDidWithWitness();
            String scid = scidFrom(created.log());
            UpdateResult updated = updateWithWitnessOff(created.log(), scid);

            String versionId2 = updated.log().latest().versionId();
            WitnessProofCollection witnessProofs = new WitnessProofCollection(List.of(
                    createWitnessProof(versionId2)));

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .witnessProofs(witnessProofs)
                    .versionNumber(1)
                    .build();

            ResolveResult result = resolver.resolve(created.did(), updated.log(), options);

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
