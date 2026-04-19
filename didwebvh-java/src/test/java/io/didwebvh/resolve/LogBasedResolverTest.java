package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.*;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.operation.CreateOperation;
import io.didwebvh.operation.DeactivateOperation;
import io.didwebvh.operation.UpdateOperation;
import io.didwebvh.support.Ed25519TestFixture;
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
        void multipleFilters_throwsIllegalArgument() {
            CreateResult created = createDid();

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionId("1-abc")
                    .versionNumber(1)
                    .build();

            assertThatThrownBy(() -> resolver.resolve(created.did(), created.log(), options))
                    .isInstanceOf(IllegalArgumentException.class);
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
        void nullVerifier_throwsNullPointer() {
            CreateResult created = createDid();
            ResolveOptions options = ResolveOptions.builder().build();

            assertThatThrownBy(() -> resolver.resolve(created.did(), created.log(), options))
                    .isInstanceOf(NullPointerException.class);
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
}
