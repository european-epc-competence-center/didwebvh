package io.didwebvh.operation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;
import io.didwebvh.api.DeactivateOptions;
import io.didwebvh.api.DeactivateResult;
import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;
import io.didwebvh.crypto.Signer;
import io.didwebvh.log.LogValidator;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DeactivateOperationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DOMAIN = "example.com";

    private Ed25519TestFixture fixtureA;
    private Signer signerA;

    @BeforeEach
    void setUp() {
        fixtureA = Ed25519TestFixture.generate();
        signerA = fixtureA.signer();
    }

    private ObjectNode buildDocument(String scid) {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
        doc.put("id", "did:webvh:" + scid + ":" + DOMAIN);
        return doc;
    }

    private CreateResult createDid() {
        return createDid(List.of(), null);
    }

    private CreateResult createDid(List<String> nextKeyHashes, Ed25519TestFixture overrideSigner) {
        Ed25519TestFixture fixture = overrideSigner != null ? overrideSigner : fixtureA;
        ObjectNode doc = MAPPER.createObjectNode();
        doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
        doc.put("id", "did:webvh:{SCID}:" + DOMAIN);

        CreateOptions.Builder builder = CreateOptions.builder()
                .domain(DOMAIN)
                .initialDocument(doc)
                .updateKeys(List.of(fixture.publicKeyMultibase()))
                .signer(fixture.signer());

        if (!nextKeyHashes.isEmpty()) {
            builder.nextKeyHashes(nextKeyHashes);
        }
        return CreateOperation.create(builder.build());
    }

    private static String keyHash(String multikey) {
        return io.didwebvh.crypto.Multiformats.sha256Multihash(
                multikey.getBytes(StandardCharsets.UTF_8));
    }

    private void assertLogPassesValidation(DidLog log) {
        LogValidator validator = new LogValidator(Ed25519TestFixture.verifier());
        int valid = validator.validate(log);
        assertThat(valid).isEqualTo(log.size());
    }

    @Nested
    class HappyPath {

        @Test
        void deactivate_appendsEntryWithDeactivatedAndEmptyUpdateKeys() {
            CreateResult created = createDid();

            DeactivateResult result = DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(created.log())
                            .signer(signerA)
                            .build());

            assertThat(result.log().size()).isEqualTo(2);
            DidLogEntry latest = result.log().latest();
            assertThat(latest.parameters().deactivated()).isTrue();
            assertThat(latest.parameters().updateKeys()).isEmpty();
            assertThat(result.metadata().deactivated()).isTrue();
            assertThat(latest.state()).isEqualTo(created.log().latest().state());
            assertLogPassesValidation(result.log());
        }

        @Test
        void deactivate_afterUpdate_validates() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult updated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .signer(signerA)
                            .build());

            DeactivateResult result = DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(updated.log())
                            .signer(signerA)
                            .build());

            assertThat(result.log().size()).isEqualTo(3);
            assertThat(result.log().latest().parameters().deactivated()).isTrue();
            assertLogPassesValidation(result.log());
        }
    }

    @Nested
    class Rejections {

        @Test
        void deactivate_rejectsAlreadyDeactivated() {
            CreateResult created = createDid();

            DeactivateResult once = DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(created.log())
                            .signer(signerA)
                            .build());

            assertThatThrownBy(() -> DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(once.log())
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("already deactivated");
        }

        @Test
        void deactivate_rejectsUnauthorizedSigner() {
            CreateResult created = createDid();
            Ed25519TestFixture stranger = Ed25519TestFixture.generate();

            assertThatThrownBy(() -> DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(created.log())
                            .signer(stranger.signer())
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not in the active 'updateKeys'");
        }

        @Test
        void deactivate_rejectsWhenPreRotationStillActive() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());
            CreateResult created = createDid(List.of(hashB), null);

            assertThatThrownBy(() -> DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(created.log())
                            .signer(fixtureB.signer())
                            .build()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pre-rotation");
        }
    }

    @Nested
    class AfterPreRotationCleared {

        @Test
        void deactivate_afterClearingPreRotation_validates() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());
            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            UpdateResult cleared = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of())
                            .signer(fixtureB.signer())
                            .build());

            DeactivateResult result = DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(cleared.log())
                            .signer(fixtureB.signer())
                            .build());

            assertThat(result.log().size()).isEqualTo(3);
            assertThat(result.log().latest().parameters().deactivated()).isTrue();
            assertLogPassesValidation(result.log());
        }
    }
}
