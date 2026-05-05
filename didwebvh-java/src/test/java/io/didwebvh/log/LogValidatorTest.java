package io.didwebvh.log;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;
import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;
import io.didwebvh.crypto.Verifier;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.proof.DataIntegrityProof;
import io.didwebvh.operation.CreateOperation;
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

/**
 * Tests for {@link LogValidator} using logs produced by {@link CreateOperation}
 * and {@link UpdateOperation} as golden inputs, plus tampered variants.
 */
class LogValidatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DOMAIN = "example.com";

    private Ed25519TestFixture fixture;
    private LogValidator validator;

    @BeforeEach
    void setUp() {
        fixture = Ed25519TestFixture.generate();
        validator = new LogValidator(Ed25519TestFixture.verifier());
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
        return UpdateOperation.update(
                UpdateOptions.builder()
                        .log(log)
                        .updatedDocument(doc)
                        .signer(fixture.signer())
                        .build());
    }

    private static DidLog replaceEntry(DidLog log, int index, DidLogEntry entry) {
        List<DidLogEntry> list = new ArrayList<>(log.entries());
        list.set(index, entry);
        return new DidLog(list);
    }

    @Nested
    class ValidateFullLog {

        @Test
        void emptyLog_throws() {
            assertThatThrownBy(() -> validator.validate(DidLog.empty()))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("empty");
        }

        @Test
        void genesisFromCreate_succeeds() {
            CreateResult created = createDid();
            int n = validator.validate(created.log());
            assertThat(n).isEqualTo(1);
        }

        @Test
        void createThenUpdate_succeeds() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            UpdateResult updated = updateDid(created.log(), scid);
            int n = validator.validate(updated.log());
            assertThat(n).isEqualTo(2);
        }

        @Test
        void multipleUpdates_succeeds() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            DidLog log = created.log();
            for (int i = 0; i < 5; i++) {
                log = updateDid(log, scid).log();
            }
            assertThat(validator.validate(log)).isEqualTo(log.size());
        }

        @Test
        void wrongVerifier_throwsOnProof() {
            CreateResult created = createDid();
            Verifier wrongVerifier = (sig, msg, key) -> false;
            assertThatThrownBy(() -> new LogValidator(wrongVerifier).validate(created.log()))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("Log entry 1");
        }
    }

    @Nested
    class TamperedEntries {

        @Test
        void entryHashMismatch_onTamperedState() {
            CreateResult created = createDid();
            DidLogEntry g = created.log().first();
            ObjectNode state = g.state().deepCopy();
            state.put("tampered", true);
            DidLogEntry bad = new DidLogEntry(
                    g.versionId(), g.versionTime(), g.parameters(), state, g.proof());
            DidLog badLog = new DidLog(List.of(bad));

            assertThatThrownBy(() -> validator.validate(badLog))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("Entry hash mismatch");
        }

        @Test
        void versionNumberMismatch() {
            CreateResult created = createDid();
            DidLogEntry g = created.log().first();
            String bogusHash = "Qm" + "1".repeat(44);
            DidLogEntry bad = new DidLogEntry(
                    "2-" + bogusHash,
                    g.versionTime(),
                    g.parameters(),
                    g.state(),
                    g.proof());
            DidLog badLog = new DidLog(List.of(bad));

            assertThatThrownBy(() -> validator.validate(badLog))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("Expected version number 1");
        }

        @Test
        void futureVersionTime_rejected() {
            CreateResult created = createDid();
            DidLogEntry g = created.log().first();
            DidLogEntry bad = new DidLogEntry(
                    g.versionId(),
                    "2099-01-01T00:00:00Z",
                    g.parameters(),
                    g.state(),
                    g.proof());
            DidLog badLog = new DidLog(List.of(bad));

            assertThatThrownBy(() -> validator.validate(badLog))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("future");
        }

        @Test
        void versionTimeBeforePrevious_rejected() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            UpdateResult updated = updateDid(created.log(), scid);
            DidLogEntry first = updated.log().first();
            DidLogEntry second = updated.log().latest();
            String tooEarly = Instant.parse(first.versionTime()).minusSeconds(3600).toString();

            DidLogEntry badSecond = new DidLogEntry(
                    second.versionId(),
                    tooEarly,
                    second.parameters(),
                    second.state(),
                    second.proof());
            DidLog badLog = replaceEntry(updated.log(), 1, badSecond);

            assertThatThrownBy(() -> validator.validate(badLog))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("before previous");
        }

        @Test
        void missingProof_rejected() {
            CreateResult created = createDid();
            DidLogEntry g = created.log().first();
            DidLogEntry noProof = new DidLogEntry(
                    g.versionId(), g.versionTime(), g.parameters(), g.state(), List.of());
            DidLog badLog = new DidLog(List.of(noProof));

            assertThatThrownBy(() -> validator.validate(badLog))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("proof");
        }

        @Test
        void missingParameters_rejected() {
            CreateResult created = createDid();
            DidLogEntry g = created.log().first();
            DidLogEntry bad = new DidLogEntry(
                    g.versionId(), g.versionTime(), null, g.state(), g.proof());
            DidLog badLog = new DidLog(List.of(bad));

            assertThatThrownBy(() -> validator.validate(badLog))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("parameters");
        }

        @Test
        void wrongVerificationMethod_rejected() {
            CreateResult created = createDid();
            DidLogEntry g = created.log().first();
            DataIntegrityProof p = g.proof().get(0);
            DataIntegrityProof tampered = new DataIntegrityProof(
                    p.type(),
                    p.cryptosuite(),
                    "did:key:z6MkhaXgBZDvotDkLPU7vEdbvdLxbfeRVFGvekf3gsTuJfVX",
                    p.created(),
                    p.proofPurpose(),
                    p.proofValue(),
                    p.id());
            DidLogEntry bad = new DidLogEntry(
                    g.versionId(), g.versionTime(), g.parameters(), g.state(), List.of(tampered));
            DidLog badLog = new DidLog(List.of(bad));

            assertThatThrownBy(() -> validator.validate(badLog))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("updateKeys");
        }

        @Test
        void secondEntryFails_wrappedMessageMentionsIndex() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            UpdateResult updated = updateDid(created.log(), scid);
            DidLogEntry second = updated.log().latest();
            ObjectNode tamperedState = (ObjectNode) second.state().deepCopy();
            tamperedState.put("x", 1);
            DidLogEntry tampered = new DidLogEntry(
                    second.versionId(),
                    second.versionTime(),
                    second.parameters(),
                    tamperedState,
                    second.proof());
            DidLog badLog = replaceEntry(updated.log(), 1, tampered);

            assertThatThrownBy(() -> validator.validate(badLog))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("Log entry 2");
        }
    }

    // -------------------------------------------------------------------------
    // Portability — per-entry document id change validation
    // -------------------------------------------------------------------------

    @Nested
    class Portability {

        /**
         * Non-portable DIDs may NOT change their document "id" across entries.
         * If the controller tries to move a non-portable DID to a new domain,
         * the per-entry portability check must reject the log.
         */
        @Test
        void nonPortableDid_documentIdChange_rejected() {
            // 1. Create a standard (non-portable) DID at example.com
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            // 2. Build an update whose document id points to a new domain
            ObjectNode movedDoc = MAPPER.createObjectNode();
            movedDoc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            movedDoc.put("id", "did:webvh:" + scid + ":newdomain.com");

            // 3. Append the move entry (UpdateOperation does not enforce portability)
            UpdateResult moved = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(movedDoc)
                            .signer(fixture.signer())
                            .build());

            // 4. Validation must reject because portable was false in entry 1
            assertThatThrownBy(() -> validator.validate(moved.log()))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("portable");
        }

        /**
         * Portable DIDs MAY change their document "id" across entries.
         * The per-entry check should accept the move because genesis set
         * portable=true.
         */
        @Test
        void portableDid_documentIdChange_accepted() {
            // 1. Create a portable DID at example.com
            CreateResult created = CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .initialDocument(initialDocument())
                            .updateKeys(List.of(fixture.publicKeyMultibase()))
                            .signer(fixture.signer())
                            .portable(true)
                            .build());
            String scid = created.metadata().scid();

            // 2. Build an update whose document id points to a new domain
            ObjectNode movedDoc = MAPPER.createObjectNode();
            movedDoc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            movedDoc.put("id", "did:webvh:" + scid + ":newdomain.com");

            // 3. Append the move entry
            UpdateResult moved = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(movedDoc)
                            .signer(fixture.signer())
                            .build());

            // 4. Validation must accept both entries
            int valid = validator.validate(moved.log());
            assertThat(valid).isEqualTo(2);
        }
    }

    @Nested
    class ValidateEntryApi {

        @Test
        void genesis_returnsEffectiveParameters() {
            CreateResult created = createDid();
            DidLogEntry g = created.log().first();
            Parameters effective = validator.validateEntry(g, null, null);
            assertThat(effective.scid()).isEqualTo(created.metadata().scid());
            assertThat(effective.updateKeys()).containsExactly(fixture.publicKeyMultibase());
        }

        @Test
        void secondEntry_chainsFromFirst() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            UpdateResult updated = updateDid(created.log(), scid);
            DidLogEntry first = updated.log().first();
            DidLogEntry second = updated.log().latest();

            Parameters afterFirst = validator.validateEntry(first, null, null);
            Parameters afterSecond = validator.validateEntry(second, first, afterFirst);
            assertThat(afterSecond.scid()).isNull();
            assertThat(afterSecond.updateKeys()).containsExactly(fixture.publicKeyMultibase());
        }
    }
}
