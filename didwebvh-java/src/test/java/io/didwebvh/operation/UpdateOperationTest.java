package io.didwebvh.operation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;
import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;
import io.didwebvh.crypto.DataIntegrity;
import io.didwebvh.crypto.JcsCanonicalizer;
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import io.didwebvh.log.LogValidator;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.proof.DataIntegrityProof;
import io.didwebvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UpdateOperationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DOMAIN = "example.com";

    private Ed25519TestFixture fixtureA;
    private Signer signerA;
    private String keyA;

    @BeforeEach
    void setUp() {
        fixtureA = Ed25519TestFixture.generate();
        signerA = fixtureA.signer();
        keyA = fixtureA.publicKeyMultibase();
    }

    // -- Helpers ---------------------------------------------------------------

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
        return Multiformats.sha256Multihash(multikey.getBytes(StandardCharsets.UTF_8));
    }

    private UpdateOptions.Builder defaultUpdateOptions(DidLog log, String scid) {
        return UpdateOptions.builder()
                .log(log)
                .updatedDocument(buildDocument(scid))
                .signer(signerA);
    }

    private void assertLogPassesValidation(DidLog log) {
        LogValidator validator = new LogValidator(Ed25519TestFixture.verifier());
        int valid = validator.validate(log);
        assertThat(valid).isEqualTo(log.size());
    }

    // =========================================================================
    // Basic update — structure and format
    // =========================================================================

    @Nested
    class BasicUpdate {

        @Test
        void update_appendsOneEntry() {
            CreateResult created = createDid();
            
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());        
            assertThat(result.log().size()).isEqualTo(2);
        }

        @Test
        void update_versionNumberIncrements() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            DidLogEntry newEntry = result.log().latest();
            assertThat(newEntry.versionNumber()).isEqualTo(2);
        }

        @Test
        void update_versionIdFormat() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            DidLogEntry newEntry = result.log().latest();
            assertThat(newEntry.versionId()).matches("2-Qm[1-9A-HJ-NP-Za-km-z]+");
            assertThat(newEntry.entryHash()).hasSize(46);
        }

        @Test
        void update_versionTimeIsRecent() {
            Instant before = Instant.now().minusSeconds(5);
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            Instant vt = Instant.parse(result.log().latest().versionTime());
            assertThat(vt).isAfterOrEqualTo(before);
            assertThat(vt).isBeforeOrEqualTo(Instant.now().plusSeconds(1));
        }

        @Test
        void update_stateContainsNewDocument() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            ObjectNode newDoc = buildDocument(scid);
            newDoc.put("customField", "customValue");

            UpdateResult result = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(newDoc)
                            .signer(signerA)
                            .build());

            assertThat(result.document().get("customField").asText()).isEqualTo("customValue");
            assertThat(result.log().latest().state().get("customField").asText()).isEqualTo("customValue");
        }

        @Test
        void update_preservesGenesisEntry() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            DidLogEntry genesis = result.log().first();
            assertThat(genesis.versionNumber()).isEqualTo(1);
            assertThat(genesis.parameters().scid()).isEqualTo(scid);
        }

        @Test
        void update_resultPassesFullLogValidation() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            assertLogPassesValidation(result.log());
        }
    }

    // =========================================================================
    // Entry hash chain
    // =========================================================================

    @Nested
    class EntryHashChain {

        @Test
        void entryHash_canBeReproduced() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            DidLogEntry newEntry = result.log().latest();
            DidLogEntry previous = result.log().first();

            DidLogEntry forHashing = new DidLogEntry(
                    previous.versionId(),
                    newEntry.versionTime(),
                    newEntry.parameters(),
                    newEntry.state(),
                    null);

            JsonNode hashInput = MAPPER.valueToTree(forHashing);
            String recomputed = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(hashInput));
            assertThat(recomputed).isEqualTo(newEntry.entryHash());
        }

        @Test
        void multipleUpdates_chainCorrectly() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult update1 = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());
            UpdateResult update2 = UpdateOperation.update(
                    defaultUpdateOptions(update1.log(), scid).build());
            UpdateResult update3 = UpdateOperation.update(
                    defaultUpdateOptions(update2.log(), scid).build());

            assertThat(update3.log().size()).isEqualTo(4);
            assertThat(update3.log().latest().versionNumber()).isEqualTo(4);
            assertLogPassesValidation(update3.log());
        }
    }

    // =========================================================================
    // Data Integrity proof
    // =========================================================================

    @Nested
    class ProofTests {

        @Test
        void proof_hasCorrectFields() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            DataIntegrityProof proof = result.log().latest().proof().get(0);
            assertThat(proof.type()).isEqualTo("DataIntegrityProof");
            assertThat(proof.cryptosuite()).isEqualTo("eddsa-jcs-2022");
            assertThat(proof.proofPurpose()).isEqualTo("assertionMethod");
            assertThat(proof.verificationMethod()).isEqualTo("did:key:" + keyA + "#" + keyA);
            assertThat(proof.proofValue()).startsWith("z");
        }

        @Test
        void proof_verificationSucceeds() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            DidLogEntry entry = result.log().latest();
            DataIntegrityProof proof = entry.proof().get(0);
            JsonNode doc = MAPPER.valueToTree(entry.withoutProof());
            boolean valid = DataIntegrity.verifyProof(doc, proof, Ed25519TestFixture.verifier());
            assertThat(valid).isTrue();
        }
    }

    // =========================================================================
    // Parameter delta — only changed fields
    // =========================================================================

    @Nested
    class ParameterDelta {

        @Test
        void delta_isEmptyWhenNothingChanges() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            Parameters delta = result.log().latest().parameters();
            assertThat(delta.method()).isNull();
            assertThat(delta.scid()).isNull();
            assertThat(delta.updateKeys()).isNull();
            assertThat(delta.portable()).isNull();
        }

        @Test
        void delta_containsNewUpdateKeysWhenRotated() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();

            UpdateResult result = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .signer(signerA)
                            .build());

            Parameters delta = result.log().latest().parameters();
            assertThat(delta.updateKeys()).containsExactly(fixtureB.publicKeyMultibase());
            assertLogPassesValidation(result.log());
        }
    }

    // =========================================================================
    // Key rotation (without pre-rotation)
    // =========================================================================

    @Nested
    class KeyRotationWithoutPreRotation {

        @Test
        void rotation_newKeyUsedForNextUpdate() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();

            // Rotate from keyA to keyB (signed by keyA, the currently active key)
            UpdateResult rotated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .signer(signerA)
                            .build());

            // Next update must be signed by keyB
            UpdateResult afterRotation = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(rotated.log())
                            .updatedDocument(buildDocument(scid))
                            .signer(fixtureB.signer())
                            .build());

            assertThat(afterRotation.log().size()).isEqualTo(3);
            assertLogPassesValidation(afterRotation.log());
        }

        @Test
        void rotation_oldKeyRejectedAfterRotation() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();

            UpdateResult rotated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .signer(signerA)
                            .build());

            // Old key (keyA) is no longer authorized
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(rotated.log())
                            .updatedDocument(buildDocument(scid))
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not in the active 'updateKeys'");
        }
    }

    // =========================================================================
    // Pre-rotation
    // =========================================================================

    @Nested
    class PreRotation {

        @Test
        void activate_firstUpdateAfterActivationUsesPreRotationRules() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            // Create with pre-rotation: commit to keyB
            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            // Update: must provide keyB as updateKeys and sign with keyB
            Ed25519TestFixture fixtureC = Ed25519TestFixture.generate();
            String hashC = keyHash(fixtureC.publicKeyMultibase());

            UpdateResult result = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of(hashC))
                            .signer(fixtureB.signer())
                            .build());

            assertThat(result.log().size()).isEqualTo(2);
            assertLogPassesValidation(result.log());
        }

        @Test
        void activate_wrongKeyRejected() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            Ed25519TestFixture fixtureC = Ed25519TestFixture.generate();

            // Attempt to sign with keyA (not committed) — should fail
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of(keyHash(fixtureC.publicKeyMultibase())))
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("was not committed in the previous 'nextKeyHashes'");
        }

        @Test
        void activate_uncommittedUpdateKeyRejected() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            Ed25519TestFixture fixtureC = Ed25519TestFixture.generate();

            // Sign with keyB (committed) but try to put keyC in updateKeys (not committed)
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureC.publicKeyMultibase()))
                            .nextKeyHashes(List.of(keyHash(fixtureC.publicKeyMultibase())))
                            .signer(fixtureB.signer())
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("was not committed in the previous 'nextKeyHashes'");
        }

        @Test
        void multiEntry_preRotationChain() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            Ed25519TestFixture fixtureC = Ed25519TestFixture.generate();
            Ed25519TestFixture fixtureD = Ed25519TestFixture.generate();

            String hashB = keyHash(fixtureB.publicKeyMultibase());
            String hashC = keyHash(fixtureC.publicKeyMultibase());
            String hashD = keyHash(fixtureD.publicKeyMultibase());

            // Create: keyA, commit to keyB
            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            // Entry 2: reveal keyB, commit to keyC
            UpdateResult entry2 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of(hashC))
                            .signer(fixtureB.signer())
                            .build());

            // Entry 3: reveal keyC, commit to keyD
            UpdateResult entry3 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(entry2.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureC.publicKeyMultibase()))
                            .nextKeyHashes(List.of(hashD))
                            .signer(fixtureC.signer())
                            .build());

            assertThat(entry3.log().size()).isEqualTo(3);
            assertLogPassesValidation(entry3.log());
        }

        @Test
        void recommitSameKey_isAllowed() {
            // Spec: SHOULD destroy revealed key (not MUST), so same key is technically valid
            String hashA = keyHash(keyA);

            CreateResult created = createDid(List.of(hashA), null);
            String scid = created.metadata().scid();

            // Re-use keyA as the revealed key and commit to it again
            UpdateResult result = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(keyA))
                            .nextKeyHashes(List.of(hashA))
                            .signer(signerA)
                            .build());

            assertThat(result.log().size()).isEqualTo(2);
            assertLogPassesValidation(result.log());

            // Can do it again — the same key is continuously re-committed
            UpdateResult result2 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(result.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(keyA))
                            .nextKeyHashes(List.of(hashA))
                            .signer(signerA)
                            .build());

            assertThat(result2.log().size()).isEqualTo(3);
            assertLogPassesValidation(result2.log());
        }

        @Test
        void recommitSameKey_deltaStillContainsKeysWhenPreRotationActive() {
            String hashA = keyHash(keyA);

            CreateResult created = createDid(List.of(hashA), null);
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(keyA))
                            .nextKeyHashes(List.of(hashA))
                            .signer(signerA)
                            .build());

            // Even though keys didn't change, delta MUST include them when pre-rotation is active
            Parameters delta = result.log().latest().parameters();
            assertThat(delta.updateKeys()).containsExactly(keyA);
            assertThat(delta.nextKeyHashes()).containsExactly(hashA);
        }

        @Test
        void deactivatePreRotation_setsNextKeyHashesToEmpty() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            // Reveal keyB and deactivate pre-rotation (nextKeyHashes=[])
            UpdateResult deactivated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of())
                            .signer(fixtureB.signer())
                            .build());

            assertLogPassesValidation(deactivated.log());

            // Next entry: normal rules — signed by previous updateKeys (keyB)
            UpdateResult afterDeactivation = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(deactivated.log())
                            .updatedDocument(buildDocument(scid))
                            .signer(fixtureB.signer())
                            .build());

            assertThat(afterDeactivation.log().size()).isEqualTo(3);
            assertLogPassesValidation(afterDeactivation.log());
        }

        @Test
        void deactivatePreRotation_entryStillFollowsPreRotationRules() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            // The deactivation entry must still use a pre-committed key
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(keyA))
                            .nextKeyHashes(List.of())
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("was not committed");
        }

        @Test
        void extraHashesInNextKeyHashes_areIgnored() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            Ed25519TestFixture fixtureC = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());
            String hashC = keyHash(fixtureC.publicKeyMultibase());

            // Commit to both keyB and keyC, but only reveal keyB
            CreateResult created = createDid(List.of(hashB, hashC), null);
            String scid = created.metadata().scid();

            Ed25519TestFixture fixtureD = Ed25519TestFixture.generate();
            String hashD = keyHash(fixtureD.publicKeyMultibase());

            UpdateResult result = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of(hashD))
                            .signer(fixtureB.signer())
                            .build());

            assertThat(result.log().size()).isEqualTo(2);
            assertLogPassesValidation(result.log());
        }

        @Test
        void missingUpdateKeysWhenPreRotationActive_isRejected() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            // Don't provide updateKeys (try to inherit) — should fail
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .nextKeyHashes(List.of(keyHash(fixtureB.publicKeyMultibase())))
                            .signer(fixtureB.signer())
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void inheritedNextKeyHashes_areIncludedInDeltaWhenPreRotationActive() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            // Don't provide nextKeyHashes — previous value [hashB] should be inherited
            // and still be included in the delta (spec: MUST be present in every entry)
            UpdateResult result = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .signer(fixtureB.signer())
                            .build());

            Parameters delta = result.log().latest().parameters();
            assertThat(delta.nextKeyHashes()).containsExactly(hashB);
            assertThat(delta.updateKeys()).containsExactly(fixtureB.publicKeyMultibase());
            assertLogPassesValidation(result.log());
        }
    }

    // =========================================================================
    // Metadata
    // =========================================================================

    @Nested
    class MetadataTests {

        @Test
        void metadata_versionIdMatchesEntry() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            assertThat(result.metadata().versionId())
                    .isEqualTo(result.log().latest().versionId());
        }

        @Test
        void metadata_scidUnchanged() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            assertThat(result.metadata().scid()).isEqualTo(scid);
        }

        @Test
        void metadata_createdStaysGenesisTime() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            String genesisTime = created.metadata().created();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            assertThat(result.metadata().created()).isEqualTo(genesisTime);
        }

        @Test
        void metadata_updatedIsNewEntryTime() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            assertThat(result.metadata().updated())
                    .isEqualTo(result.log().latest().versionTime());
        }

        @Test
        void metadata_deactivatedIsFalse() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            UpdateResult result = UpdateOperation.update(
                    defaultUpdateOptions(created.log(), scid).build());

            assertThat(result.metadata().deactivated()).isFalse();
        }
    }

    // =========================================================================
    // Validation — rejection of bad inputs
    // =========================================================================

    @Nested
    class ValidationTests {

        @Test
        void rejectsMissingLog() {
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .updatedDocument(MAPPER.createObjectNode())
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("log");
        }

        @Test
        void rejectsEmptyLog() {
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(DidLog.empty())
                            .updatedDocument(MAPPER.createObjectNode())
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("log must not be empty");
        }

        @Test
        void rejectsMissingDocument() {
            CreateResult created = createDid();
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("updatedDocument");
        }

        @Test
        void rejectsMissingSigner() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .build()))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("signer");
        }

        @Test
        void rejectsUnauthorizedSigner() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();
            Ed25519TestFixture stranger = Ed25519TestFixture.generate();

            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .signer(stranger.signer())
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not in the active 'updateKeys'");
        }

        @Test
        void rejectsUpdateOnDeactivatedDid() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            // Manually build a log where the DID is deactivated
            DidLogEntry genesis = created.log().first();
            Parameters deactivatedDelta = new Parameters(
                    null, null, List.of(), null, null, true, null, null, null);
            DidLogEntry deactivationEntry = new DidLogEntry(
                    "2-fakehash1234567890123456789012345678901234",
                    Instant.now().toString(),
                    deactivatedDelta,
                    genesis.state(),
                    genesis.proof());

            DidLog deactivatedLog = created.log().append(deactivationEntry);

            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(deactivatedLog)
                            .updatedDocument(buildDocument(scid))
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("deactivated");
        }
    }

    // =========================================================================
    // Activating pre-rotation mid-lifecycle
    // =========================================================================

    @Nested
    class ActivatePreRotationLater {

        @Test
        void activatePreRotation_inSecondEntry() {
            // Create without pre-rotation
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            // Entry 2: activate pre-rotation by providing nextKeyHashes
            // Signed by keyA (normal rules — pre-rotation not yet active)
            UpdateResult activated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .nextKeyHashes(List.of(hashB))
                            .signer(signerA)
                            .build());

            assertLogPassesValidation(activated.log());

            // Entry 3: must follow pre-rotation rules — reveal keyB
            Ed25519TestFixture fixtureC = Ed25519TestFixture.generate();
            String hashC = keyHash(fixtureC.publicKeyMultibase());

            UpdateResult entry3 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(activated.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of(hashC))
                            .signer(fixtureB.signer())
                            .build());

            assertThat(entry3.log().size()).isEqualTo(3);
            assertLogPassesValidation(entry3.log());
        }

        @Test
        void activatePreRotation_oldKeyRejectedInNextEntry() {
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            String hashB = keyHash(fixtureB.publicKeyMultibase());

            // Activate pre-rotation
            UpdateResult activated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .nextKeyHashes(List.of(hashB))
                            .signer(signerA)
                            .build());

            // Entry 3: try to sign with keyA (old key, not committed) — should fail
            assertThatThrownBy(() -> UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(activated.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of(keyHash(fixtureB.publicKeyMultibase())))
                            .signer(signerA)
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("was not committed");
        }
    }

    // =========================================================================
    // Full lifecycle: create → multiple updates → pre-rotation → deactivate
    // =========================================================================

    @Nested
    class FullLifecycle {

        @Test
        void fullLifecycle_createUpdateRotateUpdateValidates() {
            // Create with keyA
            CreateResult created = createDid();
            String scid = created.metadata().scid();

            // Update 1: doc-only change with keyA
            ObjectNode doc1 = buildDocument(scid);
            doc1.put("service", "v1");
            UpdateResult update1 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(doc1)
                            .signer(signerA)
                            .build());

            // Update 2: rotate to keyB (signed by keyA)
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            UpdateResult rotated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(update1.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .signer(signerA)
                            .build());

            // Update 3: doc change (signed by keyB)
            ObjectNode doc3 = buildDocument(scid);
            doc3.put("service", "v3");
            UpdateResult update3 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(rotated.log())
                            .updatedDocument(doc3)
                            .signer(fixtureB.signer())
                            .build());

            assertThat(update3.log().size()).isEqualTo(4);
            assertLogPassesValidation(update3.log());
        }

        @Test
        void fullLifecycle_preRotationChainThenDeactivate() {
            Ed25519TestFixture fixtureB = Ed25519TestFixture.generate();
            Ed25519TestFixture fixtureC = Ed25519TestFixture.generate();

            String hashB = keyHash(fixtureB.publicKeyMultibase());
            String hashC = keyHash(fixtureC.publicKeyMultibase());

            // Create with pre-rotation: keyA, commit to keyB
            CreateResult created = createDid(List.of(hashB), null);
            String scid = created.metadata().scid();

            // Entry 2: reveal keyB, commit to keyC
            UpdateResult entry2 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureB.publicKeyMultibase()))
                            .nextKeyHashes(List.of(hashC))
                            .signer(fixtureB.signer())
                            .build());

            // Entry 3: reveal keyC, deactivate pre-rotation
            UpdateResult entry3 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(entry2.log())
                            .updatedDocument(buildDocument(scid))
                            .updateKeys(List.of(fixtureC.publicKeyMultibase()))
                            .nextKeyHashes(List.of())
                            .signer(fixtureC.signer())
                            .build());

            // Entry 4: normal rules (signed by keyC)
            UpdateResult entry4 = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(entry3.log())
                            .updatedDocument(buildDocument(scid))
                            .signer(fixtureC.signer())
                            .build());

            assertThat(entry4.log().size()).isEqualTo(4);
            assertLogPassesValidation(entry4.log());
        }
    }
}
