package io.didwebvh.operation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.DidWebVhConstants;
import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;
import io.didwebvh.crypto.*;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.WitnessParameter;
import io.didwebvh.model.proof.DataIntegrityProof;
import io.didwebvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CreateOperationTest {

    Logger log = LoggerFactory.getLogger(CreateOperationTest.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DOMAIN = "example.com";

    private Signer signer;
    private Verifier verifier;
    private String publicKeyMultibase;

    @BeforeEach
    void setUp() {
        Ed25519TestFixture fixture = Ed25519TestFixture.generate();
        signer = fixture.signer();
        verifier = fixture.verifier();
        publicKeyMultibase = fixture.publicKeyMultibase();
    }

    private ObjectNode buildInitialDocument() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
        doc.put("id", "did:webvh:{SCID}:" + DOMAIN);
        return doc;
    }

    private CreateOptions.Builder defaultOptions() {
        return CreateOptions.builder()
                .domain(DOMAIN)
                .initialDocument(buildInitialDocument())
                .updateKeys(List.of(publicKeyMultibase))
                .signer(signer);
    }

    // -------------------------------------------------------------------------
    // Basic create — structure and format
    // -------------------------------------------------------------------------

    @Nested
    class BasicCreate {

        @Test
        void create_logContainsExactlyOneEntry() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            assertThat(result.log().entries()).hasSize(1);
        }

        @Test
        void create_didFormatIsCorrect() {
            CreateResult result = CreateOperation.create(defaultOptions().build());

            assertThat(result.did()).startsWith("did:webvh:");
            assertThat(result.did()).endsWith(":" + DOMAIN);

            String[] parts = result.did().split(":");
            assertThat(parts).hasSize(4); // did : webvh : SCID : domain
            assertThat(parts[0]).isEqualTo("did");
            assertThat(parts[1]).isEqualTo("webvh");
            assertThat(parts[3]).isEqualTo(DOMAIN);
        }

        @Test
        void create_withPathDomain() {
            String domainWithPath = "example.com:dids:issuer";
            ObjectNode doc = MAPPER.createObjectNode();
            doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc.put("id", "did:webvh:{SCID}:" + domainWithPath);

            CreateResult result = CreateOperation.create(
                    CreateOptions.builder()
                            .domain(domainWithPath)
                            .initialDocument(doc)
                            .updateKeys(List.of(publicKeyMultibase))
                            .signer(signer)
                            .build());

            assertThat(result.did()).endsWith(":" + domainWithPath);
        }
    }

    // -------------------------------------------------------------------------
    // SCID format and correctness
    // -------------------------------------------------------------------------

    @Nested
    class ScidTests {

        @Test
        void scid_startsWithQm_notZ() {
            CreateResult result = CreateOperation.create(defaultOptions().build());

            String scid = result.metadata().scid();
            assertThat(scid)
                    .as("SCID should be raw base58btc (no 'z' multibase prefix)")
                    .startsWith("Qm")
                    .doesNotStartWith("z");
        }

        @Test
        void scid_hasCorrectLength() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            // SHA-256 multihash in base58btc is 46 characters (per ABNF: 46(base58-alphabet))
            assertThat(result.metadata().scid()).hasSize(46);
        }

        @Test
        void scid_appearsInDid() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            String scid = result.metadata().scid();

            assertThat(result.did()).isEqualTo("did:webvh:" + scid + ":" + DOMAIN);
        }

        @Test
        void scid_appearsInParameters() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();
            String scid = result.metadata().scid();

            assertThat(entry.parameters().scid()).isEqualTo(scid);
        }

        @Test
        void scid_canBeVerifiedByReproducingComputation() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();
            String scid = result.metadata().scid();

            // Reproduce SCID verification per spec §5.3.2:
            // 1. Remove proof
            // 2. Replace versionId with "{SCID}"
            // 3. Text-replace actual SCID with {SCID}
            // 4. JCS → SHA-256 → multihash → base58btc
            DidLogEntry withoutProof = entry.withoutProof();
            DidLogEntry withPlaceholderVersionId = new DidLogEntry(
                    DidWebVhConstants.SCID_PLACEHOLDER,
                    withoutProof.versionTime(),
                    withoutProof.parameters(),
                    withoutProof.state(),
                    null);

            String json;
            try {
                json = MAPPER.writeValueAsString(withPlaceholderVersionId);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            json = json.replace(scid, DidWebVhConstants.SCID_PLACEHOLDER);

            DidLogEntry preliminary;
            try {
                preliminary = MAPPER.readValue(json, DidLogEntry.class);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            JsonNode preliminaryJson = MAPPER.valueToTree(preliminary);
            String recomputedScid = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(preliminaryJson));

            assertThat(recomputedScid).isEqualTo(scid);
        }
    }

    // -------------------------------------------------------------------------
    // Entry hash / versionId
    // -------------------------------------------------------------------------

    @Nested
    class EntryHashTests {

        @Test
        void versionId_format() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();

            assertThat(entry.versionId()).matches("1-Qm[1-9A-HJ-NP-Za-km-z]+");
            assertThat(entry.versionNumber()).isEqualTo(1);
        }

        @Test
        void entryHash_startsWithQm_notZ() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();

            assertThat(entry.entryHash())
                    .as("Entry hash should be raw base58btc")
                    .startsWith("Qm")
                    .doesNotStartWith("z");
        }

        @Test
        void entryHash_hasCorrectLength() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();
            assertThat(entry.entryHash()).hasSize(46);
        }

        @Test
        void entryHash_canBeVerifiedByReproducingComputation() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();
            String scid = result.metadata().scid();
            
            // For the first entry, the predecessor versionId is the SCID itself
            DidLogEntry hashInput = new DidLogEntry(
                    scid,
                    entry.versionTime(),
                    entry.parameters(),
                    entry.state(),
                    null);

            JsonNode hashInputJson = MAPPER.valueToTree(hashInput);
            String recomputedHash = Multiformats.sha256Multihash(JcsCanonicalizer.canonicalize(hashInputJson));

            assertThat(recomputedHash).isEqualTo(entry.entryHash());
        }
    }

    // -------------------------------------------------------------------------
    // Data Integrity proof
    // -------------------------------------------------------------------------

    @Nested
    class ProofTests {

        @Test
        void proof_hasCorrectFields() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DataIntegrityProof proof = result.log().first().proof().get(0);

            assertThat(proof.type()).isEqualTo("DataIntegrityProof");
            assertThat(proof.cryptosuite()).isEqualTo("eddsa-jcs-2022");
            assertThat(proof.proofPurpose()).isEqualTo("assertionMethod");
            assertThat(proof.verificationMethod()).isEqualTo(publicKeyMultibase);
            assertThat(proof.proofValue()).startsWith("z");
        }

        @Test
        void proof_createdIsRecentIso8601() {
            Instant before = Instant.now().minusSeconds(5);
            CreateResult result = CreateOperation.create(defaultOptions().build());
            Instant after = Instant.now().plusSeconds(1);

            DataIntegrityProof proof = result.log().first().proof().get(0);
            Instant created = Instant.parse(proof.created());
            assertThat(created).isBetween(before, after);
        }

        @Test
        void proof_verificationSucceeds() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();
            DataIntegrityProof proof = entry.proof().get(0);

            JsonNode document = MAPPER.valueToTree(entry.withoutProof());
            boolean valid = DataIntegrity.verifyProof(document, proof, verifier);
            assertThat(valid).isTrue();
        }

        @Test
        void proof_failsWithTamperedDocument() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();
            log.info("Entry: {}", entry);
            DataIntegrityProof proof = entry.proof().get(0);

            ObjectNode tamperedDoc = (ObjectNode) MAPPER.valueToTree(entry.withoutProof());
            tamperedDoc.put("versionTime", "2099-01-01T00:00:00Z");

            log.info("Tampered Document: {}", tamperedDoc);
            assertThatThrownBy(() -> DataIntegrity.verifyProof(tamperedDoc, proof, verifier))
                    .isInstanceOf(LogValidationException.class);
        }
    }

    // -------------------------------------------------------------------------
    // Parameters
    // -------------------------------------------------------------------------

    @Nested
    class ParameterTests {

        @Test
        void parameters_methodIsV1() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            Parameters params = result.log().first().parameters();

            assertThat(params.method()).isEqualTo("did:webvh:1.0");
        }

        @Test
        void parameters_updateKeysContainsSignerKey() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            Parameters params = result.log().first().parameters();

            assertThat(params.updateKeys()).containsExactly(publicKeyMultibase);
        }

        @Test
        void parameters_portableDefaultIsFalse() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            Parameters params = result.log().first().parameters();

            // When portable is false (default), it should be null (omitted from JSON)
            assertThat(params.portable()).isNull();
        }

        @Test
        void parameters_portableTrueWhenSet() {
            CreateResult result = CreateOperation.create(
                    defaultOptions().portable(true).build());
            Parameters params = result.log().first().parameters();

            assertThat(params.portable()).isTrue();
        }

        @Test
        void parameters_nextKeyHashesOmittedByDefault() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            Parameters params = result.log().first().parameters();

            assertThat(params.nextKeyHashes()).isNull();
        }

        @Test
        void parameters_nextKeyHashesSetWhenProvided() {
            String hash = Multiformats.sha256Multihash(
                    Multiformats.multibaseEncode(new byte[34]).getBytes());

            CreateResult result = CreateOperation.create(
                    defaultOptions().nextKeyHashes(List.of(hash)).build());
            Parameters params = result.log().first().parameters();

            assertThat(params.nextKeyHashes()).containsExactly(hash);
        }

        @Test
        void parameters_witnessSetWhenProvided() {
            WitnessParameter witness = new WitnessParameter(
                    2,
                    List.of(
                            new WitnessParameter.WitnessEntry("did:key:z6Mk1"),
                            new WitnessParameter.WitnessEntry("did:key:z6Mk2"),
                            new WitnessParameter.WitnessEntry("did:key:z6Mk3")));

            CreateResult result = CreateOperation.create(
                    defaultOptions().witness(witness).build());
            Parameters params = result.log().first().parameters();

            assertThat(params.witness()).isNotNull();
            assertThat(params.witness().threshold()).isEqualTo(2);
            assertThat(params.witness().witnesses()).hasSize(3);
        }
    }

    // -------------------------------------------------------------------------
    // State / Document
    // -------------------------------------------------------------------------

    @Nested
    class StateTests {

        @Test
        void state_scidPlaceholdersReplaced() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            String stateJson = result.log().first().state().toString();

            assertThat(stateJson).doesNotContain("{SCID}");
        }

        @Test
        void state_containsDidAsId() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            String docId = result.log().first().state().get("id").asText();

            assertThat(docId).isEqualTo(result.did());
        }

        @Test
        void state_preservesContext() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            JsonNode context = result.log().first().state().get("@context");

            assertThat(context).isNotNull();
            assertThat(context.isArray()).isTrue();
            assertThat(context.get(0).asText()).isEqualTo("https://www.w3.org/ns/did/v1");
        }

        @Test
        void state_preservesAdditionalFields() {
            ObjectNode doc = buildInitialDocument();
            ObjectNode verificationMethod = MAPPER.createObjectNode();
            verificationMethod.put("id", "did:webvh:{SCID}:" + DOMAIN + "#key-1");
            verificationMethod.put("type", "Multikey");
            verificationMethod.put("controller", "did:webvh:{SCID}:" + DOMAIN);
            verificationMethod.put("publicKeyMultibase", publicKeyMultibase);
            doc.putArray("verificationMethod").add(verificationMethod);
            doc.putArray("authentication").add("did:webvh:{SCID}:" + DOMAIN + "#key-1");

            CreateResult result = CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .initialDocument(doc)
                            .updateKeys(List.of(publicKeyMultibase))
                            .signer(signer)
                            .build());

            JsonNode state = result.log().first().state();
            String scid = result.metadata().scid();

            assertThat(state.has("verificationMethod")).isTrue();
            JsonNode vm = state.get("verificationMethod").get(0);
            assertThat(vm.get("id").asText()).contains(scid);
            assertThat(vm.get("id").asText()).doesNotContain("{SCID}");
            assertThat(vm.get("controller").asText()).isEqualTo(result.did());
        }
    }

    // -------------------------------------------------------------------------
    // versionTime
    // -------------------------------------------------------------------------

    @Nested
    class VersionTimeTests {

        @Test
        void versionTime_isRecentIso8601() {
            Instant before = Instant.now().minusSeconds(5);
            CreateResult result = CreateOperation.create(defaultOptions().build());
            Instant after = Instant.now().plusSeconds(1);

            DidLogEntry entry = result.log().first();
            Instant vt = Instant.parse(entry.versionTime());
            assertThat(vt).isBetween(before, after);
        }

        @Test
        void versionTime_truncatedToSeconds() {
            CreateResult result = CreateOperation.create(defaultOptions().build());
            DidLogEntry entry = result.log().first();

            // ISO 8601 truncated to seconds should end with 'Z' and have no fractional seconds
            assertThat(entry.versionTime()).endsWith("Z");
            assertThat(entry.versionTime()).doesNotContain(".");
        }
    }

    // -------------------------------------------------------------------------
    // Validation — missing required fields
    // -------------------------------------------------------------------------

    @Nested
    class ValidationTests {

        @Test
        void create_rejectsMissingDomain() {
            assertThatThrownBy(() -> CreateOperation.create(
                    CreateOptions.builder()
                            .initialDocument(buildInitialDocument())
                            .updateKeys(List.of(publicKeyMultibase))
                            .signer(signer)
                            .build()))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("domain");
        }

        @Test
        void create_rejectsMissingInitialDocument() {
            assertThatThrownBy(() -> CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .updateKeys(List.of(publicKeyMultibase))
                            .signer(signer)
                            .build()))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("initialDocument");
        }

        @Test
        void create_rejectsMissingUpdateKeys() {
            assertThatThrownBy(() -> CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .initialDocument(buildInitialDocument())
                            .signer(signer)
                            .build()))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("updateKeys");
        }

        @Test
        void create_rejectsEmptyUpdateKeys() {
            assertThatThrownBy(() -> CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .initialDocument(buildInitialDocument())
                            .updateKeys(List.of())
                            .signer(signer)
                            .build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("updateKeys");
        }

        @Test
        void create_rejectsMissingSigner() {
            assertThatThrownBy(() -> CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN)
                            .initialDocument(buildInitialDocument())
                            .updateKeys(List.of(publicKeyMultibase))
                            .build()))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("signer");
        }
    }

    // -------------------------------------------------------------------------
    // Multiple update keys
    // -------------------------------------------------------------------------

    @Nested
    class MultipleUpdateKeysTests {

        @Test
        void create_supportsMultipleUpdateKeys() {
            String key2 = Ed25519TestFixture.generate().publicKeyMultibase();

            CreateResult result = CreateOperation.create(
                    defaultOptions()
                            .updateKeys(List.of(publicKeyMultibase, key2))
                            .build());

            assertThat(result.log().first().parameters().updateKeys())
                    .containsExactly(publicKeyMultibase, key2);
        }
    }
}
