package io.didwebvh.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.proof.DataIntegrityProof;
import io.didwebvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DataIntegrity} verifying the {@code eddsa-jcs-2022} proof lifecycle.
 *
 * <p>Key material is freshly generated per test via {@link Ed25519TestFixture}.
 */
class DataIntegrityTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

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

    // -------------------------------------------------------------------------
    // Round-trip: create then verify succeeds
    // -------------------------------------------------------------------------

    @Test
    void roundTrip_createThenVerify_succeeds() {
        ObjectNode document = sampleDocument();
        
        DataIntegrityProof proof = DataIntegrity.createProof(document, publicKeyMultibase, signer);
        assertThat(proof.type()).isEqualTo("DataIntegrityProof");
        assertThat(proof.cryptosuite()).isEqualTo("eddsa-jcs-2022");
        assertThat(proof.proofPurpose()).isEqualTo("assertionMethod");
        assertThat(proof.verificationMethod()).isEqualTo(publicKeyMultibase);
        assertThat(proof.proofValue()).startsWith("z");

        boolean result = DataIntegrity.verifyProof(document, proof, verifier);
        assertThat(result).isTrue();
    }

    @Test
    void roundTrip_documentWithEmbeddedProof_verifyStripsProofBeforeHashing() {
        ObjectNode document = sampleDocument();
        DataIntegrityProof proof = DataIntegrity.createProof(document, publicKeyMultibase, signer);

        // Embed the proof in the document (as it would appear in a did.jsonl entry)
        ObjectNode securedDocument = document.deepCopy();
        securedDocument.putPOJO("proof", proof);

        // verifyProof must strip the embedded proof before hashing
        boolean result = DataIntegrity.verifyProof(securedDocument, proof, verifier);
        assertThat(result).isTrue();
    }

    // -------------------------------------------------------------------------
    // Tamper: modified document fails verification
    // -------------------------------------------------------------------------

    @Test
    void tamper_documentFieldChanged_verificationFails() {
        ObjectNode document = sampleDocument();
        DataIntegrityProof proof = DataIntegrity.createProof(document, publicKeyMultibase, signer);

        ObjectNode tamperedDocument = document.deepCopy();
        tamperedDocument.put("versionTime", "2099-01-01T00:00:00Z");

        assertThatThrownBy(() -> DataIntegrity.verifyProof(tamperedDocument, proof, verifier))
                .isInstanceOf(LogValidationException.class);
    }

    @Test
    void tamper_documentFieldAdded_verificationFails() {
        ObjectNode document = sampleDocument();
        DataIntegrityProof proof = DataIntegrity.createProof(document, publicKeyMultibase, signer);

        ObjectNode tamperedDocument = document.deepCopy();
        tamperedDocument.put("injected", "tamperedWith");

        assertThatThrownBy(() -> DataIntegrity.verifyProof(tamperedDocument, proof, verifier))
                .isInstanceOf(LogValidationException.class);
    }

    // -------------------------------------------------------------------------
    // Tamper: modified proof options fails verification
    // -------------------------------------------------------------------------

    @Test
    void tamper_proofVerificationMethodChanged_verificationFails() {
        ObjectNode document = sampleDocument();
        DataIntegrityProof proof = DataIntegrity.createProof(document, publicKeyMultibase, signer);

        // Replace verificationMethod with a different (but syntactically valid) value
        DataIntegrityProof tamperedProof = new DataIntegrityProof(
                proof.type(),
                proof.cryptosuite(),
                proof.verificationMethod() + "TAMPERED",
                proof.created(),
                proof.proofPurpose(),
                proof.proofValue(),
                proof.id());

        assertThatThrownBy(() -> DataIntegrity.verifyProof(document, tamperedProof, verifier))
                .isInstanceOf(LogValidationException.class);
    }

    @Test
    void tamper_proofCreatedChanged_verificationFails() {
        ObjectNode document = sampleDocument();
        DataIntegrityProof proof = DataIntegrity.createProof(document, publicKeyMultibase, signer);

        DataIntegrityProof tamperedProof = new DataIntegrityProof(
                proof.type(),
                proof.cryptosuite(),
                proof.verificationMethod(),
                "2000-01-01T00:00:00Z",
                proof.proofPurpose(),
                proof.proofValue(),
                proof.id());

        assertThatThrownBy(() -> DataIntegrity.verifyProof(document, tamperedProof, verifier))
                .isInstanceOf(LogValidationException.class);
    }

    // -------------------------------------------------------------------------
    // Wrong key: verification with a different public key fails
    // -------------------------------------------------------------------------

    @Test
    void wrongKey_differentKeyPair_verificationFails() {
        ObjectNode document = sampleDocument();
        DataIntegrityProof proof = DataIntegrity.createProof(document, publicKeyMultibase, signer);

        // Force verification with a different key by ignoring the keyMultibase from the proof
        Ed25519TestFixture wrongFixture = Ed25519TestFixture.generate();
        Verifier wrongKeyVerifier = (signature, message, ignored) ->
                wrongFixture.verifier().verify(signature, message, wrongFixture.publicKeyMultibase());

        assertThatThrownBy(() -> DataIntegrity.verifyProof(document, proof, wrongKeyVerifier))
                .isInstanceOf(LogValidationException.class);
    }

    // -------------------------------------------------------------------------
    // prepareSigningInput: determinism
    // -------------------------------------------------------------------------

    @Test
    void prepareSigningInput_deterministicAcrossInvocations() {
        ObjectNode document = sampleDocument();
        ObjectNode proofOptions = MAPPER.createObjectNode();
        proofOptions.put("type", "DataIntegrityProof");
        proofOptions.put("cryptosuite", "eddsa-jcs-2022");
        proofOptions.put("verificationMethod", publicKeyMultibase);
        proofOptions.put("created", "2025-01-23T04:12:36Z");
        proofOptions.put("proofPurpose", "assertionMethod");

        byte[] first  = DataIntegrity.prepareSigningInput(document, proofOptions);
        byte[] second = DataIntegrity.prepareSigningInput(document, proofOptions);

        assertThat(first).isEqualTo(second);
        assertThat(first).hasSize(64);
    }

    @Test
    void prepareSigningInput_differentDocuments_produceDifferentResults() {
        ObjectNode doc1 = sampleDocument();
        ObjectNode doc2 = sampleDocument();
        doc2.put("versionId", "2-differentHash");

        ObjectNode proofOptions = MAPPER.createObjectNode();
        proofOptions.put("type", "DataIntegrityProof");
        proofOptions.put("cryptosuite", "eddsa-jcs-2022");
        proofOptions.put("verificationMethod", publicKeyMultibase);
        proofOptions.put("created", "2025-01-23T04:12:36Z");
        proofOptions.put("proofPurpose", "assertionMethod");

        byte[] hash1 = DataIntegrity.prepareSigningInput(doc1, proofOptions);
        byte[] hash2 = DataIntegrity.prepareSigningInput(doc2, proofOptions);

        assertThat(hash1).isNotEqualTo(hash2);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ObjectNode sampleDocument() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("versionId", "1-QmTestHash");
        doc.put("versionTime", "2025-01-23T04:12:36Z");
        ObjectNode params = doc.putObject("parameters");
        params.put("method", "did:webvh:1.0");
        ObjectNode state = doc.putObject("state");
        state.put("id", "did:webvh:QmTestSCID:example.com");
        return doc;
    }
}
