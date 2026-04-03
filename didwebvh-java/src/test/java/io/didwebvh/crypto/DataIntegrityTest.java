package io.didwebvh.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.proof.DataIntegrityProof;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DataIntegrity} verifying the {@code eddsa-jcs-2022} proof lifecycle.
 *
 * <p>Uses BouncyCastle {@link Ed25519Signer} as the {@link Signer}/{@link Verifier}
 * implementation. All key material is freshly generated per test class setup.
 */
class DataIntegrityTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Multicodec prefix for Ed25519 public keys: [0xed, 0x01]. */
    private static final byte[] ED25519_MULTICODEC_PREFIX = {(byte) 0xed, (byte) 0x01};

    private Signer signer;
    private Verifier verifier;
    private String publicKeyMultibase;

    @BeforeEach
    void setUp() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey   = (Ed25519PublicKeyParameters) keyPair.getPublic();

        // Encode public key as multikey: base58btc([0xed, 0x01] + rawPublicKey)
        byte[] rawPublicKey = publicKey.getEncoded();
        byte[] multikeyBytes = new byte[ED25519_MULTICODEC_PREFIX.length + rawPublicKey.length];
        System.arraycopy(ED25519_MULTICODEC_PREFIX, 0, multikeyBytes, 0, ED25519_MULTICODEC_PREFIX.length);
        System.arraycopy(rawPublicKey, 0, multikeyBytes, ED25519_MULTICODEC_PREFIX.length, rawPublicKey.length);
        publicKeyMultibase = Multiformats.encodeBase58btc(multikeyBytes);

        signer = Signer.create(publicKeyMultibase, data -> {
            Ed25519Signer s = new Ed25519Signer();
            s.init(true, privateKey);
            s.update(data, 0, data.length);
            return s.generateSignature();
        });

        // Create a verifier that uses the public key to verify the signature
        verifier = (signature, message, keyMultibase) -> {
            // Decode multikey: strip 2-byte multicodec prefix to get the raw 32-byte public key
            byte[] decodedKey = Multiformats.decodeBase58btc(keyMultibase);
            Ed25519PublicKeyParameters pubKey = new Ed25519PublicKeyParameters(
                    decodedKey, ED25519_MULTICODEC_PREFIX.length);
            Ed25519Signer v = new Ed25519Signer();
            v.init(false, pubKey);
            v.update(message, 0, message.length);
            return v.verifySignature(signature);
        };
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

        // Generate a completely different key pair
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair otherKeyPair = gen.generateKeyPair();
        Ed25519PublicKeyParameters otherPublicKey = (Ed25519PublicKeyParameters) otherKeyPair.getPublic();

        byte[] rawOtherKey = otherPublicKey.getEncoded();
        byte[] otherMultikeyBytes = new byte[ED25519_MULTICODEC_PREFIX.length + rawOtherKey.length];
        System.arraycopy(ED25519_MULTICODEC_PREFIX, 0, otherMultikeyBytes, 0, ED25519_MULTICODEC_PREFIX.length);
        System.arraycopy(rawOtherKey, 0, otherMultikeyBytes, ED25519_MULTICODEC_PREFIX.length, rawOtherKey.length);

        // A verifier that always uses the OTHER public key
        Verifier wrongKeyVerifier = (signature, message, keyMultibase) -> {
            Ed25519PublicKeyParameters wrongKey = new Ed25519PublicKeyParameters(
                    otherMultikeyBytes, ED25519_MULTICODEC_PREFIX.length);
            Ed25519Signer v = new Ed25519Signer();
            v.init(false, wrongKey);
            v.update(message, 0, message.length);
            return v.verifySignature(signature);
        };

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
