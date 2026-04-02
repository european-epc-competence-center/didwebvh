package io.didwebvh.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.DidWebVhConstants;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.proof.DataIntegrityProof;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Creates and verifies {@code eddsa-jcs-2022} Data Integrity proofs.
 *
 * <p>Signing flow per W3C spec §3.3 (eddsa-jcs-2022):
 * <ol>
 *   <li>Build proof options: {@code type, cryptosuite, verificationMethod, created, proofPurpose}.</li>
 *   <li>Canonicalize (JCS) the proof options → SHA-256 → {@code proofConfigHash} (32 bytes).</li>
 *   <li>Canonicalize (JCS) the document without proof → SHA-256 → {@code documentHash} (32 bytes).</li>
 *   <li>Concatenate: {@code proofConfigHash || documentHash} (64 bytes) — proof config FIRST.</li>
 *   <li>Sign with Ed25519 (Pure EdDSA per RFC 8032).</li>
 *   <li>Set {@code proofValue} = base58btc(signature).</li>
 * </ol>
 *
 * @see <a href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">W3C Data Integrity EdDSA §3.3</a>
 */
public final class DataIntegrity {

    private static final Logger log = LoggerFactory.getLogger(DataIntegrity.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private DataIntegrity() {}

    /**
     * Creates a signed Data Integrity proof for the given document.
     *
     * @param document             the JSON document to sign (must not contain a {@code proof} field)
     * @param verificationMethodId the {@code verificationMethod} URI to embed in the proof
     * @param signer               the key holder
     * @return a fully populated {@link DataIntegrityProof}
     */
    public static DataIntegrityProof createProof(
            JsonNode unsecuredDocument,
            String verificationMethodId,
            Signer signer) {
        log.trace("Received request to create Data Integrity proof, verificationMethod={}", verificationMethodId);

        String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();

        ObjectNode options = buildProofOptions(
                DidWebVhConstants.PROOF_TYPE,
                DidWebVhConstants.CRYPTOSUITE,
                verificationMethodId,
                created,
                DidWebVhConstants.PROOF_PURPOSE);

        byte[] signingInput = prepareSigningInput(unsecuredDocument, options);
        byte[] signature = signer.sign(signingInput);
        String proofValue = Multiformats.encodeBase58btc(signature);

        DataIntegrityProof proof = new DataIntegrityProof(
                DidWebVhConstants.PROOF_TYPE,
                DidWebVhConstants.CRYPTOSUITE,
                verificationMethodId,
                created,
                DidWebVhConstants.PROOF_PURPOSE,
                proofValue,
                null);

        log.trace("Successfully created Data Integrity proof, verificationMethod={}", verificationMethodId);
        return proof;
    }

    /**
     * Verifies a Data Integrity proof on the given document.
     *
     * <p>The document may contain an embedded {@code proof} field — it will be stripped
     * before hashing, exactly as specified in §3.3.2 of the W3C spec.
     *
     * @param document the JSON document (with or without proof embedded)
     * @param proof    the proof to verify
     * @param verifier the key verifier
     * @return {@code true} if the proof is valid
     * @throws LogValidationException if the signature does not verify
     */
    public static boolean verifyProof(
            JsonNode document,
            DataIntegrityProof proof,
            Verifier verifier) {
        log.trace("Received request to verify Data Integrity proof, verificationMethod={}", proof.verificationMethod());

        // Per spec §3.3.2 step 1: unsecuredDocument = securedDocument without the proof field
        JsonNode unsecuredDocument = document.has("proof")
                ? ((ObjectNode) document.deepCopy()).without("proof")
                : document;

        // Per spec §3.3.2 step 2: proofOptions = proof without proofValue
        ObjectNode proofOptions = buildProofOptions(
                proof.type(),
                proof.cryptosuite(),
                proof.verificationMethod(),
                proof.created(),
                proof.proofPurpose());

        byte[] transformedData = prepareSigningInput(unsecuredDocument, proofOptions);
        byte[] signature = Multiformats.decodeBase58btc(proof.proofValue());

        boolean valid = verifier.verify(signature, transformedData, proof.verificationMethod());
        if (!valid) {
            throw new LogValidationException(
                    "Data Integrity proof verification failed for verificationMethod: " + proof.verificationMethod());
        }

        log.trace("Successfully verified Data Integrity proof, verificationMethod={}", proof.verificationMethod());
        return true;
    }

    /**
     * Prepares the 64-byte signing input per W3C spec §3.3.4.
     *
     * <p>Concatenation order: {@code SHA-256(JCS(proofOptions)) || SHA-256(JCS(document))}.
     * The proof-config hash is always the <em>first</em> 32 bytes.
     *
     * @param document     the document without the proof field
     * @param proofOptions the proof options without {@code proofValue}
     * @return the 64-byte concatenated hash
     */
    static byte[] prepareSigningInput(JsonNode document, JsonNode proofOptions) {
        byte[] proofOptionsHash = sha256(JcsCanonicalizer.canonicalize(proofOptions));
        byte[] transformedDocumentHash = sha256(JcsCanonicalizer.canonicalize(document));
        byte[] hashData = new byte[64];
        System.arraycopy(proofOptionsHash, 0, hashData, 0,  32);
        System.arraycopy(transformedDocumentHash,    0, hashData, 32, 32);
        return hashData;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ObjectNode buildProofOptions(
            String type,
            String cryptosuite,
            String verificationMethod,
            String created,
            String proofPurpose) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("type", type);
        node.put("cryptosuite", cryptosuite);
        node.put("verificationMethod", verificationMethod);
        node.put("created", created);
        node.put("proofPurpose", proofPurpose);
        return node;
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available in this JVM", e);
        }
    }
}
