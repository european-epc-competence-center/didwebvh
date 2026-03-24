package io.didwebvh.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.model.proof.DataIntegrityProof;

/**
 * Creates and verifies {@code eddsa-jcs-2022} Data Integrity proofs.
 *
 * <p>Signing flow (per spec):
 * <ol>
 *   <li>Canonicalize (JCS) the document without the proof field.</li>
 *   <li>SHA-256 hash the canonical document bytes.</li>
 *   <li>Canonicalize (JCS) the proof options (without {@code proofValue}).</li>
 *   <li>SHA-256 hash the canonical proof options bytes.</li>
 *   <li>Concatenate: {@code hash(proofOptions) || hash(document)}.</li>
 *   <li>Sign the concatenated bytes using the provided {@link Signer}.</li>
 *   <li>Set {@code proofValue} = base58btc(signature).</li>
 * </ol>
 *
 * @see <a href="https://www.w3.org/TR/vc-di-eddsa/">W3C Data Integrity EdDSA Cryptosuites</a>
 */
public final class DataIntegrity {

    private DataIntegrity() {}

    /**
     * Creates a signed Data Integrity proof for the given document.
     *
     * @param document             the JSON document to sign (without proof)
     * @param verificationMethodId the {@code verificationMethod} URI to embed in the proof
     * @param signer               the key holder
     * @return a fully populated {@link DataIntegrityProof}
     */
    public static DataIntegrityProof createProof(
            JsonNode document,
            String verificationMethodId,
            Signer signer) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Verifies a Data Integrity proof on the given document.
     *
     * @param document the JSON document (with proof embedded)
     * @param proof    the proof to verify
     * @param verifier the key verifier
     * @return {@code true} if the proof is valid
     * @throws io.didwebvh.exception.LogValidationException if verification fails
     */
    public static boolean verifyProof(
            JsonNode document,
            DataIntegrityProof proof,
            Verifier verifier) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Prepares the bytes-to-sign: {@code SHA-256(JCS(proofOptions)) || SHA-256(JCS(document))}.
     *
     * @param document     the document without proof
     * @param proofOptions the proof object without {@code proofValue}
     * @return the concatenated hash bytes
     */
    static byte[] prepareSigningInput(JsonNode document, JsonNode proofOptions) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
