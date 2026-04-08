package io.didwebvh.model.proof;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.didwebvh.DidWebVhConstants;

/**
 * A W3C Data Integrity proof as used in did:webvh log entries.
 *
 * <p>The spec mandates {@code eddsa-jcs-2022} as the cryptosuite and
 * {@code assertionMethod} as the proof purpose for controller update proofs.
 *
 * @see <a href="https://www.w3.org/TR/vc-data-integrity/">W3C Data Integrity</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DataIntegrityProof(
        @JsonProperty("type") String type,
        @JsonProperty("cryptosuite") String cryptosuite,
        @JsonProperty("verificationMethod") String verificationMethod,
        @JsonProperty("created") String created,
        @JsonProperty("proofPurpose") String proofPurpose,
        @JsonProperty("proofValue") String proofValue,
        @JsonProperty("id") String id
) {
    /**
     * Creates a fully-populated {@code eddsa-jcs-2022} proof with all constant fields
     * set from {@link DidWebVhConstants}.
     *
     * @param verificationMethod the multikey-encoded public key URI used to sign
     * @param created            the ISO 8601 creation timestamp
     * @param proofValue         the base58btc-encoded Ed25519 signature
     * @return a new {@link DataIntegrityProof}
     */
    public static DataIntegrityProof of(String verificationMethod, String created, String proofValue) {
        return new DataIntegrityProof(
                DidWebVhConstants.PROOF_TYPE,
                DidWebVhConstants.CRYPTOSUITE,
                verificationMethod,
                created,
                DidWebVhConstants.PROOF_PURPOSE,
                proofValue,
                null);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("DataIntegrityProof {\n");
        if (type != null)               sb.append("  type:               ").append(type).append("\n");
        if (cryptosuite != null)        sb.append("  cryptosuite:        ").append(cryptosuite).append("\n");
        if (verificationMethod != null) sb.append("  verificationMethod: ").append(verificationMethod).append("\n");
        if (created != null)            sb.append("  created:            ").append(created).append("\n");
        if (proofPurpose != null)       sb.append("  proofPurpose:       ").append(proofPurpose).append("\n");
        if (proofValue != null)         sb.append("  proofValue:         ").append(proofValue).append("\n");
        if (id != null)                 sb.append("  id:                 ").append(id).append("\n");
        sb.append("}");
        return sb.toString();
    }
}
