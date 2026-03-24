package io.didwebvh.model.proof;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

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
    // TODO: add factory method / builder once DataIntegrity.java is implemented
}
