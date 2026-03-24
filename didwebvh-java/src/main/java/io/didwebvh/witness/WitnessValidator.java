package io.didwebvh.witness;

import io.didwebvh.crypto.Verifier;
import io.didwebvh.model.WitnessParameter;

/**
 * Validates witness proofs during DID log resolution.
 *
 * <p>Validation rules (spec §8.2):
 * <ul>
 *   <li>The number of valid witness proofs for a given {@code versionId} must meet or
 *       exceed the {@code threshold} defined in {@link WitnessParameter}.</li>
 *   <li>Each proof must be a valid {@code eddsa-jcs-2022} Data Integrity proof
 *       signed by a key from one of the listed witness DIDs ({@code did:key} only).</li>
 *   <li>Proofs with a {@code versionId} not yet present in the log MUST be ignored.</li>
 * </ul>
 */
public final class WitnessValidator {

    private final Verifier verifier;

    public WitnessValidator(Verifier verifier) {
        this.verifier = verifier;
    }

    /**
     * Validates that the witness proof collection satisfies the threshold requirement
     * for the given log version.
     *
     * @param versionId       the {@code versionId} of the log entry being validated
     * @param witnessParams   the active witness configuration (threshold + witness list)
     * @param proofCollection the loaded {@code did-witness.json} content
     * @throws io.didwebvh.exception.LogValidationException if the threshold is not met
     */
    public void validate(
            String versionId,
            WitnessParameter witnessParams,
            WitnessProofCollection proofCollection) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
