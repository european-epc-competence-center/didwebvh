package io.didwebvh.witness;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.crypto.DataIntegrity;
import io.didwebvh.crypto.DefaultVerifier;
import io.didwebvh.crypto.Verifier;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.WitnessParameter;
import io.didwebvh.model.proof.DataIntegrityProof;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
 *   <li>A valid witness proof for version N implies approval of ALL prior entries (watermark).</li>
 * </ul>
 */
public final class WitnessValidator {

    private static final Logger log = LoggerFactory.getLogger(WitnessValidator.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Verifier verifier;

    /**
     * Creates a witness validator with the given verifier.
     *
     * @param verifier the verifier used to check witness Data Integrity proofs;
     *                 if {@code null}, the built-in {@link DefaultVerifier} is used
     */
    public WitnessValidator(Verifier verifier) {
        this.verifier = verifier != null ? verifier : DefaultVerifier.instance();
    }

    /**
     * Determines the highest version number covered by valid witness proofs (the "frontier").
     *
     * <p>A valid witness proof for version N implies approval of all entries 1..N.
     * Proofs for versionIds not present in {@code validEntries} are ignored per spec.
     *
     * @param validEntries    chain-validated log entries paired with their effective params
     * @param proofCollection the loaded {@code did-witness.json}, may be {@code null}
     * @return the highest approved version number, or 0 if no entries are covered
     */
    public int findApprovedFrontier(
            List<ValidatedEntryView> validEntries,
            WitnessProofCollection proofCollection) {
        log.trace("Computing witness frontier for {} validated entries", validEntries.size());

        if (proofCollection == null || proofCollection.entries() == null) {
            return 0;
        }

        int frontier = 0;

        for (WitnessProofCollection.Entry proofEntry : proofCollection.entries()) {
            ValidatedEntryView matched = validEntries.stream()
                    .filter(v -> proofEntry.versionId().equals(v.versionId()))
                    .findFirst()
                    .orElse(null);

            if (matched == null) {
                log.trace("Ignoring witness proof for unknown versionId: {}", proofEntry.versionId());
                continue;
            }

            WitnessParameter witnessParams = matched.effectiveWitness();
            if (witnessParams == null || witnessParams.isEmpty()) {
                continue;
            }

            int validCount = countValidProofs(proofEntry, witnessParams);
            int threshold = witnessParams.threshold() != null ? witnessParams.threshold() : 1;

            if (validCount >= threshold) {
                int versionNumber = matched.versionNumber();
                frontier = Math.max(frontier, versionNumber);
                log.trace("Witness frontier advanced to {} (proof for {})", frontier, proofEntry.versionId());
            }
        }

        log.trace("Final witness frontier: {}", frontier);
        return frontier;
    }

    /**
     * Counts valid, distinct witness proofs in a proof entry.
     */
    private int countValidProofs(WitnessProofCollection.Entry proofEntry, WitnessParameter witnessParams) {
        List<DataIntegrityProof> proofs = proofEntry.proof();
        if (proofs == null || proofs.isEmpty()) {
            return 0;
        }

        Set<String> authorizedDids = new HashSet<>();
        for (WitnessParameter.WitnessEntry w : witnessParams.witnesses()) {
            authorizedDids.add(w.id());
        }

        JsonNode entryNode = MAPPER.valueToTree(proofEntry);

        Set<String> seenWitnesses = new HashSet<>();
        int validCount = 0;

        for (DataIntegrityProof proof : proofs) {
            String witnessDid = extractBaseDid(proof.verificationMethod());
            if (!authorizedDids.contains(witnessDid)) {
                log.trace("Witness proof from unauthorized DID: {}", witnessDid);
                continue;
            }
            if (!seenWitnesses.add(witnessDid)) {
                log.trace("Duplicate witness proof from: {}", witnessDid);
                continue;
            }

            try {
                DataIntegrity.verifyProof(entryNode, proof, verifier);
                validCount++;
            } catch (LogValidationException e) {
                log.trace("Witness proof verification failed for {}: {}", witnessDid, e.getMessage());
            }
        }

        return validCount;
    }

    /**
     * Extracts the base DID from a verification method URI.
     * E.g. {@code did:key:z6Mk...#z6Mk...} returns {@code did:key:z6Mk...}.
     */
    private static String extractBaseDid(String verificationMethod) {
        if (verificationMethod == null) return "";
        int fragmentIdx = verificationMethod.indexOf('#');
        return fragmentIdx >= 0 ? verificationMethod.substring(0, fragmentIdx) : verificationMethod;
    }

    /**
     * A minimal view of a validated log entry, used to decouple
     * {@code WitnessValidator} from {@code LogBasedResolver}'s internal record.
     */
    public interface ValidatedEntryView {
        String versionId();
        int versionNumber();
        WitnessParameter effectiveWitness();
    }
}
