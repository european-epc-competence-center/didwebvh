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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates witness proofs during DID log resolution.
 *
 * <h3>Watermark rule (spec §8.2)</h3>
 * <p>A valid proof from a witness for version {@code N'} implies approval of <strong>all</strong>
 * prior entries up to and including {@code N'}. For an epoch {@code [first, last]} and a query
 * at version {@code V}, the resolver only needs a proof for some {@code N' >= min(last, V)}.
 *
 * <h3>Thread safety</h3>
 * <p>Instances are stateless after construction and safe for concurrent use.
 *
 * @see LogValidationException
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
     * Verifies that all witness epochs are satisfied by the supplied proof collection.
     *
     * <p>For each epoch whose {@code firstVersion <= atVersion}, the resolver checks that at
     * least {@code threshold} distinct witnesses from that epoch's {@link WitnessParameter}
     * each have a cryptographically valid proof for some version {@code N'} where
     * {@code N' >= min(epoch.lastVersion, atVersion)}.
     *
     * @param epochs          ordered list of witness epochs, built by {@code LogBasedResolver}
     * @param versionIds      ordered list of all valid versionIds in the log (index 0 = v1)
     * @param proofCollection the loaded {@code did-witness.json}; may be {@code null}
     * @param atVersion       only check epochs whose {@code firstVersion <= atVersion};
     *                        use {@link Integer#MAX_VALUE} for a latest-version query
     * @throws LogValidationException if any required epoch is not satisfied
     */
    public void verifyEpochs(
            List<WitnessEpoch> epochs,
            List<String> versionIds,
            WitnessProofCollection proofCollection,
            int atVersion) {

        if (epochs == null || epochs.isEmpty()) {
            return; // nothing to check
        }

        Map<String, MaxProof> validated = buildValidatedMap(proofCollection, versionIds);

        log.trace("Built validated witness map: {} distinct witness DIDs with valid proofs",
                validated.size());

        for (WitnessEpoch epoch : epochs) {
            if (epoch.firstVersion() > atVersion) {
                continue; // epoch starts after the queried version
            }

            int requiredVersion = Math.min(epoch.lastVersion(), atVersion);
            WitnessParameter config = epoch.config();
            int threshold = config.threshold() != null ? config.threshold() : 1;
            if (threshold == 0) {
                continue; // witnessing disabled for this epoch
            }

            int satisfiedCount = 0;
            for (WitnessParameter.WitnessEntry witnessEntry : config.witnesses()) {
                String witnessDid = witnessEntry.id();
                MaxProof maxProof = validated.get(witnessDid);
                if (maxProof == null) {
                    log.trace("No valid proof from witness {} for epoch [{}, {}] requiring v>={}",
                            witnessDid, epoch.firstVersion(), epoch.lastVersion(), requiredVersion);
                    continue;
                }

                // Watermark check: does this witness have a valid proof for any N' >= requiredVersion?
                boolean covers = maxProof.versionNumber >= requiredVersion
                        && maxProof.versionNumber <= versionIds.size()
                        && versionIds.get(maxProof.versionNumber - 1).equals(maxProof.versionId);

                if (covers) {
                    satisfiedCount++;
                    log.trace("Witness {} satisfies epoch [{}, {}] (required v>={}, threshold={})",
                            witnessDid, epoch.firstVersion(), epoch.lastVersion(), requiredVersion, threshold);
                }
            }

            if (satisfiedCount < threshold) {
                log.trace("Epoch [{}, {}] threshold={} only has {}/{} valid witnesses",
                        epoch.firstVersion(), epoch.lastVersion(), threshold, satisfiedCount, config.witnesses().size());
                throw new LogValidationException(
                        "Witness epoch [" + epoch.firstVersion() + ", " + epoch.lastVersion() + "]"
                                + " requires threshold=" + threshold
                                + " but only " + satisfiedCount + " witness(es) provided valid proofs");
            }
        }

        log.trace("All {} witness epoch(s) satisfied", epochs.size());
    }

    /**
     * Builds a map from witness DID to the highest-version valid proof that witness provided.
     *
     * <p>Because of the watermark rule, only the maximum proof version per witness matters:
     * a proof for v5 automatically approves v1-5. The result is a simple
     * {@code witnessDid → MaxProof} map.
     */
    private Map<String, MaxProof> buildValidatedMap(
            WitnessProofCollection proofCollection,
            List<String> versionIds) {

        Map<String, MaxProof> validated = new HashMap<>();

        if (proofCollection == null || proofCollection.entries() == null) {
            return validated;
        }

        // Build a fast lookup: versionId → versionNumber (only for entries in the valid log)
        Map<String, Integer> versionIdToNumber = new HashMap<>();
        for (int i = 0; i < versionIds.size(); i++) {
            versionIdToNumber.put(versionIds.get(i), i + 1); // 1-indexed
        }

        for (WitnessProofCollection.Entry proofEntry : proofCollection.entries()) {
            String versionId = proofEntry.versionId();
            Integer versionNumber = versionIdToNumber.get(versionId);
            if (versionNumber == null) {
                log.trace("Ignoring witness proof for versionId not in valid log: {}", versionId);
                continue;
            }

            List<DataIntegrityProof> proofs = proofEntry.proof();
            if (proofs == null || proofs.isEmpty()) {
                continue;
            }

            JsonNode entryNode = MAPPER.valueToTree(proofEntry);

            for (DataIntegrityProof proof : proofs) {
                String witnessDid = extractBaseDid(proof.verificationMethod());
                if (witnessDid.isEmpty()) {
                    continue;
                }

                try {
                    DataIntegrity.verifyProof(entryNode, proof, verifier);
                    // Proof is valid — keep only the highest version for this witness
                    MaxProof existing = validated.get(witnessDid);
                    if (existing == null || versionNumber > existing.versionNumber) {
                        validated.put(witnessDid, new MaxProof(versionNumber, versionId));
                        log.trace("Valid witness proof: {} for versionId {} (v{})",
                                witnessDid, versionId, versionNumber);
                    } else {
                        log.trace("Duplicate/lower witness proof from {} for versionId {} (v{}) — keeping v{}",
                                witnessDid, versionId, versionNumber, existing.versionNumber);
                    }
                } catch (LogValidationException e) {
                    log.trace("Witness proof crypto verification failed for {} @ {}: {}",
                            witnessDid, versionId, e.getMessage());
                }
            }
        }

        return validated;
    }

    /**
     * Extracts the base DID from a verification method URI.
     * E.g. {@code did:key:z6Mk...#z6Mk...} → {@code did:key:z6Mk...}.
     */
    private static String extractBaseDid(String verificationMethod) {
        if (verificationMethod == null) return "";
        int fragmentIdx = verificationMethod.indexOf('#');
        return fragmentIdx >= 0 ? verificationMethod.substring(0, fragmentIdx) : verificationMethod;
    }

    /**
     * Simple holder for the highest valid proof version of a single witness.
     */
    private record MaxProof(int versionNumber, String versionId) {}
}
