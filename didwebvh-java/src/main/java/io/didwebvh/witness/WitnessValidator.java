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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates witness proofs during DID log resolution.
 *
 * <h3>Witness epoch model (spec §8.2)</h3>
 * <p>A "witness epoch" is a (WitnessParameter, lastVersion) pair, where {@code lastVersion}
 * is the highest version number that was governed by that particular witness configuration.
 * Genesis uses its own config; each subsequent entry is governed by the <em>previous</em>
 * entry's effective config (the new config only becomes active after publication).
 *
 * <p>For the log to be valid, <strong>every epoch</strong> must independently satisfy its
 * own threshold: at least {@code threshold} distinct witnesses listed in that epoch's
 * {@link WitnessParameter} must each have a valid proof for some version N' where
 * {@code N' >= lastVersion}. This is the watermark rule: a proof for version N' implies
 * approval of all entries 1..N'.
 *
 * <h3>Historical-version queries</h3>
 * <p>When resolving a historical version V, only epochs whose {@code lastVersion <= V} are
 * checked.
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
     * <p>An epoch is satisfied when at least {@code threshold} distinct witnesses from that
     * epoch's {@link WitnessParameter} each have a cryptographically valid proof for some
     * version N' with {@code N' >= epochLastVersion}. The versionId of that proof entry
     * must match the actual log entry at position N' (anti-forgery / watermark check).
     *
     * <p>Only epochs whose {@code lastVersion <= atVersion} are checked. Pass
     * {@code Integer.MAX_VALUE} (or the total log length) when resolving the latest version.
     *
     * @param witnessEpochs   map from each distinct witness config to the highest version
     *                        number it governed; built by {@code LogBasedResolver}
     * @param versionIds      ordered list of all valid versionIds in the log (index 0 = v1)
     * @param proofCollection the loaded {@code did-witness.json}; may be {@code null}
     * @param atVersion       only check epochs with {@code lastVersion <= atVersion};
     *                        use {@link Integer#MAX_VALUE} for a latest-version query
     * @throws LogValidationException if any required epoch is not satisfied
     */
    public void verifyEpochs(
            Map<WitnessParameter, Integer> witnessEpochs,
            List<String> versionIds,
            WitnessProofCollection proofCollection,
            int atVersion) {

        if (witnessEpochs == null || witnessEpochs.isEmpty()) {
            return; // nothing to check
        }

        // Pre-validate: build the "validated" map once.
        // validated[witnessDid][versionNumber] = versionId
        // — for each witness DID that has a cryptographically valid proof,
        //   map the version number to its versionId so we can apply the watermark check.
        Map<String, Map<Integer, String>> validated = buildValidatedMap(proofCollection, versionIds);

        log.trace("Built validated witness map: {} distinct witness DIDs with valid proofs",
                validated.size());

        for (Map.Entry<WitnessParameter, Integer> epochEntry : witnessEpochs.entrySet()) {
            WitnessParameter config = epochEntry.getKey();
            int epochLastVersion = epochEntry.getValue();

            // Skip epochs that are beyond the version we are checking
            if (epochLastVersion > atVersion) {
                continue;
            }

            int threshold = config.threshold() != null ? config.threshold() : 1;
            if (threshold == 0) {
                // Threshold 0 means witnessing is disabled for this epoch
                continue;
            }

            int satisfiedCount = 0;
            for (WitnessParameter.WitnessEntry witnessEntry : config.witnesses()) {
                String witnessDid = witnessEntry.id();
                Map<Integer, String> witnessProofs = validated.get(witnessDid);
                if (witnessProofs == null) {
                    log.trace("No valid proof from witness {} for epoch requiring v>={}", witnessDid, epochLastVersion);
                    continue;
                }

                // Watermark check: does this witness have a valid proof for any N' >= epochLastVersion,
                // where the versionId at position N' matches the actual log?
                boolean covers = false;
                for (Map.Entry<Integer, String> proofAt : witnessProofs.entrySet()) {
                    int proofVersion = proofAt.getKey();
                    String proofVersionId = proofAt.getValue();
                    if (proofVersion >= epochLastVersion
                            && proofVersion <= versionIds.size()
                            && versionIds.get(proofVersion - 1).equals(proofVersionId)) {
                        covers = true;
                        break;
                    }
                }

                if (covers) {
                    satisfiedCount++;
                    log.trace("Witness {} satisfies epoch (lastVersion={}, threshold={})",
                            witnessDid, epochLastVersion, threshold);
                }
            }

            if (satisfiedCount < threshold) {
                log.trace("Epoch lastVersion={} threshold={} only has {}/{} valid witnesses",
                        epochLastVersion, threshold, satisfiedCount, config.witnesses().size());
                throw new LogValidationException(
                        "Witness epoch (lastVersion=" + epochLastVersion
                                + ") requires threshold=" + threshold
                                + " but only " + satisfiedCount + " witness(es) provided valid proofs");
            }
        }

        log.trace("All {} witness epoch(s) satisfied", witnessEpochs.size());
    }

    /**
     * Builds the "validated" map from the proof collection.
     *
     * <p>The result maps each witness DID to a map of {versionNumber → versionId} for all
     * entries where that witness provided a cryptographically valid proof. Only proof entries
     * whose versionId exists in the valid log ({@code versionIds}) are considered.
     *
     * @param proofCollection the raw proof collection; may be {@code null}
     * @param versionIds      ordered versionIds from the validated log (index 0 = version 1)
     * @return map from witnessDid → {versionNumber → versionId}; never {@code null}
     */
    private Map<String, Map<Integer, String>> buildValidatedMap(
            WitnessProofCollection proofCollection,
            List<String> versionIds) {

        Map<String, Map<Integer, String>> validated = new HashMap<>();

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
            Set<String> seenWitnesses = new HashSet<>();

            for (DataIntegrityProof proof : proofs) {
                String witnessDid = extractBaseDid(proof.verificationMethod());
                if (witnessDid.isEmpty()) {
                    continue;
                }
                if (!seenWitnesses.add(witnessDid)) {
                    log.trace("Duplicate witness proof from {} for versionId {}", witnessDid, versionId);
                    continue;
                }

                try {
                    DataIntegrity.verifyProof(entryNode, proof, verifier);
                    // Proof is valid: record witnessDid → versionNumber → versionId
                    validated.computeIfAbsent(witnessDid, k -> new HashMap<>())
                             .put(versionNumber, versionId);
                    log.trace("Valid witness proof: {} for versionId {} (v{})",
                            witnessDid, versionId, versionNumber);
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
}
