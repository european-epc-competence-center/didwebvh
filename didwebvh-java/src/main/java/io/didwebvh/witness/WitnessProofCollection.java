package io.didwebvh.witness;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.didwebvh.model.proof.DataIntegrityProof;

import java.util.List;

/**
 * The in-memory representation of {@code did-witness.json}.
 *
 * <p>Wire format (array at the top level):
 * <pre>{@code
 * [
 *   { "versionId": "1-QmXxx...", "proof": [ {...}, {...} ] },
 *   { "versionId": "2-QmYyy...", "proof": [ {...} ] }
 * ]
 * }</pre>
 *
 * <p>Key spec rules:
 * <ul>
 *   <li>{@code did-witness.json} MUST be published BEFORE the corresponding {@code did.jsonl} entry.</li>
 *   <li>Resolvers MUST ignore proofs for {@code versionId}s not yet present in the log.</li>
 *   <li>A valid witness proof implies approval of ALL prior entries.</li>
 * </ul>
 */
public record WitnessProofCollection(List<Entry> entries) {

    /**
     * One entry in the witness proof file, covering one log version.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Entry(
            String versionId,
            List<DataIntegrityProof> proof
    ) {}
}
