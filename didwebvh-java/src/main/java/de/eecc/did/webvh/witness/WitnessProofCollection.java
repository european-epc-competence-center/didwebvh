package de.eecc.did.webvh.witness;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.eecc.did.webvh.model.proof.DataIntegrityProof;
import de.eecc.did.webvh.util.JsonMapper;

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
 *
 * @param entries the list of witness proof entries
 */
public record WitnessProofCollection(List<Entry> entries) {

    private static final ObjectMapper MAPPER = JsonMapper.INSTANCE;

    /**
     * Parses the JSON array format of {@code did-witness.json} into a
     * {@code WitnessProofCollection}.
     *
     * @param json the raw JSON string (a top-level array)
     * @return a new collection wrapping the parsed entries
     * @throws JsonProcessingException if the JSON is malformed
     */
    public static WitnessProofCollection parse(String json) throws JsonProcessingException {
        List<Entry> entries = MAPPER.readValue(json, new TypeReference<>() {});
        return new WitnessProofCollection(entries);
    }

    /**
     * One entry in the witness proof file, covering one log version.
     *
     * @param versionId the versionId of the log entry this proof covers
     * @param proof     the Data Integrity proofs from witnesses for this version
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Entry(
            String versionId,
            List<DataIntegrityProof> proof
    ) {}
}
