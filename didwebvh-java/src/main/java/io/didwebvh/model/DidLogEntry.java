package io.didwebvh.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.didwebvh.DidDocument;
import io.didwebvh.model.proof.DataIntegrityProof;

import java.util.List;

/**
 * A single entry in the did:webvh log ({@code did.jsonl}).
 *
 * <p>Each line in the JSONL file deserializes to one {@code DidLogEntry}.
 * The {@code state} field holds the DID document as a {@link DidDocument}.
 *
 * <p>Wire format:
 * <pre>
 * {
 *   "versionId": "1-QmXxx...",
 *   "versionTime": "2025-01-23T04:12:36Z",
 *   "parameters": { ... },
 *   "state": { ... },
 *   "proof": [ { ... } ]
 * }
 * </pre>
 *
 * @param versionId   the version identifier in {@code {n}-{hash}} form
 * @param versionTime the ISO-8601 UTC timestamp when this entry was created
 * @param parameters  the parameter delta (or full params for genesis) for this entry
 * @param state       the DID document state at this version
 * @param proof       the Data Integrity proofs authorising this entry
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DidLogEntry(
        @JsonProperty("versionId") String versionId,
        @JsonProperty("versionTime") String versionTime,
        @JsonProperty("parameters") Parameters parameters,
        @JsonProperty("state") DidDocument state,
        @JsonProperty("proof") List<DataIntegrityProof> proof
) {

    /**
     * Returns the version number portion of the {@code versionId} (the integer before the {@code -}).
     * For example, {@code "3-QmXxx..."} → {@code 3}.
     */
    @JsonIgnore
    public int versionNumber() {
        return Integer.parseInt(versionId.substring(0, versionId.indexOf('-')));
    }

    /**
     * Returns the entry hash portion of the {@code versionId} (the base58btc multihash after the {@code -}).
     */
    @JsonIgnore
    public String entryHash() {
        return versionId.substring(versionId.indexOf('-') + 1);
    }

    /**
     * Returns a copy of this entry with the {@code proof} field removed,
     * used as input when computing or verifying the entry hash.
     */
    public DidLogEntry withoutProof() {
        return new DidLogEntry(versionId, versionTime, parameters, state, null);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("DidLogEntry {\n");
        sb.append("  versionId:   ").append(versionId).append("\n");
        sb.append("  versionTime: ").append(versionTime).append("\n");
        if (parameters != null) {
            sb.append("  parameters:  ").append(indent(parameters.toString(), "               ")).append("\n");
        }
        if (state != null) {
            sb.append("  state:       ").append(state).append("\n");
        }
        if (proof != null && !proof.isEmpty()) {
            sb.append("  proof:\n");
            for (DataIntegrityProof p : proof) {
                sb.append("    - ").append(indent(p.toString(), "      ")).append("\n");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    /** Indents every line after the first by {@code prefix}. */
    private static String indent(String s, String prefix) {
        return s.replace("\n", "\n" + prefix);
    }
}
