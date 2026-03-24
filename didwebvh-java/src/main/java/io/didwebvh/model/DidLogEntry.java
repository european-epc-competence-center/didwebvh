package io.didwebvh.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.model.proof.DataIntegrityProof;

import java.util.List;

/**
 * A single entry in the did:webvh log ({@code did.jsonl}).
 *
 * <p>Each line in the JSONL file deserializes to one {@code DidLogEntry}.
 * The {@code state} field holds the raw DID document as a {@link JsonNode}
 * to avoid prematurely binding to a specific DID doc schema.
 *
 * <p>Wire format:
 * <pre>{@code
 * {
 *   "versionId": "1-QmXxx...",
 *   "versionTime": "2025-01-23T04:12:36Z",
 *   "parameters": { ... },
 *   "state": { ... },
 *   "proof": [ { ... } ]
 * }
 * }</pre>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DidLogEntry(
        @JsonProperty("versionId") String versionId,
        @JsonProperty("versionTime") String versionTime,
        @JsonProperty("parameters") Parameters parameters,
        @JsonProperty("state") JsonNode state,
        @JsonProperty("proof") List<DataIntegrityProof> proof
) {

    /**
     * Returns the version number portion of the {@code versionId} (the integer before the {@code -}).
     * For example, {@code "3-QmXxx..."} → {@code 3}.
     */
    public int versionNumber() {
        // TODO: implement parsing
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Returns the entry hash portion of the {@code versionId} (the base58btc multihash after the {@code -}).
     */
    public String entryHash() {
        // TODO: implement parsing
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Returns a copy of this entry with the {@code proof} field removed,
     * used as input when computing or verifying the entry hash.
     */
    public DidLogEntry withoutProof() {
        return new DidLogEntry(versionId, versionTime, parameters, state, null);
    }
}
