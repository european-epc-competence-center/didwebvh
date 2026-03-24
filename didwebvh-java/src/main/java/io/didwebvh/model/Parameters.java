package io.didwebvh.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * The {@code parameters} object of a did:webvh log entry.
 *
 * <p>Encodes all per-entry spec parameters. The two most important methods are:
 * <ul>
 *   <li>{@link #validate(Parameters)} — verifies that this set of parameters is
 *       a legal transition from the previous entry's parameters.</li>
 *   <li>{@link #merge(Parameters)} — produces the effective parameter set for an
 *       entry by merging it with the previous (inherited) parameter set.</li>
 * </ul>
 *
 * <p>Key invariants (from spec):
 * <ul>
 *   <li>{@code null} MUST NOT be used — use typed empty values ({@code []}, {@code false}).</li>
 *   <li>{@code portable} can only be set {@code true} in the first entry.</li>
 *   <li>{@code scid} MUST be present in the first entry and absent in subsequent entries.</li>
 *   <li>When pre-rotation is active ({@code nextKeyHashes} is non-empty), every entry
 *       MUST contain both {@code updateKeys} and {@code nextKeyHashes}.</li>
 * </ul>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Parameters(
        @JsonProperty("method") String method,
        @JsonProperty("scid") String scid,
        @JsonProperty("updateKeys") List<String> updateKeys,
        @JsonProperty("nextKeyHashes") List<String> nextKeyHashes,
        @JsonProperty("portable") Boolean portable,
        @JsonProperty("deactivated") Boolean deactivated,
        @JsonProperty("ttl") Integer ttl,
        @JsonProperty("witness") WitnessParameter witness,
        @JsonProperty("watchers") List<String> watchers
) {

    /**
     * Validates that these parameters are a legal state transition from {@code previous}.
     * For the first entry, pass {@code null} as {@code previous}.
     *
     * @param previous the validated parameters of the preceding log entry, or {@code null}
     * @throws io.didwebvh.exception.LogValidationException if the transition is invalid
     * @return the merged/effective parameters after this entry
     * @implNote TODO: implement full parameter validation rules from spec §6
     */
    public Parameters validate(Parameters previous) {
        // TODO: implement validation + merge logic
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Computes the minimal parameter delta between this entry and {@code previous},
     * omitting fields that are unchanged. Used when appending update log entries.
     *
     * @param previous the effective parameters of the preceding log entry
     * @return a Parameters containing only the fields that changed
     * @implNote TODO: implement diff logic
     */
    public Parameters diff(Parameters previous) {
        // TODO: implement diff logic
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Returns whether pre-rotation is currently active (nextKeyHashes is non-empty).
     */
    public boolean isPreRotationActive() {
        return nextKeyHashes != null && !nextKeyHashes.isEmpty();
    }

    /**
     * Returns whether this DID is deactivated.
     */
    public boolean isDeactivated() {
        return Boolean.TRUE.equals(deactivated);
    }
}
