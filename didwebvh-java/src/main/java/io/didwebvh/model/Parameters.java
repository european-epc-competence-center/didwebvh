package io.didwebvh.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.didwebvh.DidWebVhConstants;
import io.didwebvh.exception.LogValidationException;

import java.util.List;
import java.util.Objects;

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
     * Validates that these parameters are a legal state transition from {@code previous}
     * and returns the resulting effective (merged) parameter set.
     *
     * <p>For the genesis entry pass {@code null} as {@code previous}; all subsequent
     * entries must pass the previous entry's effective parameters.
     *
     * <p>Spec §3.6 rules enforced:
     * <ul>
     *   <li>Genesis: {@code method}, {@code scid}, {@code updateKeys} are required.</li>
     *   <li>Later entries: {@code scid} MUST NOT appear.</li>
     *   <li>{@code portable} cannot change after the first entry; once {@code false} it cannot become {@code true}.</li>
     *   <li>While pre-rotation is active (previous {@code nextKeyHashes} is non-empty),
     *       both {@code updateKeys} and {@code nextKeyHashes} MUST be present.</li>
     *   <li>{@code null} field values are treated as absent (spec recommends graceful handling).</li>
     * </ul>
     *
     * @param previous the validated parameters of the preceding log entry, or {@code null} for genesis
     * @return the merged/effective parameters after this entry
     * @throws LogValidationException if the transition is invalid
     */
    public Parameters validate(Parameters previous) {
        if (previous == null) {
            validateGenesis();
        } else {
            validateTransition(previous);
        }
        return mergeWith(previous);
    }

    /**
     * Computes the minimal parameter delta between {@code effective} (this) and {@code previous},
     * returning a new {@code Parameters} with only fields that changed or were introduced.
     *
     * <p>Used when building update log entries: the on-wire parameters object should only
     * contain fields that differ from the previous entry.
     *
     * @param previous the effective parameters of the preceding log entry
     * @return a Parameters containing only the changed/new fields; unchanged fields are {@code null}
     */
    public Parameters diff(Parameters previous) {
        Objects.requireNonNull(previous, "previous must not be null for diff");
        return new Parameters(
                Objects.equals(method, previous.method) ? null : method,
                null, // scid never appears in a diff
                Objects.equals(updateKeys, previous.updateKeys) ? null : updateKeys,
                Objects.equals(nextKeyHashes, previous.nextKeyHashes) ? null : nextKeyHashes,
                Objects.equals(portable, previous.portable) ? null : portable,
                Objects.equals(deactivated, previous.deactivated) ? null : deactivated,
                Objects.equals(ttl, previous.ttl) ? null : ttl,
                Objects.equals(witness, previous.witness) ? null : witness,
                Objects.equals(watchers, previous.watchers) ? null : watchers
        );
    }

    /**
     * Returns whether pre-rotation is currently active (nextKeyHashes is non-empty).
     */
    @JsonIgnore
    public boolean isPreRotationActive() {
        return nextKeyHashes != null && !nextKeyHashes.isEmpty();
    }

    /**
     * Returns whether this DID is deactivated.
     */
    @JsonIgnore
    public boolean isDeactivated() {
        return Boolean.TRUE.equals(deactivated);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Parameters {\n");
        if (method != null)         sb.append("  method:         ").append(method).append("\n");
        if (scid != null)           sb.append("  scid:           ").append(scid).append("\n");
        if (updateKeys != null)     sb.append("  updateKeys:     ").append(updateKeys).append("\n");
        if (nextKeyHashes != null)  sb.append("  nextKeyHashes:  ").append(nextKeyHashes).append("\n");
        if (portable != null)       sb.append("  portable:       ").append(portable).append("\n");
        if (deactivated != null)    sb.append("  deactivated:    ").append(deactivated).append("\n");
        if (ttl != null)            sb.append("  ttl:            ").append(ttl).append("\n");
        if (witness != null)        sb.append("  witness:        ").append(witness).append("\n");
        if (watchers != null)       sb.append("  watchers:       ").append(watchers).append("\n");
        sb.append("}");
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Internal validation helpers
    // -------------------------------------------------------------------------

    private void validateGenesis() {
        if (method == null || method.isBlank()) {
            throw new LogValidationException("Genesis entry must contain 'method'");
        }
        if (!DidWebVhConstants.METHOD_V1_0.equals(method)) {
            throw new LogValidationException(
                    "Unsupported method version '" + method + "'; expected '" + DidWebVhConstants.METHOD_V1_0 + "'");
        }
        if (scid == null || scid.isBlank()) {
            throw new LogValidationException("Genesis entry must contain 'scid'");
        }
        if (updateKeys == null || updateKeys.isEmpty()) {
            throw new LogValidationException("Genesis entry must contain at least one 'updateKeys' entry");
        }
    }

    private void validateTransition(Parameters previous) {
        if (scid != null) {
            throw new LogValidationException("'scid' MUST NOT appear in entries after the genesis entry");
        }

        // portable: cannot be changed once set; can only be activated (true) in the genesis entry
        Boolean prevPortable = previous.portable != null ? previous.portable : Boolean.FALSE;
        if (portable != null) {
            // if portable true && prevPortable false
            if (Boolean.TRUE.equals(portable) && !Boolean.TRUE.equals(prevPortable)) {
                throw new LogValidationException(
                        "'portable' can only be set to true in the genesis entry");
            }
            // portable != prevPortable
            if (!portable.equals(prevPortable)) {
                throw new LogValidationException(
                        "'portable' cannot change after the genesis entry (was "
                                + prevPortable + ", attempted " + portable + ")");
            }
        }

        // Pre-rotation: when active, both updateKeys and nextKeyHashes must be present in every entry
        if (previous.isPreRotationActive()) {
            if (updateKeys == null) {
                throw new LogValidationException(
                        "'updateKeys' MUST be present while pre-rotation is active");
            }
            if (nextKeyHashes == null) {
                throw new LogValidationException(
                        "'nextKeyHashes' MUST be present while pre-rotation is active");
            }
        }

        // Once deactivated, no further entries are valid (LogValidator enforces this, but double-check)
        if (Boolean.TRUE.equals(previous.deactivated)) {
            throw new LogValidationException("DID is already deactivated; no further entries are valid");
        }
    }

    // -------------------------------------------------------------------------
    // Merge helper
    // -------------------------------------------------------------------------

    /**
     * Produces the effective (resolved) parameter set by merging this entry's parameters
     * with the previous entry's effective parameters. When {@code previous} is {@code null}
     * (genesis entry) spec defaults are applied for absent fields.
     *
     * <p>Rule: use this entry's value if present (non-null), otherwise inherit from {@code previous}.
     */
    private Parameters mergeWith(Parameters previous) {
        String effectiveMethod = coalesce(method, previous != null ? previous.method : null);
        List<String> effectiveUpdateKeys = coalesce(updateKeys,  previous != null ? previous.updateKeys : null);
        List<String> effectiveNextKeyHashes = coalesceWithDefault(nextKeyHashes, previous != null ? previous.nextKeyHashes : null, List.of());
        Boolean effectivePortable = coalesceWithDefault(portable, previous != null ? previous.portable : null, Boolean.FALSE);
        Boolean effectiveDeactivated = coalesceWithDefault(deactivated, previous != null ? previous.deactivated : null, Boolean.FALSE);
        Integer effectiveTtl = coalesceWithDefault(ttl, previous != null ? previous.ttl : null, DidWebVhConstants.DEFAULT_TTL_SECONDS);
        WitnessParameter effectiveWitness = coalesce(witness, previous != null ? previous.witness : null);
        List<String> effectiveWatchers = coalesceWithDefault(watchers, previous != null ? previous.watchers : null, List.of());
        
        // scid is present in genesis and null in all subsequent effective params
        String effectiveScid = previous == null ? scid : null;

        return new Parameters(effectiveMethod, effectiveScid, effectiveUpdateKeys, effectiveNextKeyHashes,
                effectivePortable, effectiveDeactivated, effectiveTtl, effectiveWitness, effectiveWatchers);
    }

    /**
     * Returns {@code value} if non-null, otherwise returns {@code fallback}.
     */
    private static <T> T coalesce(T value, T fallback) {
        return value != null ? value : fallback;
    }

    /**
     * Returns {@code value} if non-null, otherwise returns {@code fallback} or {@code defaultValue}.
     */
    private static <T> T coalesceWithDefault(T value, T fallback, T defaultValue) {
        if (value != null) return value;
        if (fallback != null) return fallback;
        return defaultValue;
    }
}
