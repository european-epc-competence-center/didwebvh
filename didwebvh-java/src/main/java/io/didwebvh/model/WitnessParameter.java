package io.didwebvh.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.didwebvh.exception.LogValidationException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The {@code witness} parameter in a did:webvh log entry.
 *
 * <p>Spec requirements (§8.2 / witness-lists):
 * <ul>
 *   <li>Witness DIDs MUST be {@code did:key} DIDs.</li>
 *   <li>The {@code threshold} MUST be between 1 and the number of witnesses (inclusive).</li>
 *   <li>Witness IDs MUST be unique within the array (no duplicates).</li>
 * </ul>
 *
 * <p>Call {@link #validate()} whenever a non-empty witness configuration is set or changed
 * in a log entry to enforce the above constraints before accepting the entry.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record WitnessParameter(
        @JsonProperty("threshold") Integer threshold,
        @JsonProperty("witnesses") List<WitnessEntry> witnesses
) {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    /** A single witness entry (did:key DID). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record WitnessEntry(
            @JsonProperty("id") String id
    ) {
        @Override
        public String toString() {
            try {
                return MAPPER.writeValueAsString(this);
            } catch (JsonProcessingException e) {
                return "WitnessEntry{id=" + id + "}";
            }
        }
    }

    /**
     * Returns {@code true} if this configuration carries no active witnesses
     * (null or empty witnesses list).
     */
    @JsonIgnore
    public boolean isEmpty() {
        return witnesses == null || witnesses.isEmpty();
    }

    /**
     * Validates this witness configuration against the spec rules.
     *
     * <p>Should be called whenever a non-empty {@code WitnessParameter} is set or changed.
     * A {@code null} or {@link #isEmpty() empty} configuration is always valid (witnesses are
     * simply not enabled).
     *
     * <p>Rules enforced:
     * <ol>
     *   <li>The {@code witnesses} array must be non-empty.</li>
     *   <li>Every witness {@code id} must be a {@code did:key} DID.</li>
     *   <li>Witness {@code id} values must be unique (no duplicates).</li>
     *   <li>The {@code threshold} must be between 1 and {@code witnesses.size()} (inclusive).</li>
     * </ol>
     *
     * @throws LogValidationException if any rule is violated
     */
    public void validate() {
        if (isEmpty()) {
            return; // nothing to validate — witnesses are disabled
        }

        // Rule 1: witnesses array must be non-empty (guaranteed by !isEmpty() above, but be explicit)
        if (witnesses == null || witnesses.isEmpty()) {
            throw new LogValidationException("'witness.witnesses' must not be empty when witness is configured");
        }

        // Rule 2 & 3: each id must be a did:key DID and must be unique
        Set<String> seen = new HashSet<>();
        for (WitnessEntry entry : witnesses) {
            if (entry == null || entry.id() == null || entry.id().isBlank()) {
                throw new LogValidationException("Each witness entry must have a non-blank 'id'");
            }
            if (!entry.id().startsWith("did:key:")) {
                throw new LogValidationException(
                        "Witness id '" + entry.id() + "' is not a did:key DID; "
                                + "witness DIDs MUST use the did:key method");
            }
            if (!seen.add(entry.id())) {
                throw new LogValidationException(
                        "Duplicate witness id '" + entry.id() + "'; witness IDs must be unique");
            }
        }

        // Rule 4: threshold must be between 1 and witnesses.size() inclusive
        int n = witnesses.size();
        if (threshold == null) {
            throw new LogValidationException(
                    "'witness.threshold' is required when witnesses are configured");
        }
        if (threshold < 1 || threshold > n) {
            throw new LogValidationException(
                    "'witness.threshold' (" + threshold + ") must be between 1 and "
                            + n + " (the number of witnesses) inclusive");
        }
    }

    @Override
    public String toString() {
        try {
            return MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return "WitnessParameter{threshold=" + threshold + ", witnesses=" + witnesses + "}";
        }
    }
}
