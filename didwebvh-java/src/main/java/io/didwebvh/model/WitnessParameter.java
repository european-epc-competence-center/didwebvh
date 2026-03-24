package io.didwebvh.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * The {@code witness} parameter in a did:webvh log entry.
 *
 * <p>Witness DIDs MUST be {@code did:key} DIDs. The threshold MUST be between
 * 1 and the number of witnesses (inclusive).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record WitnessParameter(
        @JsonProperty("threshold") Integer threshold,
        @JsonProperty("witnesses") List<WitnessEntry> witnesses
) {

    /** A single witness entry (did:key DID). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record WitnessEntry(
            @JsonProperty("id") String id
    ) {}

    public boolean isEmpty() {
        return witnesses == null || witnesses.isEmpty();
    }
}
