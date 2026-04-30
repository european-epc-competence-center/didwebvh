package io.didwebvh.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    @JsonIgnore
    public boolean isEmpty() {
        return witnesses == null || witnesses.isEmpty();
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
