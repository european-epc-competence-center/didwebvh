package io.didwebvh.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.ResolutionMetadata;

/**
 * The result of a {@link DidWebVh#update} operation.
 *
 * @param document the updated DID document
 * @param metadata the resolution metadata for the new log entry
 * @param log      the full updated log (existing entries + new entry) to replace {@code did.jsonl}
 */
public record UpdateResult(
        JsonNode document,
        ResolutionMetadata metadata,
        DidLog log
) {}
