package io.didwebvh.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.ResolutionMetadata;

/**
 * The result of a {@link DidWebVh#create} operation.
 *
 * @param did      the newly created DID string (with real SCID replacing {@code {SCID}})
 * @param document the resolved initial DID document
 * @param metadata the resolution metadata for the genesis entry
 * @param log      the single-entry log to be published as {@code did.jsonl}
 */
public record CreateResult(
        String did,
        JsonNode document,
        ResolutionMetadata metadata,
        DidLog log
) {}
