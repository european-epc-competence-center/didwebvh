package io.didwebvh.api;

import io.didwebvh.model.DidLog;
import io.didwebvh.model.ResolutionMetadata;

/**
 * The result of a {@link DidWebVh#deactivate} operation.
 *
 * @param did      the DID string (unchanged)
 * @param metadata resolution metadata for the deactivation entry ({@code deactivated = true})
 * @param log      the full updated log including the deactivation entry
 */
public record DeactivateResult(
        String did,
        ResolutionMetadata metadata,
        DidLog log
) {}
