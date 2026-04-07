package io.didwebvh.api;

import io.didwebvh.model.DidLog;
import io.didwebvh.model.ResolutionMetadata;

/**
 * The result of a {@link DidWebVh#deactivate} operation.
 *
 * @param metadata resolution metadata for the deactivation entry ({@code deactivated = true})
 * @param log      the full updated log including the deactivation entry
 */
public record DeactivateResult(
        ResolutionMetadata metadata,
        DidLog log
) {}
