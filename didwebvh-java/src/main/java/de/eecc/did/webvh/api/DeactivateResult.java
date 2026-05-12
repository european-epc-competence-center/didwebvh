package de.eecc.did.webvh.api;

import de.eecc.did.webvh.model.DidDocumentMetadata;
import de.eecc.did.webvh.model.DidLog;

/**
 * The result of a {@link DidWebVh#deactivate} operation.
 *
 * @param metadata document metadata for the deactivation entry ({@code deactivated = true})
 * @param log      the full updated log including the deactivation entry
 */
public record DeactivateResult(
        DidDocumentMetadata metadata,
        DidLog log
) {}
