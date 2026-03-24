package io.didwebvh.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.model.ResolutionMetadata;

/**
 * The result of a {@link DidWebVh#resolve} or {@link DidWebVh#resolveFromLog} operation.
 *
 * <p>If resolution fails, {@code document} is {@code null} and {@code metadata}
 * contains an {@code error} code and optional {@code problemDetails}.
 *
 * @param did      the resolved DID string
 * @param document the resolved DID document, or {@code null} on error
 * @param metadata resolution metadata including version info, error codes, etc.
 */
public record ResolveResult(
        String did,
        JsonNode document,
        ResolutionMetadata metadata
) {

    /** Returns {@code true} if resolution succeeded (no error in metadata). */
    public boolean isSuccess() {
        return document != null && metadata.error() == null;
    }
}
