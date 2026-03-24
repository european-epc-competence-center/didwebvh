package io.didwebvh.model;

import java.util.List;

/**
 * Metadata returned alongside a resolved DID document.
 *
 * <p>All fields mirror the did:webvh spec §7 resolution metadata.
 * Note: per the DID Resolution spec, integer-typed fields (e.g. TTL)
 * are represented as {@link String} in the metadata output.
 */
public record ResolutionMetadata(
        String versionId,
        String versionTime,
        String created,
        String updated,
        String scid,
        boolean portable,
        boolean deactivated,
        String ttl,
        WitnessParameter witness,
        List<String> watchers,
        String error,
        ProblemDetails problemDetails
) {

    /**
     * An RFC 9457 problem details object for structured error reporting.
     */
    public record ProblemDetails(
            String type,
            String title,
            String detail
    ) {}
}
