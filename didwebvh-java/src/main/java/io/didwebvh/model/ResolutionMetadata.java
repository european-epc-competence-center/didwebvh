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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ResolutionMetadata {\n");
        sb.append("  versionId:   ").append(versionId).append("\n");
        sb.append("  versionTime: ").append(versionTime).append("\n");
        sb.append("  created:     ").append(created).append("\n");
        sb.append("  updated:     ").append(updated).append("\n");
        sb.append("  scid:        ").append(scid).append("\n");
        sb.append("  portable:    ").append(portable).append("\n");
        sb.append("  deactivated: ").append(deactivated).append("\n");
        sb.append("  ttl:         ").append(ttl).append("\n");
        if (witness != null)   sb.append("  witness:     ").append(witness).append("\n");
        if (watchers != null)  sb.append("  watchers:    ").append(watchers).append("\n");
        if (error != null)     sb.append("  error:       ").append(error).append("\n");
        if (problemDetails != null) sb.append("  problem:     ").append(problemDetails).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * An RFC 9457 problem details object for structured error reporting.
     */
    public record ProblemDetails(
            String type,
            String title,
            String detail
    ) {}
}
