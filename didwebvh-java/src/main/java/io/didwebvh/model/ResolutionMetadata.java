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

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates error metadata with an RFC 9457 problem details object.
     *
     * @param errorCode spec error code ({@code "invalidDid"} or {@code "notFound"})
     * @param title     short human-readable summary
     * @param detail    longer explanation
     */
    public static ResolutionMetadata error(String errorCode, String title, String detail) {
        return builder()
                .error(errorCode)
                .problemDetails(new ProblemDetails("about:blank", title, detail))
                .build();
    }

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

    public static final class Builder {
        private String versionId;
        private String versionTime;
        private String created;
        private String updated;
        private String scid;
        private boolean portable;
        private boolean deactivated;
        private String ttl;
        private WitnessParameter witness;
        private List<String> watchers;
        private String error;
        private ProblemDetails problemDetails;

        private Builder() {}

        public Builder versionId(String versionId) { this.versionId = versionId; return this; }
        public Builder versionTime(String versionTime) { this.versionTime = versionTime; return this; }
        public Builder created(String created) { this.created = created; return this; }
        public Builder updated(String updated) { this.updated = updated; return this; }
        public Builder scid(String scid) { this.scid = scid; return this; }
        public Builder portable(boolean portable) { this.portable = portable; return this; }
        public Builder deactivated(boolean deactivated) { this.deactivated = deactivated; return this; }
        public Builder ttl(String ttl) { this.ttl = ttl; return this; }
        public Builder witness(WitnessParameter witness) { this.witness = witness; return this; }
        public Builder watchers(List<String> watchers) { this.watchers = watchers; return this; }
        public Builder error(String error) { this.error = error; return this; }
        public Builder problemDetails(ProblemDetails problemDetails) { this.problemDetails = problemDetails; return this; }

        public ResolutionMetadata build() {
            return new ResolutionMetadata(
                    versionId, versionTime, created, updated, scid,
                    portable, deactivated, ttl, witness, watchers,
                    error, problemDetails);
        }
    }
}
