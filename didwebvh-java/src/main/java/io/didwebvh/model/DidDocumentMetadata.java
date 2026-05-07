package io.didwebvh.model;

import java.util.List;

/**
 * Metadata about a resolved DID document.
 *
 * <p>This corresponds to {@code didDocumentMetadata} in the W3C DID Resolution spec.
 * It contains properties that describe the DID document itself, such as version
 * information, timestamps, and parameter state.
 */
public record DidDocumentMetadata(
        String versionId,
        Integer versionNumber,
        String versionTime,
        String created,
        String updated,
        String scid,
        Boolean portable,
        Boolean deactivated,
        String ttl,
        WitnessParameter witness,
        List<String> watchers
) {

    /**
     * An empty metadata structure for use in error results.
     *
     * <p>Per the DID Resolution spec, {@code didDocumentMetadata} MUST be present
     * as an empty metadata structure when resolution is unsuccessful.
     */
    public static final DidDocumentMetadata EMPTY =
            new DidDocumentMetadata(null, null, null, null, null, null,
                    null, null, null, null, null);

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("DidDocumentMetadata {\n");
        sb.append("  versionId:     ").append(versionId).append("\n");
        sb.append("  versionNumber: ").append(versionNumber).append("\n");
        sb.append("  versionTime:   ").append(versionTime).append("\n");
        sb.append("  created:       ").append(created).append("\n");
        sb.append("  updated:       ").append(updated).append("\n");
        sb.append("  scid:          ").append(scid).append("\n");
        sb.append("  portable:      ").append(portable).append("\n");
        sb.append("  deactivated:   ").append(deactivated).append("\n");
        sb.append("  ttl:           ").append(ttl).append("\n");
        if (witness != null)   sb.append("  witness:       ").append(witness).append("\n");
        if (watchers != null)  sb.append("  watchers:      ").append(watchers).append("\n");
        sb.append("}");
        return sb.toString();
    }

    public static final class Builder {
        private String versionId;
        private Integer versionNumber;
        private String versionTime;
        private String created;
        private String updated;
        private String scid;
        private Boolean portable;
        private Boolean deactivated;
        private String ttl;
        private WitnessParameter witness;
        private List<String> watchers;

        private Builder() {}

        public Builder versionId(String versionId) { this.versionId = versionId; return this; }
        public Builder versionNumber(Integer versionNumber) { this.versionNumber = versionNumber; return this; }
        public Builder versionTime(String versionTime) { this.versionTime = versionTime; return this; }
        public Builder created(String created) { this.created = created; return this; }
        public Builder updated(String updated) { this.updated = updated; return this; }
        public Builder scid(String scid) { this.scid = scid; return this; }
        public Builder portable(Boolean portable) { this.portable = portable; return this; }
        public Builder deactivated(Boolean deactivated) { this.deactivated = deactivated; return this; }
        public Builder ttl(String ttl) { this.ttl = ttl; return this; }
        public Builder witness(WitnessParameter witness) { this.witness = witness; return this; }
        public Builder watchers(List<String> watchers) { this.watchers = watchers; return this; }

        public DidDocumentMetadata build() {
            return new DidDocumentMetadata(
                    versionId, versionNumber, versionTime, created, updated, scid,
                    portable, deactivated, ttl, witness, watchers);
        }
    }
}
