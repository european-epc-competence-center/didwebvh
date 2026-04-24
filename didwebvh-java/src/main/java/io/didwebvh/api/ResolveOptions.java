package io.didwebvh.api;

import io.didwebvh.crypto.Verifier;
import io.didwebvh.witness.WitnessProofCollection;

import java.time.Instant;

/**
 * Options for {@link DidWebVh#resolve}.
 *
 * <p>{@code verifier} is required. All version filter fields are optional; when all
 * are absent, the latest valid version of the DID document is returned.
 *
 * <p>Example:
 * <pre>{@code
 * var options = ResolveOptions.builder()
 *     .verifier(verifier)
 *     .versionNumber(3)   // optional: resolve a specific version
 *     .build();
 * }</pre>
 */
public final class ResolveOptions {

    /** The verifier used to validate Data Integrity proofs on each log entry. */
    private final Verifier verifier;

    /** Return the version whose {@code versionId} exactly matches this string. */
    private final String versionId;

    /** Return the version active at this point in time. */
    private final Instant versionTime;

    /** Return the version with this version number (the integer prefix of {@code versionId}). */
    private final Integer versionNumber;

    /** Pre-loaded witness proofs from {@code did-witness.json}; {@code null} when not available. */
    private final WitnessProofCollection witnessProofs;

    private ResolveOptions(Builder builder) {
        this.verifier = builder.verifier;
        this.versionId = builder.versionId;
        this.versionTime = builder.versionTime;
        this.versionNumber = builder.versionNumber;
        this.witnessProofs = builder.witnessProofs;
    }

    public Verifier getVerifier() { return verifier; }
    public String getVersionId() { return versionId; }
    public Instant getVersionTime() { return versionTime; }
    public Integer getVersionNumber() { return versionNumber; }
    public WitnessProofCollection getWitnessProofs() { return witnessProofs; }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns a new {@link Builder} pre-populated with this instance's values.
     * Useful for creating a copy with one or two fields changed (e.g. adding witness proofs).
     */
    public Builder toBuilder() {
        Builder b = new Builder();
        b.verifier = this.verifier;
        b.versionId = this.versionId;
        b.versionTime = this.versionTime;
        b.versionNumber = this.versionNumber;
        b.witnessProofs = this.witnessProofs;
        return b;
    }

    public static final class Builder {
        private Verifier verifier;
        private String versionId;
        private Instant versionTime;
        private Integer versionNumber;
        private WitnessProofCollection witnessProofs;

        private Builder() {}

        public Builder verifier(Verifier verifier) {
            this.verifier = verifier;
            return this;
        }

        public Builder versionId(String versionId) {
            this.versionId = versionId;
            return this;
        }

        public Builder versionTime(Instant versionTime) {
            this.versionTime = versionTime;
            return this;
        }

        public Builder versionNumber(int versionNumber) {
            this.versionNumber = versionNumber;
            return this;
        }

        public Builder witnessProofs(WitnessProofCollection witnessProofs) {
            this.witnessProofs = witnessProofs;
            return this;
        }

        public ResolveOptions build() {
            return new ResolveOptions(this);
        }
    }
}
