package io.didwebvh.api;

import io.didwebvh.crypto.Verifier;

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

    private ResolveOptions(Builder builder) {
        this.verifier = builder.verifier;
        this.versionId = builder.versionId;
        this.versionTime = builder.versionTime;
        this.versionNumber = builder.versionNumber;
    }

    public Verifier getVerifier() { return verifier; }
    public String getVersionId() { return versionId; }
    public Instant getVersionTime() { return versionTime; }
    public Integer getVersionNumber() { return versionNumber; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Verifier verifier;
        private String versionId;
        private Instant versionTime;
        private Integer versionNumber;

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

        public ResolveOptions build() {
            return new ResolveOptions(this);
        }
    }
}
