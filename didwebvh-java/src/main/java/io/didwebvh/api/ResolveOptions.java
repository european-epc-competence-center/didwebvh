package io.didwebvh.api;

import io.didwebvh.crypto.Verifier;

import java.time.Instant;

/**
 * Options for {@link DidWebVh#resolve} and {@link DidWebVh#resolveFromLog}.
 *
 * <p>All fields are optional. When all version filters are absent, the latest valid
 * version of the DID document is returned.
 */
public final class ResolveOptions {

    /** Return the version whose {@code versionId} exactly matches this string. */
    private final String versionId;

    /** Return the version active at this point in time. */
    private final Instant versionTime;

    /** Return the version with this version number (the integer prefix of {@code versionId}). */
    private final Integer versionNumber;

    /**
     * Optional verifier override for use when calling the resolver directly.
     * When using {@link DidWebVh#resolve} or {@link DidWebVh#resolveFromLog}, the verifier
     * is passed as a top-level argument and this field is ignored.
     */
    private final Verifier verifier;

    private ResolveOptions(Builder builder) {
        this.versionId = builder.versionId;
        this.versionTime = builder.versionTime;
        this.versionNumber = builder.versionNumber;
        this.verifier = builder.verifier;
    }

    public static ResolveOptions defaults() {
        return new Builder().build();
    }

    public String getVersionId() { return versionId; }
    public Instant getVersionTime() { return versionTime; }
    public Integer getVersionNumber() { return versionNumber; }
    public Verifier getVerifier() { return verifier; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String versionId;
        private Instant versionTime;
        private Integer versionNumber;
        private Verifier verifier;

        public Builder versionId(String versionId) { this.versionId = versionId; return this; }
        public Builder versionTime(Instant versionTime) { this.versionTime = versionTime; return this; }
        public Builder versionNumber(int versionNumber) { this.versionNumber = versionNumber; return this; }
        public Builder verifier(Verifier verifier) { this.verifier = verifier; return this; }

        public ResolveOptions build() { return new ResolveOptions(this); }
    }
}
