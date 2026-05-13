package de.eecc.did.webvh.api;

import de.eecc.did.webvh.crypto.Signer;
import de.eecc.did.webvh.model.DidLog;

/**
 * Options for the {@link DidWebVh#deactivate} operation.
 *
 * <p>Use the nested {@link Builder} to construct instances. {@code log} and
 * {@code signer} are required.
 *
 * <p>Example:
 * <pre>{@code
 * var options = DeactivateOptions.builder()
 *     .log(currentLog)
 *     .signer(signer)
 *     .build();
 * }</pre>
 */
public final class DeactivateOptions {

    /** The current log to which the deactivation entry will be appended. */
    private final DidLog log;

    /** The signing key corresponding to the currently active {@code updateKeys}. */
    private final Signer signer;

    /**
     * The {@code versionTime} to record in the deactivation log entry. {@code null} means the
     * library picks the current wall-clock time, guaranteeing it is strictly after the
     * previous entry's time by advancing by one second if needed.
     */
    private final java.time.Instant versionTime;

    private DeactivateOptions(Builder builder) {
        this.log = builder.log;
        this.signer = builder.signer;
        this.versionTime = builder.versionTime;
    }

    public DidLog getLog() { return log; }
    public Signer getSigner() { return signer; }
    public java.time.Instant getVersionTime() { return versionTime; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private DidLog log;
        private Signer signer;
        private java.time.Instant versionTime;  // null → auto-advance past previous entry

        private Builder() {}

        public Builder log(DidLog log) {
            this.log = log;
            return this;
        }

        public Builder signer(Signer signer) {
            this.signer = signer;
            return this;
        }

        public Builder versionTime(java.time.Instant versionTime) {
            this.versionTime = versionTime;
            return this;
        }

        public DeactivateOptions build() {
            return new DeactivateOptions(this);
        }
    }
}
