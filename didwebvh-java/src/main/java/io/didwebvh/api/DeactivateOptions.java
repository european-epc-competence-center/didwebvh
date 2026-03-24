package io.didwebvh.api;

import io.didwebvh.crypto.Signer;
import io.didwebvh.model.DidLog;

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

    private DeactivateOptions(Builder builder) {
        this.log = builder.log;
        this.signer = builder.signer;
    }

    public DidLog getLog() { return log; }
    public Signer getSigner() { return signer; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private DidLog log;
        private Signer signer;

        private Builder() {}

        public Builder log(DidLog log) {
            this.log = log;
            return this;
        }

        public Builder signer(Signer signer) {
            this.signer = signer;
            return this;
        }

        public DeactivateOptions build() {
            return new DeactivateOptions(this);
        }
    }
}
