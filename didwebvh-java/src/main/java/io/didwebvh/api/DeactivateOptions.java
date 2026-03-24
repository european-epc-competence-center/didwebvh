package io.didwebvh.api;

import io.didwebvh.crypto.Signer;

/**
 * Options for the {@link DidWebVh#deactivate} operation.
 *
 * <p>Use the nested {@link Builder} to construct instances. {@code signer} is required.
 *
 * <p>Example:
 * <pre>{@code
 * var options = DeactivateOptions.builder()
 *     .signer(signer)
 *     .build();
 * }</pre>
 */
public final class DeactivateOptions {

    /** The signing key corresponding to the currently active {@code updateKeys}. */
    private final Signer signer;

    private DeactivateOptions(Builder builder) {
        this.signer = builder.signer;
    }

    public Signer getSigner() { return signer; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Signer signer;

        private Builder() {}

        public Builder signer(Signer signer) {
            this.signer = signer;
            return this;
        }

        public DeactivateOptions build() {
            return new DeactivateOptions(this);
        }
    }
}
