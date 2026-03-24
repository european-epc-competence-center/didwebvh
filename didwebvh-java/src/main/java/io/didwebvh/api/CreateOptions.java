package io.didwebvh.api;

import io.didwebvh.model.WitnessParameter;

import java.util.List;

/**
 * Options for the {@link DidWebVh#create} operation.
 *
 * <p>Use the nested {@link Builder} to construct instances.
 */
public final class CreateOptions {

    /** The domain (and optional path) for the DID, e.g. {@code example.com:dids:issuer}. */
    private final String domain;

    /** Pre-rotation key hashes; empty means pre-rotation is disabled. */
    private final List<String> nextKeyHashes;

    /** Whether the DID should be portable (can only be set true at creation). */
    private final boolean portable;

    /** Witness configuration; {@code null} means no witnesses. */
    private final WitnessParameter witness;

    /** Watcher URLs; {@code null} or empty means no watchers. */
    private final List<String> watchers;

    private CreateOptions(Builder builder) {
        this.domain = builder.domain;
        this.nextKeyHashes = builder.nextKeyHashes;
        this.portable = builder.portable;
        this.witness = builder.witness;
        this.watchers = builder.watchers;
    }

    public String getDomain() { return domain; }
    public List<String> getNextKeyHashes() { return nextKeyHashes; }
    public boolean isPortable() { return portable; }
    public WitnessParameter getWitness() { return witness; }
    public List<String> getWatchers() { return watchers; }

    public static Builder builder(String domain) {
        return new Builder(domain);
    }

    public static final class Builder {
        private final String domain;
        private List<String> nextKeyHashes = List.of();
        private boolean portable = false;
        private WitnessParameter witness;
        private List<String> watchers;

        private Builder(String domain) {
            this.domain = domain;
        }

        public Builder nextKeyHashes(List<String> nextKeyHashes) {
            this.nextKeyHashes = nextKeyHashes;
            return this;
        }

        public Builder portable(boolean portable) {
            this.portable = portable;
            return this;
        }

        public Builder witness(WitnessParameter witness) {
            this.witness = witness;
            return this;
        }

        public Builder watchers(List<String> watchers) {
            this.watchers = watchers;
            return this;
        }

        public CreateOptions build() {
            return new CreateOptions(this);
        }
    }
}
