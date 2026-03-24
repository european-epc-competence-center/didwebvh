package io.didwebvh.api;

import io.didwebvh.model.WitnessParameter;
import io.didwebvh.witness.WitnessProofCollection;

import java.util.List;

/**
 * Options for the {@link DidWebVh#update} operation.
 */
public final class UpdateOptions {

    private final List<String> newUpdateKeys;
    private final List<String> newNextKeyHashes;
    private final WitnessParameter witness;
    private final List<String> watchers;
    private final WitnessProofCollection witnessProofs;

    private UpdateOptions(Builder builder) {
        this.newUpdateKeys = builder.newUpdateKeys;
        this.newNextKeyHashes = builder.newNextKeyHashes;
        this.witness = builder.witness;
        this.watchers = builder.watchers;
        this.witnessProofs = builder.witnessProofs;
    }

    public List<String> getNewUpdateKeys() { return newUpdateKeys; }
    public List<String> getNewNextKeyHashes() { return newNextKeyHashes; }
    public WitnessParameter getWitness() { return witness; }
    public List<String> getWatchers() { return watchers; }
    public WitnessProofCollection getWitnessProofs() { return witnessProofs; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private List<String> newUpdateKeys;
        private List<String> newNextKeyHashes;
        private WitnessParameter witness;
        private List<String> watchers;
        private WitnessProofCollection witnessProofs;

        public Builder newUpdateKeys(List<String> keys) { this.newUpdateKeys = keys; return this; }
        public Builder newNextKeyHashes(List<String> hashes) { this.newNextKeyHashes = hashes; return this; }
        public Builder witness(WitnessParameter witness) { this.witness = witness; return this; }
        public Builder watchers(List<String> watchers) { this.watchers = watchers; return this; }
        public Builder witnessProofs(WitnessProofCollection proofs) { this.witnessProofs = proofs; return this; }

        public UpdateOptions build() { return new UpdateOptions(this); }
    }
}
