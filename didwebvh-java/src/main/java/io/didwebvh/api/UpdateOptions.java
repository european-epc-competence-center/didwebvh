package io.didwebvh.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.crypto.Signer;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.WitnessParameter;

import java.util.List;

/**
 * Options for the {@link DidWebVh#update} operation.
 *
 * <p>Use the nested {@link Builder} to construct instances. {@code log},
 * {@code updatedDocument}, and {@code signer} are required; all other fields are optional
 * and only need to be supplied when that aspect of the DID is changing.
 *
 * <p>The library computes the parameter delta between the current log state and these
 * options; callers never need to construct a {@code Parameters} instance directly.
 *
 * <p>Example (document-only update):
 * <pre>{@code
 * var options = UpdateOptions.builder()
 *     .log(currentLog)
 *     .updatedDocument(newDoc)
 *     .signer(signer)
 *     .build();
 * }</pre>
 *
 * <p>Example (key rotation):
 * <pre>{@code
 * var options = UpdateOptions.builder()
 *     .log(currentLog)
 *     .updatedDocument(newDoc)
 *     .updateKeys(List.of(newPublicKeyMultibase))
 *     .signer(newSigner)
 *     .build();
 * }</pre>
 */
public final class UpdateOptions {

    /** The current log to which the update entry will be appended. */
    private final DidLog log;

    /** The new DID document state to record in this log entry. */
    private final JsonNode updatedDocument;

    /** The signing key corresponding to the currently active {@code updateKeys}. */
    private final Signer signer;

    /**
     * New authorization keys; supply only when rotating keys.
     * {@code null} means the current {@code updateKeys} remain unchanged.
     */
    private final List<String> updateKeys;

    /**
     * New pre-rotation key hashes; supply only when changing pre-rotation configuration.
     * {@code null} means the current {@code nextKeyHashes} remain unchanged.
     */
    private final List<String> nextKeyHashes;

    /**
     * New witness configuration; supply only when changing witnesses.
     * {@code null} means the current witness configuration remains unchanged.
     */
    private final WitnessParameter witness;

    /**
     * New watcher URLs; supply only when changing watchers.
     * {@code null} means the current watchers remain unchanged.
     */
    private final List<String> watchers;

    private UpdateOptions(Builder builder) {
        this.log = builder.log;
        this.updatedDocument = builder.updatedDocument;
        this.signer = builder.signer;
        this.updateKeys = builder.updateKeys;
        this.nextKeyHashes = builder.nextKeyHashes;
        this.witness = builder.witness;
        this.watchers = builder.watchers;
    }

    public DidLog getLog() { return log; }
    public JsonNode getUpdatedDocument() { return updatedDocument; }
    public Signer getSigner() { return signer; }
    public List<String> getUpdateKeys() { return updateKeys; }
    public List<String> getNextKeyHashes() { return nextKeyHashes; }
    public WitnessParameter getWitness() { return witness; }
    public List<String> getWatchers() { return watchers; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private DidLog log;
        private JsonNode updatedDocument;
        private Signer signer;
        private List<String> updateKeys;
        private List<String> nextKeyHashes;
        private WitnessParameter witness;
        private List<String> watchers;

        private Builder() {}

        public Builder log(DidLog log) {
            this.log = log;
            return this;
        }

        public Builder updatedDocument(JsonNode updatedDocument) {
            this.updatedDocument = updatedDocument;
            return this;
        }

        public Builder signer(Signer signer) {
            this.signer = signer;
            return this;
        }

        public Builder updateKeys(List<String> updateKeys) {
            this.updateKeys = updateKeys;
            return this;
        }

        public Builder nextKeyHashes(List<String> nextKeyHashes) {
            this.nextKeyHashes = nextKeyHashes;
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

        public UpdateOptions build() {
            return new UpdateOptions(this);
        }
    }
}
