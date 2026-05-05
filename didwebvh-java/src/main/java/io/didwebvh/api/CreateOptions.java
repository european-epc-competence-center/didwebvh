package io.didwebvh.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.crypto.Signer;
import io.didwebvh.model.WitnessParameter;

import java.util.List;

/**
 * Options for the {@link DidWebVh#create} operation.
 *
 * <p>Use the nested {@link Builder} to construct instances. The following fields are required:
 * {@code domain}, {@code initialDocument}, {@code updateKeys}, {@code signer}.
 *
 * <p>The library assembles the internal log {@code parameters} object from these options;
 * callers never need to construct a {@code Parameters} instance directly.
 *
 * <p>Example:
 * <pre>{@code
 * var options = CreateOptions.builder()
 *     .domain("example.com:dids:issuer")
 *     .initialDocument(doc)                    // JsonNode with {SCID} placeholders
 *     .updateKeys(List.of(publicKeyMultibase))  // multikey-encoded public key(s)
 *     .signer(signer)
 *     .build();
 * }</pre>
 */
public final class CreateOptions {

    /**
     * The domain (and optional path) for the DID, e.g. {@code example.com:dids:issuer}.
     * Used to construct the DID string: {@code did:webvh:{SCID}:{domain}}.
     */
    private final String domain;

    /**
     * The initial DID document. Must contain {@code {SCID}} as a placeholder wherever the
     * DID identifier appears (e.g. the {@code id} field). The library replaces all occurrences
     * with the computed SCID before signing.
     */
    private final JsonNode initialDocument;

    /**
     * The multikey-encoded public key(s) authorised to sign future log updates.
     * These are the log-level authorization keys, separate from any verification methods
     * listed inside the DID document itself.
     */
    private final List<String> updateKeys;

    /** The signing key corresponding to one of the {@code updateKeys}. */
    private final Signer signer;

    /** Whether the DID should be portable (can only be set {@code true} at creation). */
    private final boolean portable;

    /** Pre-rotation key hashes; empty list means pre-rotation is disabled. */
    private final List<String> nextKeyHashes;

    /** Witness configuration; {@code null} means no witnesses. */
    private final WitnessParameter witness;

    /** Watcher URLs; {@code null} or empty means no watchers. */
    private final List<String> watchers;

    /**
     * Time-to-live in seconds for caching the resolved DID. {@code null} means the
     * spec default ({@value io.didwebvh.DidWebVhConstants#DEFAULT_TTL_SECONDS}) is used.
     */
    private final Integer ttl;

    private CreateOptions(Builder builder) {
        this.domain = builder.domain;
        this.initialDocument = builder.initialDocument;
        this.updateKeys = builder.updateKeys;
        this.signer = builder.signer;
        this.portable = builder.portable;
        this.nextKeyHashes = builder.nextKeyHashes;
        this.witness = builder.witness;
        this.watchers = builder.watchers;
        this.ttl = builder.ttl;
    }

    public String getDomain() { return domain; }
    public JsonNode getInitialDocument() { return initialDocument; }
    public List<String> getUpdateKeys() { return updateKeys; }
    public Signer getSigner() { return signer; }
    public boolean isPortable() { return portable; }
    public List<String> getNextKeyHashes() { return nextKeyHashes; }
    public WitnessParameter getWitness() { return witness; }
    public List<String> getWatchers() { return watchers; }
    public Integer getTtl() { return ttl; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String domain;
        private JsonNode initialDocument;
        private List<String> updateKeys;
        private Signer signer;
        private boolean portable = false;
        private List<String> nextKeyHashes = List.of();
        private WitnessParameter witness;
        private List<String> watchers;
        private Integer ttl;  // null → use spec default

        private Builder() {}

        public Builder domain(String domain) {
            this.domain = domain;
            return this;
        }

        public Builder initialDocument(JsonNode initialDocument) {
            this.initialDocument = initialDocument;
            return this;
        }

        public Builder updateKeys(List<String> updateKeys) {
            this.updateKeys = updateKeys;
            return this;
        }

        public Builder signer(Signer signer) {
            this.signer = signer;
            return this;
        }

        public Builder portable(boolean portable) {
            this.portable = portable;
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

        public Builder ttl(Integer ttl) {
            this.ttl = ttl;
            return this;
        }

        public CreateOptions build() {
            return new CreateOptions(this);
        }
    }
}
