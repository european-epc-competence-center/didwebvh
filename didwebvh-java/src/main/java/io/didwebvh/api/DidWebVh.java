package io.didwebvh.api;

import io.didwebvh.model.DidLog;
import io.didwebvh.operation.CreateOperation;
import io.didwebvh.operation.DeactivateOperation;
import io.didwebvh.operation.UpdateOperation;
import io.didwebvh.resolve.HttpResolver;

/**
 * Main entry point for the did:webvh Java library.
 *
 * <p>All four DID operations are available as static methods:
 * <ul>
 *   <li>{@link #create} — generate a new DID with a genesis log entry</li>
 *   <li>{@link #resolve} — fetch and verify a DID over HTTPS</li>
 *   <li>{@link #update} — append an update entry to the log</li>
 *   <li>{@link #deactivate} — append a deactivation entry to the log</li>
 * </ul>
 *
 * <p>Every operation accepts a single options object that bundles all inputs including
 * the signing or verification key. The internal log {@code parameters} structure is
 * assembled by the library — callers never need to construct a {@code Parameters}
 * object directly.
 */
public final class DidWebVh {

    private DidWebVh() {}

    // -------------------------------------------------------------------------
    // Create (Register)
    // -------------------------------------------------------------------------

    /**
     * Creates a new DID and returns the genesis log entry.
     *
     * <p>The library generates the SCID, builds the internal log entry, and signs it.
     * The caller is responsible for publishing the resulting {@code did.jsonl} (and
     * {@code did-witness.json} if witnesses are configured).
     *
     * @param options creation options including domain, initial document, update keys, and signer
     * @return the creation result containing the DID string, document, metadata, and log
     */
    public static CreateResult create(CreateOptions options) {
        return CreateOperation.create(options);
    }

    // -------------------------------------------------------------------------
    // Read (Resolve)
    // -------------------------------------------------------------------------

    /**
     * Resolves a DID by fetching {@code did.jsonl} over HTTPS.
     *
     * @param did     the full DID string (e.g. {@code did:webvh:{SCID}:example.com})
     * @param options resolution options including the verifier and optional version filters;
     *                supply only a verifier for the latest version
     * @return the resolution result; errors are encoded in {@link ResolveResult#metadata()}
     */
    public static ResolveResult resolve(String did, ResolveOptions options) {
        return new HttpResolver().resolve(did, options);
    }

    // -------------------------------------------------------------------------
    // Update (Rotate)
    // -------------------------------------------------------------------------

    /**
     * Appends an update entry to the log.
     *
     * <p>Only supply {@code updateKeys}, {@code nextKeyHashes}, {@code witness}, or
     * {@code watchers} in the options when those aspects of the DID are actually changing;
     * unchanged fields are inherited from the previous log entry automatically.
     *
     * @param log     the current (validated) log
     * @param options update options including the new document and signing key
     * @return the update result containing the extended log
     */
    public static UpdateResult update(DidLog log, UpdateOptions options) {
        return UpdateOperation.update(log, options);
    }

    // -------------------------------------------------------------------------
    // Deactivate (Revoke)
    // -------------------------------------------------------------------------

    /**
     * Appends a deactivation entry to the log.
     *
     * <p>After deactivation, resolvers will not return the DID document and will
     * include {@code deactivated: true} in the resolution metadata.
     *
     * @param log     the current (validated) log
     * @param options deactivation options including the signing key
     * @return the deactivation result containing the updated log
     */
    public static DeactivateResult deactivate(DidLog log, DeactivateOptions options) {
        return DeactivateOperation.deactivate(log, options);
    }
}
