package io.didwebvh.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.crypto.Signer;
import io.didwebvh.crypto.Verifier;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.Parameters;
import io.didwebvh.operation.CreateOperation;
import io.didwebvh.operation.DeactivateOperation;
import io.didwebvh.operation.UpdateOperation;
import io.didwebvh.resolve.HttpResolver;
import io.didwebvh.resolve.LogBasedResolver;

/**
 * Main entry point for the did:webvh Java library.
 *
 * <p>All four DID operations are available as static methods:
 * <ul>
 *   <li>{@link #create} — generate a new DID with a genesis log entry</li>
 *   <li>{@link #resolve} — fetch and verify a DID over HTTPS</li>
 *   <li>{@link #resolveFromLog} — verify a DID from an in-memory log (no network)</li>
 *   <li>{@link #update} — append an update entry to the log</li>
 *   <li>{@link #deactivate} — append a deactivation entry to the log</li>
 * </ul>
 *
 * <p>Callers are responsible for supplying their own {@link Signer} and {@link Verifier}
 * implementations backed by the key material of their choice.
 */
public final class DidWebVh {

    private DidWebVh() {}

    // -------------------------------------------------------------------------
    // Create
    // -------------------------------------------------------------------------

    /**
     * Creates a new DID and returns the genesis log entry.
     *
     * @param initialDocument the initial DID document (may contain {@code {SCID}} placeholders)
     * @param initialParams   initial parameters ({@code method}, {@code updateKeys}, etc.)
     * @param signer          the signing key; its public key must be listed in
     *                        {@code initialParams.updateKeys()}
     * @param options         creation options (domain, portable, witnesses, watchers)
     * @return the creation result containing the DID string, document, metadata, and log
     */
    public static CreateResult create(
            JsonNode initialDocument,
            Parameters initialParams,
            Signer signer,
            CreateOptions options) {
        return CreateOperation.create(initialDocument, initialParams, signer, options);
    }

    // -------------------------------------------------------------------------
    // Resolve
    // -------------------------------------------------------------------------

    /**
     * Resolves a DID by fetching {@code did.jsonl} over HTTPS.
     *
     * @param did      the full DID string (e.g. {@code did:webvh:{SCID}:example.com})
     * @param verifier the verifier used to validate Data Integrity proofs
     * @param options  resolution options (version filters, etc.)
     * @return the resolution result; errors are encoded in {@link ResolveResult#metadata()}
     */
    public static ResolveResult resolve(String did, Verifier verifier, ResolveOptions options) {
        return new HttpResolver(verifier).resolve(did, options);
    }

    /**
     * Resolves a DID from an already-fetched {@link DidLog} without any network access.
     *
     * @param did      the DID string (used to verify the {@code id} field of the document)
     * @param log      the pre-parsed log
     * @param verifier the verifier used to validate Data Integrity proofs
     * @param options  resolution options
     * @return the resolution result
     */
    public static ResolveResult resolveFromLog(
            String did,
            DidLog log,
            Verifier verifier,
            ResolveOptions options) {
        return new LogBasedResolver(verifier).resolveFromLog(did, log, options);
    }

    // -------------------------------------------------------------------------
    // Update
    // -------------------------------------------------------------------------

    /**
     * Appends an update entry to the log.
     *
     * @param log             the current (validated) log
     * @param updatedDocument the new DID document state
     * @param paramsUpdate    parameter changes ({@code null} for a document-only update)
     * @param signer          the current update signing key
     * @param options         update options (key rotation, witness proofs, etc.)
     * @return the update result containing the new log
     */
    public static UpdateResult update(
            DidLog log,
            JsonNode updatedDocument,
            Parameters paramsUpdate,
            Signer signer,
            UpdateOptions options) {
        return UpdateOperation.update(log, updatedDocument, paramsUpdate, signer, options);
    }

    // -------------------------------------------------------------------------
    // Deactivate
    // -------------------------------------------------------------------------

    /**
     * Appends a deactivation entry to the log.
     *
     * @param log     the current (validated) log
     * @param signer  the current update signing key
     * @param options deactivation options
     * @return the deactivation result containing the updated log
     */
    public static DeactivateResult deactivate(
            DidLog log,
            Signer signer,
            DeactivateOptions options) {
        return DeactivateOperation.deactivate(log, signer, options);
    }
}
