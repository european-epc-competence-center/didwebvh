package io.didwebvh.resolve;

import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;

/**
 * Resolves a {@code did:webvh} DID and returns the DID document with metadata.
 *
 * <p>Implementations differ in how they obtain the raw log content:
 * <ul>
 *   <li>{@link LogBasedResolver} — resolves from an in-memory {@code DidLog} (no network)</li>
 *   <li>{@link HttpResolver} — fetches {@code did.jsonl} via HTTPS, then delegates to
 *       {@link LogBasedResolver}</li>
 * </ul>
 */
public interface DidResolver {

    /**
     * Resolves the given DID and returns the DID document and metadata.
     *
     * @param did     the full DID string (e.g. {@code did:webvh:{SCID}:example.com})
     * @param options resolution options (version filters, etc.)
     * @return the resolution result; never {@code null}; errors are encoded in
     *         {@link ResolveResult#metadata()}
     */
    ResolveResult resolve(String did, ResolveOptions options);
}
