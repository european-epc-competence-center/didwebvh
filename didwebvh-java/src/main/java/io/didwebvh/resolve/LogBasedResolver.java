package io.didwebvh.resolve;

import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;
import io.didwebvh.model.DidLog;

/**
 * Resolves a DID from an in-memory {@link DidLog} without any network access.
 *
 * <p>This is the core resolution engine:
 * <ol>
 *   <li>Runs {@link io.didwebvh.log.LogValidator} to validate the full chain.</li>
 *   <li>Applies version filters from {@link ResolveOptions}
 *       ({@code versionId}, {@code versionTime}, {@code versionNumber}).</li>
 *   <li>Returns the DID document at the requested version (latest if unspecified).</li>
 *   <li>Populates {@link io.didwebvh.model.ResolutionMetadata}.</li>
 * </ol>
 *
 * <p>The {@link io.didwebvh.crypto.Verifier} used for proof validation is taken from
 * {@link ResolveOptions#getVerifier()}.
 *
 * <p>This class is intentionally not exposed on the {@link io.didwebvh.api.DidWebVh}
 * facade. Advanced callers may use it directly when they have already obtained the log
 * through a non-HTTP channel.
 */
public final class LogBasedResolver implements DidResolver {

    public LogBasedResolver() {}

    /**
     * Resolves the DID from the given pre-fetched log.
     *
     * @param did     the DID string (used to verify the {@code id} field of the resolved document)
     * @param log     the pre-parsed log
     * @param options resolution options including the verifier and optional version filters
     * @return the resolution result
     */
    public ResolveResult resolveFromLog(String did, DidLog log, ResolveOptions options) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public ResolveResult resolve(String did, ResolveOptions options) {
        // TODO: implement — called when the caller supplies the log out-of-band
        throw new UnsupportedOperationException("TODO");
    }
}
