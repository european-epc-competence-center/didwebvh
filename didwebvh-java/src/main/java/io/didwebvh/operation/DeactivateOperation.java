package io.didwebvh.operation;

import io.didwebvh.api.DeactivateOptions;
import io.didwebvh.api.DeactivateResult;
import io.didwebvh.crypto.Signer;
import io.didwebvh.model.DidLog;

/**
 * Implements the did:webvh {@code Deactivate} operation.
 *
 * <p>Appends a deactivation entry to the log per spec §6.4:
 * <ul>
 *   <li>Sets {@code parameters.deactivated = true}.</li>
 *   <li>Sets {@code parameters.updateKeys = []} (empty — no further updates possible).</li>
 *   <li>Retains the current DID document state.</li>
 * </ul>
 *
 * <p>If pre-rotation is active, two entries are required:
 * first an entry to stop pre-rotation ({@code nextKeyHashes: []}),
 * then this deactivation entry. That two-step flow is the caller's responsibility.
 */
public final class DeactivateOperation {

    private DeactivateOperation() {}

    /**
     * Appends a deactivation entry to the given log.
     *
     * @param log     the current (validated) log
     * @param signer  the current update signing key (for the last authorized proof)
     * @param options additional options
     * @return the result containing the updated log with the deactivation entry
     * @implNote TODO: implement the deactivate flow
     */
    public static DeactivateResult deactivate(
            DidLog log,
            Signer signer,
            DeactivateOptions options) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
