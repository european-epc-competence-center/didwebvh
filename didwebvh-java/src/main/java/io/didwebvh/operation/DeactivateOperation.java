package io.didwebvh.operation;

import io.didwebvh.api.DeactivateOptions;
import io.didwebvh.api.DeactivateResult;

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
     * Appends a deactivation entry to the log supplied in {@code options}.
     *
     * @param options deactivation options (current log and signing key)
     * @return the result containing the updated log with the deactivation entry
     */
    public static DeactivateResult deactivate(DeactivateOptions options) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
