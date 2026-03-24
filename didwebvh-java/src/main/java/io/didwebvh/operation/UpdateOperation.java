package io.didwebvh.operation;

import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;

/**
 * Implements the did:webvh {@code Update} operation.
 *
 * <p>Appends a new log entry to an existing log following the spec §6.3 flow:
 * <ol>
 *   <li>Resolve the current state from the existing log (validates the full chain).</li>
 *   <li>Reject if the DID is deactivated.</li>
 *   <li>Compute the parameter delta between the active state and the requested options.</li>
 *   <li>Build the new entry: {@code versionId} = previous {@code versionId}, new
 *       {@code versionTime}, updated {@code state}, delta {@code parameters}.</li>
 *   <li>Compute the new entry hash and set {@code versionId = "{n+1}-{hash}"}.</li>
 *   <li>Generate a Data Integrity proof with the active signing key.</li>
 *   <li>Return the log with the new entry appended.</li>
 * </ol>
 */
public final class UpdateOperation {

    private UpdateOperation() {}

    /**
     * Appends an update entry to the log supplied in {@code options}.
     *
     * @param options update options (current log, new document, signer, and any parameter changes)
     * @return the result containing the updated log
     */
    public static UpdateResult update(UpdateOptions options) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
