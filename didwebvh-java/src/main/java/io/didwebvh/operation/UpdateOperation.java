package io.didwebvh.operation;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;
import io.didwebvh.crypto.Signer;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.Parameters;

/**
 * Implements the did:webvh {@code Update} operation.
 *
 * <p>Appends a new log entry to an existing log following the spec §6.3 flow:
 * <ol>
 *   <li>Resolve the current state from the existing log (validates the full chain).</li>
 *   <li>Reject if the DID is deactivated.</li>
 *   <li>Compute the parameter delta: {@link Parameters#diff(Parameters)}.</li>
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
     * Appends an update entry to the given log.
     *
     * @param log             the current (validated) log
     * @param updatedDocument the new DID document state
     * @param paramsUpdate    parameter changes to apply ({@code null} if document-only update)
     * @param signer          the current update signing key
     * @param options         additional update options
     * @return the result containing the updated log
     * @implNote TODO: implement the full update flow
     */
    public static UpdateResult update(
            DidLog log,
            JsonNode updatedDocument,
            Parameters paramsUpdate,
            Signer signer,
            UpdateOptions options) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
