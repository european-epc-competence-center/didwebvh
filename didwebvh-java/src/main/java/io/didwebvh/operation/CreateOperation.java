package io.didwebvh.operation;

import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;

/**
 * Implements the did:webvh {@code Create} operation.
 *
 * <p>Produces a genesis log entry following the spec §6.1 flow:
 * <ol>
 *   <li>Build a preliminary log entry with {@code {SCID}} placeholders and no proof.</li>
 *   <li>Compute the SCID: {@code base58btc(multihash(JCS(preliminary_entry)))}.</li>
 *   <li>Replace all {@code {SCID}} placeholders with the real SCID.</li>
 *   <li>Compute the entry hash and set {@code versionId = "1-{entryHash}"}.</li>
 *   <li>Generate a Data Integrity proof signed by the first {@code updateKeys} key.</li>
 *   <li>Append the proof to the entry and return a single-entry log.</li>
 * </ol>
 *
 * <p>No I/O is performed. The caller is responsible for publishing the resulting
 * {@code did.jsonl} and, if witnesses are configured, the {@code did-witness.json}.
 */
public final class CreateOperation {

    private CreateOperation() {}

    /**
     * Creates the genesis DID log entry.
     *
     * @param options creation options (domain, initial document, update keys, signer, etc.)
     * @return the result containing the DID string, resolved document, metadata, and single-entry log
     */
    public static CreateResult create(CreateOptions options) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
