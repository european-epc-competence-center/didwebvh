package io.didwebvh.api;

import io.didwebvh.DidDocument;
import io.didwebvh.model.DidDocumentMetadata;
import io.didwebvh.model.DidLog;

/**
 * The result of a {@link DidWebVh#update} operation.
 *
 * @param document the updated DID document
 * @param metadata the document metadata for the new log entry
 * @param log      the full updated log (existing entries + new entry) to replace {@code did.jsonl}
 */
public record UpdateResult(
        DidDocument document,
        DidDocumentMetadata metadata,
        DidLog log
) {}
