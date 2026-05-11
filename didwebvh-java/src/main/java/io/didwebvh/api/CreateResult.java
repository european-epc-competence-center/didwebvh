package io.didwebvh.api;

import io.didwebvh.DidDocument;
import io.didwebvh.model.DidDocumentMetadata;
import io.didwebvh.model.DidLog;

/**
 * The result of a {@link DidWebVh#create} operation.
 *
 * @param did      the newly created DID string (with real SCID replacing {@code {SCID}})
 * @param document the resolved initial DID document
 * @param metadata the document metadata for the genesis entry
 * @param log      the single-entry log to be published as {@code did.jsonl}
 */
public record CreateResult(
        String did,
        DidDocument document,
        DidDocumentMetadata metadata,
        DidLog log
) {

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("CreateResult {\n");
        sb.append("  did:      ").append(did).append("\n");
        sb.append("  document: ").append(document).append("\n");
        if (metadata != null) {
            sb.append("  metadata: ").append(indent(metadata.toString(), "            ")).append("\n");
        }
        if (log != null) {
            sb.append("  log:      ").append(indent(log.toString(), "            ")).append("\n");
        }
        sb.append("}");
        return sb.toString();
    }

    /** Indents every line after the first by {@code prefix}. */
    private static String indent(String s, String prefix) {
        return s.replace("\n", "\n" + prefix);
    }
}
