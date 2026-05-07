package io.didwebvh.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.model.DidDocumentMetadata;
import io.didwebvh.model.ResolutionMetadata;



/**
 * The result of a {@link DidWebVh#resolve} or {@link DidWebVh#resolveFromLog} operation.
 *
 * <p>When serialized to JSON this object aligns with the W3C DID Resolution spec:
 * <ul>
 *   <li>{@code didDocument} — the resolved DID document (may be {@code null})</li>
 *   <li>{@code didDocumentMetadata} — metadata about the document</li>
 *   <li>{@code didResolutionMetadata} — metadata about the resolution process</li>
 * </ul>
 *
 * <p>If resolution fails, {@code didDocument} is {@code null} and
 * {@code didResolutionMetadata} contains an {@code error} code and optional
 * {@code problemDetails}.
 *
 * @param did                  the resolved DID string (ignored during JSON serialization)
 * @param document             the resolved DID document, or {@code null} on error
 * @param documentMetadata     metadata describing the DID document
 * @param resolutionMetadata   metadata describing the resolution process
 */
public record ResolveResult(
        @JsonIgnore String did,
        @JsonInclude(JsonInclude.Include.ALWAYS)
        @JsonProperty("didDocument") JsonNode document,
        @JsonProperty("didDocumentMetadata") DidDocumentMetadata documentMetadata,
        @JsonProperty("didResolutionMetadata") ResolutionMetadata resolutionMetadata
) {

    /** Returns {@code true} if resolution succeeded (no error in resolution metadata). */
    @JsonIgnore
    public boolean isSuccess() {
        return document != null && resolutionMetadata != null && resolutionMetadata.error() == null;
    }

    /**
     * JSON-LD context for the DID Resolution result.
     *
     * <p>This aligns with other did:webvh resolver implementations and JSON-LD
     * representations of the resolution output.
     */
    @JsonProperty("@context")
    public String context() {
        return "https://w3id.org/did-resolution/v1";
    }
}
