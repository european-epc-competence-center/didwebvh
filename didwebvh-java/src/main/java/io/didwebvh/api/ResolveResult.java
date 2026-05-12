package io.didwebvh.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.didwebvh.DidDocument;
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
 * <p>For DID URL <b>dereferencing</b> (e.g. resolving {@code did:.../whois} or
 * {@code did:.../path/to/file}), the result carries the fetched resource content
 * in {@code contentStream} instead of a DID document.</p>
 *
 * <p>This design keeps {@code resolve()} as a single entry point. Callers can
 * distinguish the two cases by checking {@link #isSuccess()} and then inspecting
 * whether {@link #document()} (DID resolution) or {@link #contentStream()}
 * (dereferencing) is present.</p>
 *
 * <p>If resolution fails, {@code didDocument} and {@code contentStream} are
 * {@code null} and {@code didResolutionMetadata} contains an {@code error} code
 * and optional {@code problemDetails}.</p>
 *
 * @param did                the DID that was resolved
 * @param document           the resolved DID document
 * @param documentMetadata   metadata about the document
 * @param resolutionMetadata metadata about the resolution process
 * @param contentStream      dereferenced resource content, if a path was resolved
 */
public record ResolveResult(
        @JsonIgnore String did,
        @JsonInclude(JsonInclude.Include.ALWAYS)
        @JsonProperty("didDocument") DidDocument document,
        @JsonProperty("didDocumentMetadata") DidDocumentMetadata documentMetadata,
        @JsonProperty("didResolutionMetadata") ResolutionMetadata resolutionMetadata,
        @JsonInclude(JsonInclude.Include.NON_NULL)
        @JsonProperty("contentStream") String contentStream
) {

    /**
     * Backward-compatible constructor for normal DID resolution results.
     *
     * <p>When a DID is resolved without a path, only the DID document and its
     * metadata are returned. The {@code contentStream} is left {@code null}.</p>
     */
    public ResolveResult(String did, DidDocument document,
                          DidDocumentMetadata documentMetadata,
                          ResolutionMetadata resolutionMetadata) {
        this(did, document, documentMetadata, resolutionMetadata, null);
    }

    /**
     * Constructor for dereferencing results (path or {@code /whois} resolution).
     *
     * <p>When a DID URL with a path is resolved, the resolver fetches the
     * resource and returns it as {@code contentStream}. The DID document and
     * its metadata are omitted because the result is not a DID document.</p>
     */
    public ResolveResult(String did, ResolutionMetadata resolutionMetadata,
                          String contentStream) {
        this(did, null, DidDocumentMetadata.EMPTY, resolutionMetadata, contentStream);
    }

    /** Returns {@code true} if resolution or dereferencing succeeded. */
    @JsonIgnore
    public boolean isSuccess() {
        return (document != null || contentStream != null)
                && resolutionMetadata != null
                && resolutionMetadata.error() == null;
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
