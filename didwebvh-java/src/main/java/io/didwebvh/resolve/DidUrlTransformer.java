package io.didwebvh.resolve;

/**
 * Transforms a {@code did:webvh} DID into its corresponding HTTPS URL for log retrieval.
 *
 * <p>Transformation steps (spec §4.3):
 * <ol>
 *   <li>Remove the {@code did:webvh:} prefix.</li>
 *   <li>Remove the SCID segment (first colon-delimited segment).</li>
 *   <li>Decode percent-encoded port ({@code %3A} → {@code :}).</li>
 *   <li>Apply Unicode normalization (RFC 3491) and IDNA/Punycode (RFC 9233) to the domain.</li>
 *   <li>Percent-encode path segments (RFC 3986) and replace {@code :} with {@code /}.</li>
 *   <li>Reconstruct URL:
 *     <ul>
 *       <li>No path: {@code https://{domain}/.well-known/did.jsonl}</li>
 *       <li>With path: {@code https://{domain}/{path}/did.jsonl}</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code did:webvh:{SCID}:example.com} → {@code https://example.com/.well-known/did.jsonl}</li>
 *   <li>{@code did:webvh:{SCID}:example.com:dids:issuer} → {@code https://example.com/dids/issuer/did.jsonl}</li>
 *   <li>{@code did:webvh:{SCID}:example.com%3A3000} → {@code https://example.com:3000/.well-known/did.jsonl}</li>
 * </ul>
 */
public final class DidUrlTransformer {

    private DidUrlTransformer() {}

    /**
     * Transforms a {@code did:webvh} DID into the HTTPS URL for fetching {@code did.jsonl}.
     *
     * @param did the full DID string
     * @return the HTTPS URL string
     * @throws io.didwebvh.exception.InvalidDidException if the DID cannot be parsed
     * @implNote TODO: implement full transformation including IDNA normalization
     */
    public static String toLogUrl(String did) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Transforms the DID to the HTTPS URL for fetching {@code did-witness.json}.
     * Same as {@link #toLogUrl} but replaces {@code did.jsonl} with {@code did-witness.json}.
     *
     * @param did the full DID string
     * @return the HTTPS URL string for the witness file
     */
    public static String toWitnessUrl(String did) {
        // TODO: implement — derive from toLogUrl
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Extracts the SCID from the DID string (the segment immediately after {@code did:webvh:}).
     *
     * @param did the full DID string
     * @return the SCID string
     * @throws io.didwebvh.exception.InvalidDidException if the structure is invalid
     */
    public static String extractScid(String did) {
        // TODO: implement
        throw new UnsupportedOperationException("TODO");
    }
}
