package io.didwebvh.resolve;

import io.didwebvh.DidWebVhConstants;
import io.didwebvh.exception.InvalidDidException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.IDN;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Transforms a {@code did:webvh} DID into its corresponding HTTPS URL for log retrieval.
 *
 * <p>Transformation steps (spec §3.4):
 * <ol>
 *   <li>Remove the {@code did:webvh:} prefix.</li>
 *   <li>Remove the SCID segment (first colon-delimited segment).</li>
 *   <li>Decode percent-encoded port ({@code %3A} → {@code :}).</li>
 *   <li>Apply Unicode normalization (RFC 3491) and IDNA/Punycode (RFC 9233) to the domain via {@link IDN#toASCII}.</li>
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
 *   <li>{@code did:webvh:{SCID}:münchen.de} → {@code https://xn--mnchen-3ya.de/.well-known/did.jsonl}</li>
 * </ul>
 */
public final class DidUrlTransformer {

    private static final Logger log = LoggerFactory.getLogger(DidUrlTransformer.class);

    private DidUrlTransformer() {}

    /**
     * Transforms a {@code did:webvh} DID into the HTTPS URL for fetching {@code did.jsonl}.
     *
     * @param did the full DID string
     * @return the HTTPS URL string
     * @throws InvalidDidException if the DID cannot be parsed
     */
    public static String toLogUrl(String did) {
        log.trace("Transforming DID to log URL: {}", did);
        String url = buildBaseUrl(did) + "/" + DidWebVhConstants.DID_LOG_FILENAME;
        log.trace("Resolved log URL for {}: {}", did, url);
        return url;
    }

    /**
     * Transforms the DID to the HTTPS URL for fetching {@code did-witness.json}.
     * Identical to {@link #toLogUrl} but appends {@code did-witness.json} instead.
     *
     * @param did the full DID string
     * @return the HTTPS URL string for the witness file
     * @throws InvalidDidException if the DID cannot be parsed
     */
    public static String toWitnessUrl(String did) {
        log.trace("Transforming DID to witness URL: {}", did);
        String url = buildBaseUrl(did) + "/" + DidWebVhConstants.WITNESS_FILENAME;
        log.trace("Resolved witness URL for {}: {}", did, url);
        return url;
    }

    /**
     * Extracts the SCID from the DID string (the segment immediately after {@code did:webvh:}).
     *
     * @param did the full DID string
     * @return the SCID string
     * @throws InvalidDidException if the structure is invalid
     */
    public static String extractScid(String did) {
        log.trace("Extracting SCID from DID: {}", did);
        validatePrefix(did);
        String withoutPrefix = did.substring(DidWebVhConstants.DID_METHOD_PREFIX.length());
        int colonIdx = withoutPrefix.indexOf(':');
        if (colonIdx < 0) {
            throw new InvalidDidException("DID has no SCID segment: " + did);
        }
        String scid = withoutPrefix.substring(0, colonIdx);
        if (scid.isEmpty()) {
            throw new InvalidDidException("SCID segment is empty in DID: " + did);
        }
        log.trace("Extracted SCID '{}' from DID: {}", scid, did);
        return scid;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Builds the base HTTPS URL (without the filename) for the given DID.
     * The returned string ends with the last path segment, before the "/" + "filename".
     */
    private static String buildBaseUrl(String did) {
        validatePrefix(did);
        String withoutPrefix = did.substring(DidWebVhConstants.DID_METHOD_PREFIX.length());

        // Split on ':' — parts[0] is SCID, parts[1] is host segment, parts[2..] are path segments
        String[] parts = withoutPrefix.split(":", -1);
        if (parts.length < 2) {
            throw new InvalidDidException("DID must have at least a SCID and host segment: " + did);
        }
        if (parts[1].isEmpty()) {
            throw new InvalidDidException("Host segment is empty in DID: " + did);
        }

        // Decode percent-encoded port (%3A / %3a → ':') in the host segment
        String hostSegment = parts[1].replace("%3A", ":").replace("%3a", ":");

        // Apply Unicode normalization and IDNA/Punycode to the hostname only (not the port)
        String host = normalizeHost(hostSegment, did);

        // Path segments live in parts[2..]; replace ':' separator with '/'
        String[] pathSegments = Arrays.copyOfRange(parts, 2, parts.length);

        if (pathSegments.length == 0) {
            return "https://" + host + "/" + DidWebVhConstants.WELL_KNOWN_PATH;
        }

        StringBuilder sb = new StringBuilder("https://").append(host);
        for (String segment : pathSegments) {
            // Percent-encode each path segment and append with '/' separator
            sb.append('/').append(percentEncodeSegment(segment));
        }
        return sb.toString();
    }

    /**
     * Applies IDNA normalization to a host string that may include a port.
     * E.g. {@code münchen.de} → {@code xn--mnchen-3ya.de},
     *      {@code example.com:3000} → {@code example.com:3000}.
     */
    private static String normalizeHost(String hostWithOptionalPort, String did) {
        int portSep = hostWithOptionalPort.indexOf(':');
        if (portSep >= 0) {
            // If port is present, only apply IDNA to the host part, not the port
            String hostPart = hostWithOptionalPort.substring(0, portSep);
            String portPart = hostWithOptionalPort.substring(portSep + 1);
            try {
                return IDN.toASCII(hostPart) + ":" + portPart;
            } catch (IllegalArgumentException e) {
                throw new InvalidDidException("Invalid host in DID: " + did, e);
            }
        }
        try {
            return IDN.toASCII(hostWithOptionalPort);
        } catch (IllegalArgumentException e) {
            throw new InvalidDidException("Invalid host in DID: " + did, e);
        }
    }

    /**
     * Percent-encodes a single DID path segment per RFC 3986.
     * Uses UTF-8 encoding; spaces (if any) are encoded as {@code %20}, not {@code +}.
     */
    private static String percentEncodeSegment(String segment) {
        return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * Validates that the DID string starts with the expected {@code did:webvh:} prefix.
     * @param did the full DID string to validate
     * @throws InvalidDidException if the prefix is missing or null
     */
    private static void validatePrefix(String did) {
        if (did == null || !did.startsWith(DidWebVhConstants.DID_METHOD_PREFIX)) {
            throw new InvalidDidException("Not a did:webvh DID: " + did);
        }
    }
}
