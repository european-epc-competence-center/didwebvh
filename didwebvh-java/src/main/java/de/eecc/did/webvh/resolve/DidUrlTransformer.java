package de.eecc.did.webvh.resolve;

import de.eecc.did.webvh.DidWebVhConstants;
import de.eecc.did.webvh.exception.InvalidDidException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
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
 *   <li>Apply IDNA2003 ToASCII (RFC 3490, including Nameprep RFC 3491) to the domain via {@link IDN#toASCII}.</li>
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
     * The host and ordered path segments parsed (and validated) out of a DID's
     * method-specific identifier.
     */
    private record Location(String host, String[] pathSegments) {}

    /**
     * Parses and validates the location (host + path segments) from a DID, applying
     * the spec transformation and rejecting identifiers the spec forbids.
     *
     * <p>Validation performed (each surfaced as {@link InvalidDidException}):
     * <ul>
     *   <li>Host MUST NOT be an IP address (spec: "it MUST NOT include IP addresses"),
     *       checked after percent-decoding so e.g. {@code 127%2E0%2E0%2E1} cannot smuggle one.</li>
     *   <li>Host MUST NOT contain URL-structural characters ({@code # / \ ? @} or whitespace),
     *       which would otherwise let a fragment or path leak into the domain segment.</li>
     *   <li>Each path segment, after percent-decoding, MUST NOT be empty, {@code .}, {@code ..},
     *       or contain a {@code /} or {@code \} (path-traversal defence).</li>
     * </ul>
     */
    private static Location parseLocation(String did) {
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

        // Path segments live in parts[2..]; validate each before they become URL path components
        String[] pathSegments = Arrays.copyOfRange(parts, 2, parts.length);
        for (String segment : pathSegments) {
            validatePathSegment(segment, did);
        }
        return new Location(host, pathSegments);
    }

    /**
     * Builds the base HTTPS URL (without the filename) for the given DID.
     * The returned string ends with the last path segment, before the "/" + "filename".
     */
    private static String buildBaseUrl(String did) {
        Location loc = parseLocation(did);

        if (loc.pathSegments().length == 0) {
            return "https://" + loc.host() + "/" + DidWebVhConstants.WELL_KNOWN_PATH;
        }

        StringBuilder sb = new StringBuilder("https://").append(loc.host());
        for (String segment : loc.pathSegments()) {
            // Percent-encode each path segment and append with '/' separator
            sb.append('/').append(percentEncodeSegment(segment));
        }
        return sb.toString();
    }

    /**
     * Applies IDNA normalization to a host string that may include a port, after
     * validating that the host is neither an IP address nor carries URL-structural
     * characters.
     * E.g. {@code münchen.de} → {@code xn--mnchen-3ya.de},
     *      {@code example.com:3000} → {@code example.com:3000}.
     */
    private static String normalizeHost(String hostWithOptionalPort, String did) {
        int portSep = hostWithOptionalPort.indexOf(':');
        String hostPart = portSep >= 0 ? hostWithOptionalPort.substring(0, portSep) : hostWithOptionalPort;
        String portPart = portSep >= 0 ? hostWithOptionalPort.substring(portSep + 1) : null;

        validateHostName(hostPart, did);

        String ascii;
        try {
            ascii = IDN.toASCII(hostPart);
        } catch (IllegalArgumentException e) {
            throw new InvalidDidException("Invalid host in DID: " + did, e);
        }
        return portPart != null ? ascii + ":" + portPart : ascii;
    }

    /**
     * Rejects host segments the spec forbids: IP addresses and hosts carrying
     * characters that would alter the URL structure (a leaked fragment or path).
     */
    private static void validateHostName(String host, String did) {
        if (host.isEmpty()) {
            throw new InvalidDidException("Host segment is empty in DID: " + did);
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c == '#' || c == '/' || c == '\\' || c == '?' || c == '@' || Character.isWhitespace(c)) {
                throw new InvalidDidException("Invalid character '" + c + "' in host of DID: " + did);
            }
        }
        // Spec: the domain MUST NOT be an IP address. Percent-decode first so that
        // encodings such as 127%2E0%2E0%2E1 cannot smuggle an IP literal past this check.
        if (isIpLiteral(percentDecode(host))) {
            throw new InvalidDidException("Host must not be an IP address in DID: " + did);
        }
    }

    /**
     * Rejects path segments that are empty, dot-segments ({@code .} / {@code ..}), or
     * contain a path separator — guarding against path traversal both directly and via
     * percent-encoding (e.g. {@code %2E%2E} → {@code ..}).
     */
    private static void validatePathSegment(String segment, String did) {
        String decoded = percentDecode(segment);
        if (decoded.isEmpty() || decoded.equals(".") || decoded.equals("..")
                || decoded.indexOf('/') >= 0 || decoded.indexOf('\\') >= 0) {
            throw new InvalidDidException("Invalid path segment '" + segment + "' in DID: " + did);
        }
    }

    /**
     * Decodes {@code %XX} percent-escapes in a string as UTF-8, leaving any other
     * characters (including {@code +}) untouched. Malformed escapes are passed through
     * literally.
     */
    private static String percentDecode(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) + lo);
                    i += 2;
                    continue;
                }
            }
            // Pass non-escape bytes through as UTF-8.
            byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
            out.write(bytes, 0, bytes.length);
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    /** Returns true if the host is an IPv4 dotted-quad or a bracketed IPv6 literal. */
    private static boolean isIpLiteral(String host) {
        return host.startsWith("[") || isIpv4Literal(host);
    }

    private static boolean isIpv4Literal(String host) {
        String[] octets = host.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                return false;
            }
            for (int i = 0; i < octet.length(); i++) {
                if (!Character.isDigit(octet.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * Percent-encodes a single DID path segment per RFC 3986.
     * Uses UTF-8 encoding; spaces (if any) are encoded as {@code %20}, not {@code +}.
     */
    private static String percentEncodeSegment(String segment) {
        return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * Extracts the fragment from a DID URL — the substring starting with {@code #}.
     *
     * <p>Example: {@code did:webvh:{SCID}:example.com#key-1} → {@code "#key-1"}.
     *
     * @param didUrl the DID URL string (may include a fragment)
     * @return the fragment including the leading {@code #}, or {@code null} if absent
     */
    public static String extractFragment(String didUrl) {
        if (didUrl == null) return null;
        int idx = didUrl.indexOf('#');
        return idx >= 0 ? didUrl.substring(idx) : null;
    }

    /**
     * Strips the fragment (and leading {@code #}) from a DID URL.
     * Returns the input unchanged if no fragment is present.
     *
     * <p>Example: {@code did:webvh:{SCID}:example.com#key-1} → {@code did:webvh:{SCID}:example.com}.
     *
     * @param didUrl the DID URL string (may include a fragment)
     * @return the DID URL without the fragment
     */
    public static String stripFragment(String didUrl) {
        if (didUrl == null) return null;
        int idx = didUrl.indexOf('#');
        return idx >= 0 ? didUrl.substring(0, idx) : didUrl;
    }

    /**
     * Extracts the path from a DID URL — everything from the first {@code /} to
     * the next {@code #} (or end of string).
     *
     * <p>In a DID URL such as {@code did:webvh:{SCID}:example.com/whois} or
     * {@code did:webvh:{SCID}:example.com/governance/issuers.json}, the path
     * is the part after the method-specific identifier.
     *
     * <p>Example: {@code did:webvh:{SCID}:example.com/whois#fragment} → {@code "/whois"}.
     *
     * @param didUrl the DID URL string (may include a path and/or fragment)
     * @return the path including the leading {@code /}, or {@code null} if absent
     */
    public static String extractPath(String didUrl) {
        if (didUrl == null) return null;
        int slashIdx = didUrl.indexOf('/');
        if (slashIdx >= 0) {
            int hashIdx = didUrl.indexOf('#', slashIdx);
            if (hashIdx >= 0) {
                return didUrl.substring(slashIdx, hashIdx);
            }
            return didUrl.substring(slashIdx);
        }
        return null;
    }

    /**
     * Strips the path from a DID URL, returning just the DID (without path or fragment).
     *
     * <p>Example: {@code did:webvh:{SCID}:example.com/whois} → {@code did:webvh:{SCID}:example.com}.
     *
     * @param didUrl the DID URL string (may include a path)
     * @return the DID without the path
     */
    public static String stripPath(String didUrl) {
        if (didUrl == null) return null;
        int slashIdx = didUrl.indexOf('/');
        if (slashIdx >= 0) {
            return didUrl.substring(0, slashIdx);
        }
        return didUrl;
    }

    /**
     * Strips both path and fragment from a DID URL, returning the clean base DID.
     *
     * <p>This is a convenience combining {@link #stripPath(String)} and
     * {@link #stripFragment(String)}.
     *
     * @param didUrl the DID URL string (may include path and/or fragment)
     * @return the base DID without path or fragment
     */
    public static String stripPathAndFragment(String didUrl) {
        return stripFragment(stripPath(didUrl));
    }

    /**
     * Returns the base HTTPS URL for implicit service endpoints.
     *
     * <p>Unlike {@link #toLogUrl}, this <b>excludes</b> {@code .well-known/}
     * and the filename. It produces the directory prefix that implicit
     * {@code #files} and {@code #whois} services use as their
     * {@code serviceEndpoint}.</p>
     *
     * <p>Per spec §3.4 (DID-to-HTTPS transformation for paths):
     * <ul>
     *   <li>{@code did:webvh:{SCID}:example.com} → {@code https://example.com/}</li>
     *   <li>{@code did:webvh:{SCID}:example.com:dids:issuer} → {@code https://example.com/dids/issuer/}</li>
     * </ul>
     *
     * @param did the full DID string (without path or fragment)
     * @return the base HTTPS URL ending with {@code /}
     * @throws InvalidDidException if the DID cannot be parsed
     */
    public static String toBaseUrl(String did) {
        Location loc = parseLocation(did);

        StringBuilder sb = new StringBuilder("https://").append(loc.host());
        for (String segment : loc.pathSegments()) {
            sb.append('/').append(percentEncodeSegment(segment));
        }
        sb.append('/');
        return sb.toString();
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
