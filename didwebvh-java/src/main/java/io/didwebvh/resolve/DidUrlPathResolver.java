package io.didwebvh.resolve;

import io.didwebvh.DidDocument;
import io.didwebvh.exception.DidNotFoundException;
import io.didwebvh.exception.DidWebVhException;

import java.util.List;

/**
 * Resolves a DID URL path to a concrete HTTPS URL by looking up the
 * appropriate service in the DID document.
 *
 * <p>The {@code did:webvh} specification defines two kinds of DID URL paths:
 * <ul>
 *   <li><b>{@code /whois}</b> — resolves via the {@code #whois} service
 *       (implicit or explicit). The target URL is the service's
 *       {@code serviceEndpoint} directly.</li>
 *   <li><b>any other path</b> (e.g. {@code /governance/issuers.json}) —
 *       resolves via the {@code #files} service. The path is appended to
 *       the service's {@code serviceEndpoint}.</li>
 * </ul>
 *
 * <p>The DID document <b>must</b> already have implicit services injected
 * (see {@link ImplicitServiceInjector}) before this resolver is used,
 * otherwise the lookup will fail when no explicit service exists.</p>
 *
 * <p><b>Override semantics:</b> If the DID Controller defines an explicit
 * service with {@code id} {@code "#files"} or {@code "<did>#files"}, that
 * service's {@code serviceEndpoint} is used instead of the implicit one.
 * The same applies for {@code #whois}.</p>
 *
 * <p><b>URL construction rules:</b>
 * <ul>
 *   <li>For {@code #whois}: returns {@code serviceEndpoint} unchanged.</li>
 *   <li>For {@code #files}: returns {@code serviceEndpoint + relativePath},
 *       ensuring exactly one {@code /} between the endpoint and the path.</li>
 * </ul>
 */
public final class DidUrlPathResolver {

    private static final String FILES_SERVICE_ID = "#files";
    private static final String WHOIS_SERVICE_ID = "#whois";

    private DidUrlPathResolver() {}

    /**
     * Resolves a DID URL path to the HTTPS URL that should be fetched.
     *
     * @param document the resolved DID document (with implicit services injected)
     * @param did      the base DID string (used to match absolute service IDs)
     * @param path     the path from the DID URL (e.g. {@code "/whois"} or
     *                 {@code "/governance/issuers.json"})
     * @return the target HTTPS URL
     * @throws DidNotFoundException if the required service is not found in the document
     * @throws DidWebVhException    if the service entry is malformed (missing {@code serviceEndpoint})
     */
    public static String resolvePath(DidDocument document, String did, String path) {
        if ("/whois".equals(path)) {
            return resolveWhois(document, did);
        } else {
            return resolveFilesPath(document, did, path);
        }
    }

    private static String resolveWhois(DidDocument document, String did) {
        DidDocument service = findService(document, did, WHOIS_SERVICE_ID);
        if (service == null) {
            throw new DidNotFoundException(
                    "whois service not found in DID document for " + did);
        }
        String endpoint = service.getString("serviceEndpoint");
        if (endpoint == null || endpoint.isEmpty()) {
            throw new DidWebVhException(
                    "Missing or empty serviceEndpoint for whois service in " + did);
        }
        return endpoint;
    }

    private static String resolveFilesPath(DidDocument document, String did, String path) {
        DidDocument service = findService(document, did, FILES_SERVICE_ID);
        if (service == null) {
            throw new DidNotFoundException(
                    "files service not found in DID document for " + did);
        }
        String endpoint = service.getString("serviceEndpoint");
        if (endpoint == null || endpoint.isEmpty()) {
            throw new DidWebVhException(
                    "Missing or empty serviceEndpoint for files service in " + did);
        }

        // Ensure exactly one '/' between endpoint and path
        String base = endpoint.endsWith("/") ? endpoint : endpoint + "/";
        String relativePath = path.startsWith("/") ? path.substring(1) : path;
        return base + relativePath;
    }

    /**
     * Finds a service in the DID document by matching its {@code id} against
     * both the relative form ({@code "#files"}) and the absolute form
     * ({@code "<did>#files"}).
     *
     * @param document  the DID document
     * @param did       the base DID string
     * @param serviceId the relative service ID to look for (e.g. {@code "#files"})
     * @return the matching service node, or {@code null} if not found
     */
    private static DidDocument findService(DidDocument document, String did, String serviceId) {
        List<DidDocument> services = document.getObjects("service");
        for (DidDocument svc : services) {
            String id = svc.getString("id", "");
            if (serviceId.equals(id) || (did + serviceId).equals(id)) {
                return svc;
            }
        }
        return null;
    }
}
