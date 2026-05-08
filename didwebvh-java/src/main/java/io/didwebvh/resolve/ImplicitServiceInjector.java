package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * Injects the two implicit {@code did:webvh} services into a resolved DID document.
 *
 * <p>The {@code did:webvh} specification (§6.5 and §6.6) defines two implicit
 * services that every DID automatically supports, even when the DID Controller
 * does not explicitly declare them in the DID document:
 * <ul>
 *   <li><b>{@code #files}</b> — a {@code relativeRef} service that enables
 *       DID URL path resolution (e.g. {@code did:.../path/to/file}).</li>
 *   <li><b>{@code #whois}</b> — a {@code LinkedVerifiablePresentation} service
 *       that resolves the special {@code /whois} path to a verifiable presentation.</li>
 * </ul>
 *
 * <p>If the DID document already contains an explicit service with
 * {@code id} {@code "#files"}, {@code "<did>#files"}, {@code "#whois"},
 * or {@code "<did>#whois"}, that explicit entry <b>MUST</b> override the
 * implicit one and is left untouched.</p>
 *
 * <p>This injection is performed <b>after</b> the log has been validated and
 * the DID document selected, but <b>before</b> fragment or path dereferencing.
 * It ensures that:
 * <ol>
 *   <li>Path resolution can always find a {@code #files} or {@code #whois}
 *       service to construct the target URL.</li>
 *   <li>Parallel {@code did:web} publishing (spec §6.7) has the required
 *       services available in the document.</li>
 * </ol>
 *
 * <p><b>Important:</b> The supplied {@code document} is mutated in-place.
 * Callers should pass a mutable {@link ObjectNode} (typically a deep copy of
 * the original log entry state) to avoid corrupting the cached log data.</p>
 *
 * @see DidUrlPathResolver
 * @see <a href="https://identity.foundation/linked-vp/">Linked Verifiable Presentation</a>
 */
public final class ImplicitServiceInjector {

    private static final String FILES_SERVICE_ID = "#files";
    private static final String WHOIS_SERVICE_ID = "#whois";
    private static final String LINKED_VP_CONTEXT = "https://identity.foundation/linked-vp/contexts/v1";

    private ImplicitServiceInjector() {}

    /**
     * Injects implicit {@code #files} and {@code #whois} services into the DID
     * document if they are not already explicitly defined.
     *
     * <p>The {@code serviceEndpoint} for both is derived from the DID's base URL
     * (see {@link DidUrlTransformer#toBaseUrl}). The {@code #whois} endpoint
     * additionally appends {@code whois.vp}.</p>
     *
     * @param document the resolved DID document; must be a mutable {@link ObjectNode}
     * @param did      the base DID string (used to construct absolute service IDs
     *                 and the base URL)
     */
    public static void inject(JsonNode document, String did) {
        if (!document.isObject()) {
            return;
        }
        ObjectNode doc = (ObjectNode) document;

        ArrayNode services;
        if (doc.has("service")) {
            JsonNode existing = doc.get("service");
            if (existing.isArray()) {
                services = (ArrayNode) existing;
            } else {
                // Non-array service field — wrap in array to keep it valid
                services = JsonNodeFactory.instance.arrayNode();
                services.add(existing);
                doc.set("service", services);
            }
        } else {
            services = doc.putArray("service");
        }

        boolean hasFiles = false;
        boolean hasWhois = false;

        for (JsonNode svc : services) {
            if (!svc.isObject()) continue;
            String id = svc.path("id").asText("");
            if (FILES_SERVICE_ID.equals(id) || (did + FILES_SERVICE_ID).equals(id)) {
                hasFiles = true;
            }
            if (WHOIS_SERVICE_ID.equals(id) || (did + WHOIS_SERVICE_ID).equals(id)) {
                hasWhois = true;
            }
        }

        String baseUrl = DidUrlTransformer.toBaseUrl(did);

        if (!hasFiles) {
            ObjectNode filesService = services.addObject();
            filesService.put("id", FILES_SERVICE_ID);
            filesService.put("type", "relativeRef");
            filesService.put("serviceEndpoint", baseUrl);
        }

        if (!hasWhois) {
            ObjectNode whoisService = services.addObject();
            whoisService.put("@context", LINKED_VP_CONTEXT);
            whoisService.put("id", WHOIS_SERVICE_ID);
            whoisService.put("type", "LinkedVerifiablePresentation");
            whoisService.put("serviceEndpoint", baseUrl + "whois.vp");
        }
    }
}
