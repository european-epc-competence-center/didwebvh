package de.eecc.did.webvh.resolve;

import de.eecc.did.webvh.DidDocument;

import java.util.ArrayList;
import java.util.List;

/**
 * Injects the two implicit {@code did:webvh} services into a resolved DID document.
 *
 * <p>The {@code did:webvh} specification defines two implicit
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
     * @param document the resolved DID document
     * @param did      the base DID string (used to construct absolute service IDs
     *                 and the base URL)
     * @return a new DID document with implicit services injected
     */
    public static DidDocument inject(DidDocument document, String did) {
        if (!document.isObject()) {
            return document;
        }

        List<DidDocument> services = new ArrayList<>(document.getObjects("service"));

        boolean hasFiles = false;
        boolean hasWhois = false;

        for (DidDocument svc : services) {
            String id = svc.getString("id", "");
            if (FILES_SERVICE_ID.equals(id) || (did + FILES_SERVICE_ID).equals(id)) {
                hasFiles = true;
            }
            if (WHOIS_SERVICE_ID.equals(id) || (did + WHOIS_SERVICE_ID).equals(id)) {
                hasWhois = true;
            }
        }

        String baseUrl = DidUrlTransformer.toBaseUrl(did);

        if (!hasFiles) {
            DidDocument filesService = DidDocument.builder()
                    .setString("id", FILES_SERVICE_ID)
                    .setString("type", "relativeRef")
                    .setString("serviceEndpoint", baseUrl)
                    .build();
            services.add(filesService);
        }

        if (!hasWhois) {
            DidDocument whoisService = DidDocument.builder()
                    .setString("@context", LINKED_VP_CONTEXT)
                    .setString("id", WHOIS_SERVICE_ID)
                    .setString("type", "LinkedVerifiablePresentation")
                    .setString("serviceEndpoint", baseUrl + "whois.vp")
                    .build();
            services.add(whoisService);
        }

        return document.toBuilder().setObjects("service", services).build();
    }
}
