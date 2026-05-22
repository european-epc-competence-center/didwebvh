package de.eecc.did.webvh.didweb;

import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.DidWebVhConstants;
import de.eecc.did.webvh.resolve.DidUrlTransformer;
import de.eecc.did.webvh.resolve.ImplicitServiceInjector;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Generates the parallel {@code did:web} DID document for a {@code did:webvh},
 * following the {@code did:webvh} specification §3.7.10 (Publishing a Parallel
 * {@code did:web} DID).
 *
 * <p>Publishing a {@code did:web} alongside a {@code did:webvh} lets resolvers that
 * do not understand {@code did:webvh} continue to resolve the controller's DID,
 * while {@code did:webvh}-aware clients can follow the {@code alsoKnownAs} link back
 * to the verifiable history. The trade-off is that {@code did:web} consumers lose
 * the verifiable properties of {@code did:webvh}.
 *
 * <p>The transformation, exactly as specified, is:
 * <ol>
 *   <li>Start with the resolved {@code did:webvh} DID document.</li>
 *   <li>Add the implicit {@code #files} and {@code #whois} services if not already
 *       present (a resolved document already has them, so this is idempotent).</li>
 *   <li>Text-replace {@code did:webvh:<scid>:} with {@code did:web:} across the
 *       whole document.</li>
 *   <li>Add the full {@code did:webvh} DID to {@code alsoKnownAs}.</li>
 *   <li>Remove duplicate {@code alsoKnownAs} entries, including the {@code did:web}
 *       DID itself if the replacement produced it.</li>
 * </ol>
 *
 * <p>This class performs no I/O. The caller publishes the returned document as
 * {@code did.json} at the same web location where {@code did.jsonl} is served (the
 * {@code did:web} DID-to-HTTPS transformation of the same domain and path).
 *
 * <p>Per the literal specification, the blanket prefix replacement also rewrites the
 * {@code controller} (and any other self-references) to {@code did:web}; the original
 * {@code did:webvh} identity is preserved via {@code alsoKnownAs}.
 */
public final class DidWebPublisher {

    private static final String DID_WEB_PREFIX = "did:web:";
    private static final String ALSO_KNOWN_AS = "alsoKnownAs";

    private DidWebPublisher() {}

    /**
     * Generates the parallel {@code did:web} document for a resolved {@code did:webvh}
     * document.
     *
     * @param resolvedWebVh the resolved {@code did:webvh} DID document (its {@code id}
     *                      must be a {@code did:webvh} DID)
     * @return the equivalent {@code did:web} document to publish as {@code did.json}
     * @throws IllegalArgumentException if the document has no {@code did:webvh} {@code id}
     */
    public static DidDocument toDidWeb(DidDocument resolvedWebVh) {
        String webVhDid = requireWebVhId(resolvedWebVh);
        String didWebDid = toDidWebId(webVhDid);

        // Step 2: ensure the implicit services are present (no-op for a resolved doc).
        DidDocument withServices = ImplicitServiceInjector.inject(resolvedWebVh, webVhDid);

        // Step 3: blanket text-replace did:webvh:<scid>: -> did:web: across the document.
        String scidPrefix = DidWebVhConstants.DID_METHOD_PREFIX
                + DidUrlTransformer.extractScid(webVhDid) + ":";
        String replaced = withServices.toJson().replace(scidPrefix, DID_WEB_PREFIX);
        DidDocument webDoc = DidDocument.fromJson(replaced);

        // Steps 4 & 5: add the did:webvh DID to alsoKnownAs, dedupe, drop the did:web self.
        return reconcileAliases(webDoc, webVhDid, didWebDid);
    }

    /**
     * Converts a {@code did:webvh} DID string to the equivalent {@code did:web} DID
     * by dropping the method's {@code <scid>:} element.
     *
     * @param webVhDid a {@code did:webvh} DID, e.g. {@code did:webvh:Qm...:example.com:dids:issuer}
     * @return the {@code did:web} DID, e.g. {@code did:web:example.com:dids:issuer}
     */
    public static String toDidWebId(String webVhDid) {
        String scidPrefix = DidWebVhConstants.DID_METHOD_PREFIX
                + DidUrlTransformer.extractScid(webVhDid) + ":";
        return DID_WEB_PREFIX + webVhDid.substring(scidPrefix.length());
    }

    // -------------------------------------------------------------------------

    private static String requireWebVhId(DidDocument document) {
        Objects.requireNonNull(document, "resolvedWebVh must not be null");
        String id = document.getString("id");
        if (id == null || !id.startsWith(DidWebVhConstants.DID_METHOD_PREFIX)) {
            throw new IllegalArgumentException(
                    "document id must be a did:webvh DID, but was: " + id);
        }
        return id;
    }

    /**
     * Adds the {@code did:webvh} DID to {@code alsoKnownAs}, removes duplicates, and
     * drops the {@code did:web} self-DID that the prefix replacement may have produced.
     */
    private static DidDocument reconcileAliases(DidDocument document, String webVhDid, String didWebDid) {
        List<String> aliases = new ArrayList<>();
        for (String alias : document.getStrings(ALSO_KNOWN_AS)) {
            if (!alias.equals(didWebDid) && !aliases.contains(alias)) {
                aliases.add(alias);
            }
        }
        if (!aliases.contains(webVhDid)) {
            aliases.add(webVhDid);
        }
        return document.toBuilder().setStrings(ALSO_KNOWN_AS, aliases).build();
    }
}
