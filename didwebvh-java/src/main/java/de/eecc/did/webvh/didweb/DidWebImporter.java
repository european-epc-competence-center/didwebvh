package de.eecc.did.webvh.didweb;

import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.DidWebVhConstants;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Converts an existing {@code did:web} DID document into a {@code did:webvh}
 * genesis document suitable for {@link de.eecc.did.webvh.api.DidWebVh#create}.
 *
 * <p>The {@code did:webvh} specification notes that the two methods are "almost
 * identical, with changes only to the DID Method ({@code webvh} instead of
 * {@code web}), and the addition of the {@code <scid>:} element". Importing an
 * existing {@code did:web} document therefore reduces to two mechanical steps:
 * <ol>
 *   <li>Rewrite every reference to the document's own {@code did:web:<domain>}
 *       identifier (the {@code id}, {@code controller}, verification-method IDs,
 *       service IDs, fragments, and same-domain paths) to
 *       {@code did:webvh:{SCID}:<domain>}. The literal {@code {SCID}} placeholder
 *       is later replaced with the computed SCID by the create operation.</li>
 *   <li>Record the original {@code did:web} DID in {@code alsoKnownAs} so the
 *       equivalence between the two identifiers is declared in the document.</li>
 * </ol>
 *
 * <p>References to <em>other</em> {@code did:web} DIDs (for example an external
 * controller or an unrelated {@code alsoKnownAs} entry) are left untouched: only
 * the document's own identifier and identifiers derived from it are rewritten.
 *
 * <p>This class performs no I/O and never computes the SCID; it only prepares the
 * {@code initialDocument}. Typical usage:
 * <pre>{@code
 * DidDocument didWeb = DidDocument.fromJson(existingDidJson);
 * DidDocument genesis = DidWebImporter.toWebVhDocument(didWeb);
 *
 * CreateResult result = DidWebVh.create(
 *     CreateOptions.builder()
 *         .domain(DidWebImporter.domainOf(didWeb))   // e.g. "example.com:dids:issuer"
 *         .initialDocument(genesis)
 *         .updateKeys(List.of(publicKeyMultibase))
 *         .signer(signer)
 *         .build());
 * }</pre>
 */
public final class DidWebImporter {

    private static final String DID_WEB_PREFIX = "did:web:";

    private DidWebImporter() {}

    /**
     * Converts a {@code did:web} document into a {@code did:webvh} genesis document,
     * recording the original {@code did:web} DID in {@code alsoKnownAs}.
     *
     * @param didWebDocument an existing {@code did:web} DID document
     * @return a genesis document whose {@code id} uses the {@code {SCID}} placeholder,
     *         ready for {@link de.eecc.did.webvh.api.DidWebVh#create}
     * @throws IllegalArgumentException if the document has no {@code did:web:} {@code id}
     */
    public static DidDocument toWebVhDocument(DidDocument didWebDocument) {
        return toWebVhDocument(didWebDocument, true);
    }

    /**
     * Converts a {@code did:web} document into a {@code did:webvh} genesis document.
     *
     * @param didWebDocument an existing {@code did:web} DID document
     * @param linkDidWeb     when {@code true}, the original {@code did:web} DID is
     *                       added to {@code alsoKnownAs} (deduplicated); when
     *                       {@code false}, {@code alsoKnownAs} is left as-is
     * @return a genesis document whose {@code id} uses the {@code {SCID}} placeholder
     * @throws IllegalArgumentException if the document has no {@code did:web:} {@code id}
     */
    public static DidDocument toWebVhDocument(DidDocument didWebDocument, boolean linkDidWeb) {
        String didWeb = requireDidWebId(didWebDocument);
        String placeholderDid = DidWebVhConstants.DID_METHOD_PREFIX
                + DidWebVhConstants.SCID_PLACEHOLDER + ":" + domainComponent(didWeb);

        DidDocument rewritten = rewriteOwnDid(didWebDocument, didWeb, placeholderDid);
        return finalizeAliases(rewritten, placeholderDid, didWeb, linkDidWeb);
    }

    /**
     * Returns the {@code did:webvh} domain component for the given {@code did:web}
     * document, i.e. everything after the {@code did:web:} prefix. This is the value
     * to pass to {@code CreateOptions.domain(...)}.
     *
     * @param didWebDocument an existing {@code did:web} DID document
     * @return the domain (and optional path) component, e.g. {@code example.com:dids:issuer}
     * @throws IllegalArgumentException if the document has no {@code did:web:} {@code id}
     */
    public static String domainOf(DidDocument didWebDocument) {
        return domainComponent(requireDidWebId(didWebDocument));
    }

    // -------------------------------------------------------------------------

    private static String requireDidWebId(DidDocument document) {
        Objects.requireNonNull(document, "didWebDocument must not be null");
        String id = document.getString("id");
        if (id == null || !id.startsWith(DID_WEB_PREFIX)) {
            throw new IllegalArgumentException(
                    "document id must be a did:web DID, but was: " + id);
        }
        if (id.indexOf('#') >= 0) {
            throw new IllegalArgumentException(
                    "document id must be a bare DID without a fragment, but was: " + id);
        }
        return id;
    }

    private static String domainComponent(String didWeb) {
        return didWeb.substring(DID_WEB_PREFIX.length());
    }

    /**
     * Rewrites the document's own DID (and any fragment/path identifiers derived
     * from it) to the placeholder {@code did:webvh} DID, leaving references to other
     * DIDs untouched. The lookahead restricts replacement to a full DID token: the
     * base DID followed by a closing quote, a fragment ({@code #}), a path or
     * percent-encoded port ({@code :}), or a slash.
     */
    private static DidDocument rewriteOwnDid(DidDocument document, String didWeb, String placeholderDid) {
        String json = document.toJson();
        String rewritten = Pattern.compile(Pattern.quote(didWeb) + "(?=[\"#:/])")
                .matcher(json)
                .replaceAll(Matcher.quoteReplacement(placeholderDid));
        return DidDocument.fromJson(rewritten);
    }

    /**
     * Reconciles {@code alsoKnownAs}: drops any self-reference to the (placeholder)
     * {@code did:webvh} DID that the rewrite step may have produced from an existing
     * self {@code did:web} entry, deduplicates, and — when requested — appends the
     * original {@code did:web} DID. Leaves the document untouched when there is
     * nothing to add or change.
     */
    private static DidDocument finalizeAliases(DidDocument document, String selfDid,
                                               String didWeb, boolean linkDidWeb) {
        List<String> aliases = new ArrayList<>();
        for (String alias : document.getStrings("alsoKnownAs")) {
            if (!alias.equals(selfDid) && !aliases.contains(alias)) {
                aliases.add(alias);
            }
        }
        if (linkDidWeb && !aliases.contains(didWeb)) {
            aliases.add(didWeb);
        }
        if (aliases.isEmpty() && !document.has("alsoKnownAs")) {
            return document;
        }
        return document.toBuilder().setStrings("alsoKnownAs", aliases).build();
    }
}
