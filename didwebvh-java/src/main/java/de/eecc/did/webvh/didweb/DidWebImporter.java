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
 * <p>For a DID that has already been created (e.g. a dual publisher whose editable
 * {@code did:web} document changed and must be appended to the {@code did:webvh} log),
 * use {@link #toWebVhDocument(DidDocument, String)} with the log's SCID to rewrite the
 * document to the concrete DID expected by {@link de.eecc.did.webvh.api.DidWebVh#update}.
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
        return toWebVhDocument(didWebDocument, DidWebVhConstants.SCID_PLACEHOLDER, linkDidWeb);
    }

    /**
     * Converts a {@code did:web} document into the equivalent {@code did:webvh} document
     * for an <em>existing</em> DID with the given SCID, recording the original
     * {@code did:web} DID in {@code alsoKnownAs}.
     *
     * <p>This is the update-time counterpart of {@link #toWebVhDocument(DidDocument)}:
     * use it when the {@code did:web} document is the editable source of truth and each
     * change must be appended to the already-created {@code did:webvh} log via
     * {@link de.eecc.did.webvh.api.DidWebVh#update}. The document's own identifiers are
     * rewritten to the concrete DID ({@code did:webvh:<scid>:<domain>}); a forward
     * {@code alsoKnownAs} reference to that DID (as produced by
     * {@link DidWebPublisher#toDidWeb}) would become a self-reference and is removed.
     * <pre>{@code
     * String scid = log.first().parameters().scid();
     * DidDocument updatedDoc = DidWebImporter.toWebVhDocument(changedDidWebDoc, scid);
     *
     * UpdateResult result = DidWebVh.update(
     *     UpdateOptions.builder()
     *         .log(log)
     *         .updatedDocument(updatedDoc)
     *         .signer(signer)
     *         .build());
     * }</pre>
     *
     * @param didWebDocument an existing {@code did:web} DID document
     * @param scid           the SCID of the existing {@code did:webvh} DID, i.e.
     *                       {@code log.first().parameters().scid()}
     * @return the document with its own identifiers rewritten to
     *         {@code did:webvh:<scid>:<domain>}, ready for
     *         {@link de.eecc.did.webvh.api.DidWebVh#update}
     * @throws IllegalArgumentException if the document has no {@code did:web:} {@code id}
     *                                  or {@code scid} is blank
     */
    public static DidDocument toWebVhDocument(DidDocument didWebDocument, String scid) {
        return toWebVhDocument(didWebDocument, scid, true);
    }

    /**
     * Converts a {@code did:web} document into the equivalent {@code did:webvh} document
     * for an existing DID with the given SCID.
     *
     * @param didWebDocument an existing {@code did:web} DID document
     * @param scid           the SCID of the existing {@code did:webvh} DID (or the literal
     *                       {@code {SCID}} placeholder to produce a genesis document)
     * @param linkDidWeb     when {@code true}, the original {@code did:web} DID is
     *                       added to {@code alsoKnownAs} (deduplicated); when
     *                       {@code false}, {@code alsoKnownAs} is left as-is apart from
     *                       dropping self-references
     * @return the document with its own identifiers rewritten to
     *         {@code did:webvh:<scid>:<domain>}
     * @throws IllegalArgumentException if the document has no {@code did:web:} {@code id}
     *                                  or {@code scid} is blank
     */
    public static DidDocument toWebVhDocument(DidDocument didWebDocument, String scid, boolean linkDidWeb) {
        if (scid == null || scid.isBlank()) {
            throw new IllegalArgumentException("scid must not be blank");
        }
        String didWeb = requireDidWebId(didWebDocument);
        String webVhDid = DidWebVhConstants.DID_METHOD_PREFIX + scid + ":" + domainComponent(didWeb);

        DidDocument rewritten = rewriteOwnDid(didWebDocument, didWeb, webVhDid);
        return finalizeAliases(rewritten, webVhDid, didWeb, linkDidWeb);
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
     * from it) to the target {@code did:webvh} DID (placeholder or concrete), leaving
     * references to other DIDs untouched. The lookahead restricts replacement to a
     * full DID token: the base DID followed by a closing quote, a fragment
     * ({@code #}), a path or percent-encoded port ({@code :}), or a slash.
     */
    private static DidDocument rewriteOwnDid(DidDocument document, String didWeb, String webVhDid) {
        String json = document.toJson();
        String rewritten = Pattern.compile(Pattern.quote(didWeb) + "(?=[\"#:/])")
                .matcher(json)
                .replaceAll(Matcher.quoteReplacement(webVhDid));
        return DidDocument.fromJson(rewritten);
    }

    /**
     * Reconciles {@code alsoKnownAs}: drops any self-reference to the target
     * {@code did:webvh} DID — whether produced by the rewrite step from an existing
     * self {@code did:web} entry or already present as a forward link in a
     * dual-published document — deduplicates, and, when requested, appends the
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
