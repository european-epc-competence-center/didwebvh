package de.eecc.did.webvh.didweb;

import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.api.CreateOptions;
import de.eecc.did.webvh.api.CreateResult;
import de.eecc.did.webvh.api.DidWebVh;
import de.eecc.did.webvh.api.ResolveOptions;
import de.eecc.did.webvh.api.ResolveResult;
import de.eecc.did.webvh.api.UpdateOptions;
import de.eecc.did.webvh.api.UpdateResult;
import de.eecc.did.webvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DidWebImporter}.
 *
 * <p>Verifies the {@code did:web} -> {@code did:webvh} genesis-document conversion:
 * the document's own DID (and identifiers derived from it) are rewritten to use the
 * {@code {SCID}} placeholder, references to other DIDs are preserved, and the
 * original {@code did:web} DID is recorded in {@code alsoKnownAs}.
 */
class DidWebImporterTest {

    @Test
    void rewritesIdToScidPlaceholder() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com"}""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb);

        assertThat(result.getString("id")).isEqualTo("did:webvh:{SCID}:example.com");
    }

    @Test
    void rewritesFragmentAndControllerReferencesToOwnDid() {
        DidDocument didWeb = DidDocument.fromJson("""
                {
                  "id": "did:web:example.com",
                  "controller": "did:web:example.com",
                  "verificationMethod": [
                    {"id":"did:web:example.com#key-1","controller":"did:web:example.com","type":"Multikey"}
                  ],
                  "assertionMethod": ["did:web:example.com#key-1"]
                }""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb);

        assertThat(result.getString("controller")).isEqualTo("did:webvh:{SCID}:example.com");
        DidDocument vm = result.getObjects("verificationMethod").get(0);
        assertThat(vm.getString("id")).isEqualTo("did:webvh:{SCID}:example.com#key-1");
        assertThat(vm.getString("controller")).isEqualTo("did:webvh:{SCID}:example.com");
        assertThat(result.getStrings("assertionMethod"))
                .containsExactly("did:webvh:{SCID}:example.com#key-1");
    }

    @Test
    void preservesPathComponentsOfOwnDid() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com:dids:issuer"}""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb);

        assertThat(result.getString("id")).isEqualTo("did:webvh:{SCID}:example.com:dids:issuer");
    }

    @Test
    void recordsOriginalDidWebInAlsoKnownAs() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com"}""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb);

        assertThat(result.getStrings("alsoKnownAs")).containsExactly("did:web:example.com");
    }

    @Test
    void doesNotDuplicateExistingDidWebAlias() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com","alsoKnownAs":["did:web:example.com","https://example.com/about"]}""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb);

        // The self did:web entry is rewritten to the webvh self-DID, dropped as a
        // meaningless self-reference, and the did:web alias re-appended at the end.
        assertThat(result.getStrings("alsoKnownAs"))
                .containsExactly("https://example.com/about", "did:web:example.com");
    }

    @Test
    void leavesOtherDidWebReferencesUntouched() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com","controller":"did:web:other.example"}""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb);

        assertThat(result.getString("id")).isEqualTo("did:webvh:{SCID}:example.com");
        assertThat(result.getString("controller")).isEqualTo("did:web:other.example");
    }

    @Test
    void doesNotRewriteDomainPrefixCollision() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com","controller":"did:web:example.community"}""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb);

        assertThat(result.getString("controller")).isEqualTo("did:web:example.community");
    }

    @Test
    void canSkipAliasLinking() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com"}""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb, false);

        assertThat(result.has("alsoKnownAs")).isFalse();
    }

    @Test
    void domainOfReturnsComponentAfterPrefix() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com:dids:issuer"}""");

        assertThat(DidWebImporter.domainOf(didWeb)).isEqualTo("example.com:dids:issuer");
    }

    @Test
    void rejectsNonDidWebDocument() {
        DidDocument notWeb = DidDocument.fromJson("""
                {"id":"did:webvh:QmAbc:example.com"}""");

        assertThatThrownBy(() -> DidWebImporter.toWebVhDocument(notWeb))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("did:web");
    }

    @Test
    void rejectsDidUrlWithFragment() {
        DidDocument withFragment = DidDocument.fromJson("""
                {"id":"did:web:example.com#key-1"}""");

        assertThatThrownBy(() -> DidWebImporter.toWebVhDocument(withFragment))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fragment");
    }

    @Test
    void importedDocumentRoundTripsThroughCreateAndResolve() {
        Ed25519TestFixture key = Ed25519TestFixture.generate();
        DidDocument didWeb = DidDocument.fromJson("""
                {
                  "@context": ["https://www.w3.org/ns/did/v1"],
                  "id": "did:web:example.com",
                  "verificationMethod": [
                    {"id":"did:web:example.com#key-1","controller":"did:web:example.com","type":"Multikey"}
                  ],
                  "assertionMethod": ["did:web:example.com#key-1"]
                }""");

        DidDocument genesis = DidWebImporter.toWebVhDocument(didWeb);

        CreateResult created = DidWebVh.create(
                CreateOptions.builder()
                        .domain(DidWebImporter.domainOf(didWeb))
                        .initialDocument(genesis)
                        .updateKeys(List.of(key.publicKeyMultibase()))
                        .signer(key.signer())
                        .build());

        // The placeholder is resolved to the real SCID and the did:web link is preserved.
        String did = created.did();
        assertThat(did).startsWith("did:webvh:").endsWith(":example.com");
        DidDocument doc = created.document();
        assertThat(doc.getString("id")).isEqualTo(did);
        assertThat(doc.getObjects("verificationMethod").get(0).getString("id"))
                .isEqualTo(did + "#key-1");
        assertThat(doc.getStrings("alsoKnownAs")).containsExactly("did:web:example.com");

        // The signed genesis log validates end-to-end.
        ResolveResult resolved = DidWebVh.resolveFromLog(
                did, created.log(),
                ResolveOptions.builder().verifier(Ed25519TestFixture.verifier()).build());
        assertThat(resolved.isSuccess()).isTrue();
    }

    // -------------------------------------------------------------------------
    // Concrete-SCID conversion (update-time, dual publishing)
    // -------------------------------------------------------------------------

    @Test
    void concreteScid_rewritesOwnIdsToConcreteDid() {
        DidDocument didWeb = DidDocument.fromJson("""
                {
                  "id": "did:web:example.com",
                  "controller": "did:web:example.com",
                  "verificationMethod": [
                    {"id":"did:web:example.com#key-1","controller":"did:web:example.com","type":"Multikey"}
                  ],
                  "assertionMethod": ["did:web:example.com#key-1"]
                }""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb, "QmScid123");

        String did = "did:webvh:QmScid123:example.com";
        assertThat(result.getString("id")).isEqualTo(did);
        assertThat(result.getString("controller")).isEqualTo(did);
        assertThat(result.getObjects("verificationMethod").get(0).getString("id"))
                .isEqualTo(did + "#key-1");
        assertThat(result.getStrings("assertionMethod")).containsExactly(did + "#key-1");
        assertThat(result.getStrings("alsoKnownAs")).containsExactly("did:web:example.com");
    }

    /**
     * A dual-published did:web document carries a forward alsoKnownAs link to the
     * did:webvh DID (as produced by {@link DidWebPublisher#toDidWeb}). After the
     * conversion that link would be a self-reference and must be dropped.
     */
    @Test
    void concreteScid_dropsForwardSelfAliasAndKeepsBackLink() {
        DidDocument didWeb = DidDocument.fromJson("""
                {
                  "id": "did:web:example.com",
                  "alsoKnownAs": ["did:webvh:QmScid123:example.com"]
                }""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb, "QmScid123");

        assertThat(result.getString("id")).isEqualTo("did:webvh:QmScid123:example.com");
        assertThat(result.getStrings("alsoKnownAs")).containsExactly("did:web:example.com");
    }

    @Test
    void concreteScid_canSkipAliasLinking() {
        DidDocument didWeb = DidDocument.fromJson("""
                {
                  "id": "did:web:example.com",
                  "alsoKnownAs": ["did:webvh:QmScid123:example.com", "did:example:other"]
                }""");

        DidDocument result = DidWebImporter.toWebVhDocument(didWeb, "QmScid123", false);

        // Self-reference dropped, unrelated alias kept, no did:web back-link added.
        assertThat(result.getStrings("alsoKnownAs")).containsExactly("did:example:other");
    }

    @Test
    void concreteScid_rejectsBlankScid() {
        DidDocument didWeb = DidDocument.fromJson("""
                {"id":"did:web:example.com"}""");

        assertThatThrownBy(() -> DidWebImporter.toWebVhDocument(didWeb, " "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("scid");
    }

    /**
     * The full dual-publishing lifecycle: did:web is the editable source of truth,
     * did:webvh the derived append-only log. Genesis via the placeholder conversion,
     * parallel did:web via {@link DidWebPublisher}, then a did:web edit is appended
     * with the concrete-SCID conversion and the DID still resolves.
     */
    @Test
    void dualPublishRoundTrip_didWebEditAppendsAndResolves() {
        Ed25519TestFixture key = Ed25519TestFixture.generate();
        DidDocument didWeb = DidDocument.fromJson("""
                {
                  "@context": ["https://www.w3.org/ns/did/v1"],
                  "id": "did:web:example.com",
                  "verificationMethod": [
                    {"id":"did:web:example.com#key-1","controller":"did:web:example.com","type":"Multikey"}
                  ],
                  "assertionMethod": ["did:web:example.com#key-1"]
                }""");

        // 1. Genesis: placeholder conversion + create.
        CreateResult created = DidWebVh.create(
                CreateOptions.builder()
                        .domain(DidWebImporter.domainOf(didWeb))
                        .initialDocument(DidWebImporter.toWebVhDocument(didWeb))
                        .updateKeys(List.of(key.publicKeyMultibase()))
                        .signer(key.signer())
                        .build());
        String did = created.did();
        String scid = created.log().first().parameters().scid();

        // 2. Dual publish: generate the parallel did:web document (carries the
        //    forward alsoKnownAs link back to the did:webvh DID).
        DidDocument published = DidWebPublisher.toDidWeb(created.document());
        assertThat(published.getString("id")).isEqualTo("did:web:example.com");
        assertThat(published.getStrings("alsoKnownAs")).contains(did);

        // 3. The did:web source of truth changes: a second key is added.
        DidDocument editedDidWeb = published.toBuilder().build();
        String editedJson = editedDidWeb.toJson().replace(
                "\"assertionMethod\":",
                "\"keyAgreement\":[\"did:web:example.com#key-2\"],\"assertionMethod\":");
        editedDidWeb = DidDocument.fromJson(editedJson);

        // 4. Convert the edited did:web document for the update and append it.
        DidDocument updatedDoc = DidWebImporter.toWebVhDocument(editedDidWeb, scid);
        assertThat(updatedDoc.getString("id")).isEqualTo(did);

        UpdateResult updated = DidWebVh.update(
                UpdateOptions.builder()
                        .log(created.log())
                        .updatedDocument(updatedDoc)
                        .signer(key.signer())
                        .build());

        // 5. The extended log resolves; the edit is visible under the did:webvh id.
        ResolveResult resolved = DidWebVh.resolveFromLog(
                did, updated.log(),
                ResolveOptions.builder().verifier(Ed25519TestFixture.verifier()).build());
        assertThat(resolved.isSuccess()).isTrue();
        assertThat(resolved.document().getString("id")).isEqualTo(did);
        assertThat(resolved.document().getStrings("keyAgreement"))
                .containsExactly(did + "#key-2");
        assertThat(resolved.document().getStrings("alsoKnownAs"))
                .containsExactly("did:web:example.com");
    }
}
