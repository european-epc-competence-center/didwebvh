package de.eecc.did.webvh.didweb;

import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.api.CreateOptions;
import de.eecc.did.webvh.api.CreateResult;
import de.eecc.did.webvh.api.DidWebVh;
import de.eecc.did.webvh.api.ResolveOptions;
import de.eecc.did.webvh.api.ResolveResult;
import de.eecc.did.webvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DidWebPublisher} (spec §3.7.10, parallel {@code did:web} publishing).
 *
 * <p>Verifies the {@code did:webvh} -> {@code did:web} conversion: the {@code did:webvh:<scid>:}
 * prefix is rewritten to {@code did:web:} throughout, implicit services are present,
 * and {@code alsoKnownAs} carries the original {@code did:webvh} DID without the
 * {@code did:web} self-reference.
 */
class DidWebPublisherTest {

    private static final String SCID = "QmExampleScid123";
    private static final String WEBVH = "did:webvh:" + SCID + ":example.com";
    private static final String WEB = "did:web:example.com";

    @Test
    void rewritesIdAndControllerToDidWeb() {
        DidDocument resolved = DidDocument.fromJson("""
                {
                  "id": "%s",
                  "controller": "%s",
                  "verificationMethod": [
                    {"id":"%s#key-1","controller":"%s","type":"Multikey"}
                  ]
                }""".formatted(WEBVH, WEBVH, WEBVH, WEBVH));

        DidDocument web = DidWebPublisher.toDidWeb(resolved);

        assertThat(web.getString("id")).isEqualTo(WEB);
        // Per the literal spec, the blanket replace also rewrites controller to did:web.
        assertThat(web.getString("controller")).isEqualTo(WEB);
        assertThat(web.getObjects("verificationMethod").get(0).getString("id"))
                .isEqualTo(WEB + "#key-1");
    }

    @Test
    void addsWebVhToAlsoKnownAsAndDropsWebSelf() {
        DidDocument resolved = DidDocument.fromJson("""
                {"id":"%s"}""".formatted(WEBVH));

        DidDocument web = DidWebPublisher.toDidWeb(resolved);

        // The full did:webvh DID is added; the did:web self-DID must not appear.
        assertThat(web.getStrings("alsoKnownAs")).containsExactly(WEBVH);
    }

    @Test
    void injectsImplicitServicesWhenAbsent() {
        DidDocument resolved = DidDocument.fromJson("""
                {"id":"%s"}""".formatted(WEBVH));

        DidDocument web = DidWebPublisher.toDidWeb(resolved);

        List<DidDocument> services = web.getObjects("service");
        assertThat(services).hasSize(2);
        assertThat(services.get(0).getString("id")).isEqualTo("#files");
        assertThat(services.get(0).getString("type")).isEqualTo("relativeRef");
        assertThat(services.get(0).getString("serviceEndpoint")).isEqualTo("https://example.com/");
        assertThat(services.get(1).getString("id")).isEqualTo("#whois");
        assertThat(services.get(1).getString("serviceEndpoint")).isEqualTo("https://example.com/whois.vp");
    }

    @Test
    void preservesExplicitServicesAndDoesNotDuplicateImplicit() {
        DidDocument resolved = DidDocument.fromJson("""
                {
                  "id": "%s",
                  "service": [
                    {"id":"%s#files","type":"relativeRef","serviceEndpoint":"https://example.com/custom/"}
                  ]
                }""".formatted(WEBVH, WEBVH));

        DidDocument web = DidWebPublisher.toDidWeb(resolved);

        List<DidDocument> services = web.getObjects("service");
        // The explicit #files is kept (rewritten to did:web); only #whois is added.
        assertThat(services).hasSize(2);
        assertThat(services.get(0).getString("id")).isEqualTo(WEB + "#files");
        assertThat(services.get(0).getString("serviceEndpoint")).isEqualTo("https://example.com/custom/");
        assertThat(services.get(1).getString("id")).isEqualTo("#whois");
    }

    @Test
    void doesNotDuplicateExistingWebVhAlias() {
        DidDocument resolved = DidDocument.fromJson("""
                {"id":"%s","alsoKnownAs":["%s","https://example.com/about"]}"""
                .formatted(WEBVH, WEBVH));

        DidDocument web = DidWebPublisher.toDidWeb(resolved);

        // The existing did:webvh entry is rewritten to did:web, dropped as the self-DID,
        // then re-added once as did:webvh — so it appears exactly once, order aside.
        assertThat(web.getStrings("alsoKnownAs"))
                .containsExactlyInAnyOrder(WEBVH, "https://example.com/about");
    }

    @Test
    void preservesPathComponents() {
        String webvhPath = "did:webvh:" + SCID + ":example.com:dids:issuer";
        DidDocument resolved = DidDocument.fromJson("""
                {"id":"%s"}""".formatted(webvhPath));

        DidDocument web = DidWebPublisher.toDidWeb(resolved);

        assertThat(web.getString("id")).isEqualTo("did:web:example.com:dids:issuer");
        assertThat(web.getStrings("alsoKnownAs")).containsExactly(webvhPath);
        assertThat(web.getObjects("service").get(0).getString("serviceEndpoint"))
                .isEqualTo("https://example.com/dids/issuer/");
    }

    @Test
    void toDidWebIdDropsScid() {
        assertThat(DidWebPublisher.toDidWebId(WEBVH)).isEqualTo(WEB);
        assertThat(DidWebPublisher.toDidWebId("did:webvh:" + SCID + ":example.com:dids:issuer"))
                .isEqualTo("did:web:example.com:dids:issuer");
    }

    @Test
    void rejectsNonWebVhDocument() {
        DidDocument web = DidDocument.fromJson("""
                {"id":"did:web:example.com"}""");

        assertThatThrownBy(() -> DidWebPublisher.toDidWeb(web))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("did:webvh");
    }

    @Test
    void roundTripsFromResolvedDocument() {
        Ed25519TestFixture key = Ed25519TestFixture.generate();
        DidDocument genesis = DidDocument.fromJson("""
                {
                  "@context": ["https://www.w3.org/ns/did/v1"],
                  "id": "did:webvh:{SCID}:example.com",
                  "verificationMethod": [
                    {"id":"did:webvh:{SCID}:example.com#key-1","controller":"did:webvh:{SCID}:example.com","type":"Multikey"}
                  ]
                }""");

        CreateResult created = DidWebVh.create(
                CreateOptions.builder()
                        .domain("example.com")
                        .initialDocument(genesis)
                        .updateKeys(List.of(key.publicKeyMultibase()))
                        .signer(key.signer())
                        .build());

        // Resolve to get the canonical document (with implicit services injected).
        ResolveResult resolved = DidWebVh.resolveFromLog(
                created.did(), created.log(),
                ResolveOptions.builder().verifier(Ed25519TestFixture.verifier()).build());
        assertThat(resolved.isSuccess()).isTrue();

        DidDocument web = DidWebPublisher.toDidWeb(resolved.document());

        String expectedWebId = DidWebPublisher.toDidWebId(created.did());
        assertThat(web.getString("id")).isEqualTo(expectedWebId);
        assertThat(web.getString("id")).startsWith("did:web:").doesNotContain("did:webvh");
        assertThat(web.getStrings("alsoKnownAs")).containsExactly(created.did());
        assertThat(web.getObjects("verificationMethod").get(0).getString("id"))
                .isEqualTo(expectedWebId + "#key-1");
        assertThat(web.getObjects("service")).hasSize(2);
    }
}
