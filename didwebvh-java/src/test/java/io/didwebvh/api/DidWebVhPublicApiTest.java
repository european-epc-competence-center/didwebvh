package io.didwebvh.api;

import io.didwebvh.DidDocument;
import io.didwebvh.log.LogParser;
import io.didwebvh.log.LogSerializer;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests that verify the public API surface is free of Jackson
 * types and can be used entirely through {@link DidDocument}.
 */
class DidWebVhPublicApiTest {

    private static final String DOMAIN = "example.com";

    @Test
    void createDid_usingDidDocumentBuilder() {
        Ed25519TestFixture fixture = Ed25519TestFixture.generate();

        DidDocument initialDoc = DidDocument.builder()
                .setStrings("@context", List.of("https://www.w3.org/ns/did/v1"))
                .setString("id", "did:webvh:{SCID}:" + DOMAIN)
                .build();

        CreateResult result = DidWebVh.create(
                CreateOptions.builder()
                        .domain(DOMAIN)
                        .initialDocument(initialDoc)
                        .updateKeys(List.of(fixture.publicKeyMultibase()))
                        .signer(fixture.signer())
                        .build()
        );

        assertThat(result.did()).startsWith("did:webvh:");
        assertThat(result.document()).isNotNull();
        assertThat(result.document().getString("id")).isEqualTo(result.did());
        assertThat(result.log()).isNotNull();
        assertThat(result.log().size()).isEqualTo(1);
    }

    @Test
    void createDid_usingDidDocumentFromJson() {
        Ed25519TestFixture fixture = Ed25519TestFixture.generate();

        DidDocument initialDoc = DidDocument.fromJson(
                "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"did:webvh:{SCID}:"
                        + DOMAIN + "\"}"
        );

        CreateResult result = DidWebVh.create(
                CreateOptions.builder()
                        .domain(DOMAIN)
                        .initialDocument(initialDoc)
                        .updateKeys(List.of(fixture.publicKeyMultibase()))
                        .signer(fixture.signer())
                        .build()
        );

        assertThat(result.did()).startsWith("did:webvh:");
        assertThat(result.document()).isNotNull();
        assertThat(result.document().getString("id")).isEqualTo(result.did());
    }

    @Test
    void resolveDid_documentIsDidDocumentWithImplicitServices() {
        Ed25519TestFixture fixture = Ed25519TestFixture.generate();

        DidDocument initialDoc = DidDocument.builder()
                .setStrings("@context", List.of("https://www.w3.org/ns/did/v1"))
                .setString("id", "did:webvh:{SCID}:" + DOMAIN)
                .build();

        CreateResult created = DidWebVh.create(
                CreateOptions.builder()
                        .domain(DOMAIN)
                        .initialDocument(initialDoc)
                        .updateKeys(List.of(fixture.publicKeyMultibase()))
                        .signer(fixture.signer())
                        .build()
        );

        ResolveResult resolved = DidWebVh.resolveFromLog(
                created.did(),
                created.log(),
                ResolveOptions.builder()
                        .verifier(Ed25519TestFixture.verifier())
                        .build()
        );

        assertThat(resolved.isSuccess()).isTrue();
        DidDocument doc = resolved.document();
        assertThat(doc).isNotNull();
        assertThat(doc.getString("id")).isEqualTo(created.did());

        List<DidDocument> services = doc.getObjects("service");
        assertThat(services).hasSize(2);

        DidDocument filesService = services.stream()
                .filter(s -> (created.did() + "#files").equals(s.getString("id")))
                .findFirst()
                .orElseThrow();
        assertThat(filesService.getString("type")).isEqualTo("relativeRef");
        assertThat(filesService.getString("serviceEndpoint")).isEqualTo("https://example.com/");

        DidDocument whoisService = services.stream()
                .filter(s -> (created.did() + "#whois").equals(s.getString("id")))
                .findFirst()
                .orElseThrow();
        assertThat(whoisService.getString("type")).isEqualTo("LinkedVerifiablePresentation");
        assertThat(whoisService.getString("serviceEndpoint")).isEqualTo("https://example.com/whois.vp");
    }

    @Test
    void logRoundTrip_serializeAndParse_preservesDidDocument() {
        Ed25519TestFixture fixture = Ed25519TestFixture.generate();

        DidDocument initialDoc = DidDocument.builder()
                .setStrings("@context", List.of("https://www.w3.org/ns/did/v1"))
                .setString("id", "did:webvh:{SCID}:" + DOMAIN)
                .build();

        CreateResult created = DidWebVh.create(
                CreateOptions.builder()
                        .domain(DOMAIN)
                        .initialDocument(initialDoc)
                        .updateKeys(List.of(fixture.publicKeyMultibase()))
                        .signer(fixture.signer())
                        .build()
        );

        String jsonl = LogSerializer.serialize(created.log());
        DidLog parsedLog = LogParser.parse(jsonl);

        assertThat(parsedLog.size()).isEqualTo(created.log().size());
        assertThat(parsedLog.isParsingComplete()).isTrue();

        DidLogEntry originalEntry = created.log().first();
        DidLogEntry parsedEntry = parsedLog.first();

        assertThat(parsedEntry.versionId()).isEqualTo(originalEntry.versionId());
        assertThat(parsedEntry.versionTime()).isEqualTo(originalEntry.versionTime());

        DidDocument parsedState = parsedEntry.state();
        assertThat(parsedState).isNotNull();
        assertThat(parsedState.getString("id")).isEqualTo(created.did());
        assertThat(parsedState.getStrings("@context")).containsExactly("https://www.w3.org/ns/did/v1");
    }
}
