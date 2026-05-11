package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.DidDocument;
import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;
import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;
import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;
import io.didwebvh.api.DeactivateOptions;
import io.didwebvh.log.LogSerializer;
import io.didwebvh.operation.CreateOperation;
import io.didwebvh.operation.UpdateOperation;
import io.didwebvh.operation.DeactivateOperation;
import io.didwebvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class HttpResolverTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DOMAIN = "example.com";

    private Ed25519TestFixture fixture;

    @BeforeEach
    void setUp() {
        fixture = Ed25519TestFixture.generate();
    }

    private ResolveOptions defaultOptions() {
        return ResolveOptions.builder()
                .verifier(Ed25519TestFixture.verifier())
                .build();
    }

    private CreateResult createDid() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
        doc.put("id", "did:webvh:{SCID}:" + DOMAIN);

        return CreateOperation.create(
                CreateOptions.builder()
                        .domain(DOMAIN)
                        .initialDocument(new DidDocument(doc))
                        .updateKeys(List.of(fixture.publicKeyMultibase()))
                        .signer(fixture.signer())
                        .build());
    }

    // -------------------------------------------------------------------------
    // Successful resolution
    // -------------------------------------------------------------------------

    @Nested
    class SuccessfulResolution {

        @Test
        void resolvesThroughInjectedFetcher() {
            CreateResult created = createDid();
            String jsonl = LogSerializer.serialize(created.log());

            LogFetcher testFetcher = url -> jsonl;
            DidResolver resolver = new HttpResolver(testFetcher);

            ResolveResult result = resolver.resolve(created.did(), defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.did()).isEqualTo(created.did());
            assertThat(result.document()).isNotNull();
            assertThat(result.documentMetadata().scid()).isEqualTo(
                    created.log().first().parameters().scid());
        }

        @Test
        void fetchedBodyIsActuallyParsedAndValidated() {
            // Two-entry log: genesis doc has no "updated" field, update adds it.
            // Requesting versionNumber=1 must return the genesis document, proving
            // the fetched body went all the way through parse → validate → filter.
            CreateResult created = createDid();
            String scid = created.log().first().parameters().scid();

            ObjectNode updatedDoc = MAPPER.createObjectNode();
            updatedDoc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            updatedDoc.put("id", "did:webvh:" + scid + ":" + DOMAIN);

            UpdateResult updated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(new DidDocument(updatedDoc))
                            .signer(fixture.signer())
                            .build());

            String jsonl = LogSerializer.serialize(updated.log());
            LogFetcher testFetcher = url -> jsonl;
            DidResolver resolver = new HttpResolver(testFetcher);

            ResolveOptions options = ResolveOptions.builder()
                    .verifier(Ed25519TestFixture.verifier())
                    .versionNumber(1)
                    .build();

            ResolveResult result = resolver.resolve(created.did(), options);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.documentMetadata().versionId()).isEqualTo(created.log().first().versionId());
            // The resolved document now includes implicit #files and #whois services,
            // so we check the id and service presence instead of
            // exact JSON equality.
            assertThat(result.document().getString("id")).isEqualTo(
                    created.document().getString("id"));
            assertThat(result.document().has("service")).isTrue();
            assertThat(result.document().getObjects("service")).hasSize(2);
        }
    }

    // -------------------------------------------------------------------------
    // Error cases
    // -------------------------------------------------------------------------

    @Nested
    class ErrorCases {

        @Test
        void httpError_returnsNotFoundMetadata() {
            LogFetcher failFetcher = url -> { throw new IOException("HTTP 404 for " + url); };
            DidResolver resolver = new HttpResolver(failFetcher);

            CreateResult created = createDid();
            ResolveResult result = resolver.resolve(created.did(), defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.resolutionMetadata().error()).isEqualTo("notFound");
            assertThat(result.resolutionMetadata().problemDetails()).isNotNull();
        }

        @Test
        void malformedJsonl_returnsInvalidDidMetadata() {
            LogFetcher badFetcher = url -> "this is not valid jsonl at all";
            DidResolver resolver = new HttpResolver(badFetcher);

            CreateResult created = createDid();
            ResolveResult result = resolver.resolve(created.did(), defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.resolutionMetadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void invalidDid_returnsInvalidDidMetadata() {
            LogFetcher fetcher = url -> "{}";
            DidResolver resolver = new HttpResolver(fetcher);

            ResolveResult result = resolver.resolve("did:web:not-webvh", defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.resolutionMetadata().error()).isEqualTo("invalidDid");
        }
    }

    // -------------------------------------------------------------------------
    // Fragment (DID URL) resolution
    // -------------------------------------------------------------------------

    @Nested
    class FragmentResolution {

        @Test
        void resolveWithFragment_returnsVerificationMethodNode() {
            CreateResult created = createDid();
            String scid = created.log().first().parameters().scid();
            String didBase = "did:webvh:" + scid + ":" + DOMAIN;
            String vmId = didBase + "#key-1";

            ObjectNode doc = MAPPER.createObjectNode();
            doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc.put("id", didBase);
            ObjectNode vm = MAPPER.createObjectNode();
            vm.put("id", vmId);
            vm.put("type", "Multikey");
            vm.put("controller", didBase);
            vm.put("publicKeyMultibase", fixture.publicKeyMultibase());
            doc.putArray("verificationMethod").add(vm);

            UpdateResult updated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(new DidDocument(doc))
                            .signer(fixture.signer())
                            .build());

            String jsonl = LogSerializer.serialize(updated.log());
            DidResolver resolver = new HttpResolver(url -> jsonl);

            ResolveResult result = resolver.resolve(didBase + "#key-1", defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.did()).isEqualTo(didBase + "#key-1");
            assertThat(result.document().getString("id")).isEqualTo(vmId);
            assertThat(result.document().getString("publicKeyMultibase"))
                    .isEqualTo(fixture.publicKeyMultibase());
            // The full document is not returned — only the matched VM node
            assertThat(result.document().has("verificationMethod")).isFalse();
        }

        @Test
        void resolveWithUnknownFragment_returnsNotFound() {
            CreateResult created = createDid();
            String jsonl = LogSerializer.serialize(created.log());
            DidResolver resolver = new HttpResolver(url -> jsonl);

            ResolveResult result = resolver.resolve(created.did() + "#nonexistent", defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.resolutionMetadata().error()).isEqualTo("notFound");
        }
    }

    // -------------------------------------------------------------------------
    // DID URL path resolution (implicit #files service)
    // -------------------------------------------------------------------------

    @Nested
    class PathResolution {

        @Test
        void resolvePath_returnsContentStream() {
            CreateResult created = createDid();
            String jsonl = LogSerializer.serialize(created.log());
            String expectedContent = "{\"governance\":\"data\"}";

            // The fetcher must handle both the log URL and the path resource URL.
            LogFetcher testFetcher = url -> {
                if (url.endsWith("did.jsonl")) return jsonl;
                if (url.endsWith("governance/issuers.json")) return expectedContent;
                throw new IOException("Unexpected URL: " + url);
            };

            DidResolver resolver = new HttpResolver(testFetcher);
            String didWithPath = created.did() + "/governance/issuers.json";
            ResolveResult result = resolver.resolve(didWithPath, defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.did()).isEqualTo(didWithPath);
            assertThat(result.document()).isNull(); // not a DID document
            assertThat(result.contentStream()).isEqualTo(expectedContent);
        }

        @Test
        void resolvePath_withDidPath_includesPathSegments() {
            // Create a DID that has path segments in its identifier
            ObjectNode doc = MAPPER.createObjectNode();
            doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc.put("id", "did:webvh:{SCID}:" + DOMAIN + ":dids:issuer");

            CreateResult created = CreateOperation.create(
                    CreateOptions.builder()
                            .domain(DOMAIN + ":dids:issuer")
                            .initialDocument(new DidDocument(doc))
                            .updateKeys(List.of(fixture.publicKeyMultibase()))
                            .signer(fixture.signer())
                            .build());

            String jsonl = LogSerializer.serialize(created.log());
            String expectedContent = "{\"schema\":true}";

            LogFetcher testFetcher = url -> {
                if (url.endsWith("did.jsonl")) return jsonl;
                if (url.endsWith("schema.json")) return expectedContent;
                throw new IOException("Unexpected URL: " + url);
            };

            DidResolver resolver = new HttpResolver(testFetcher);
            String didWithPath = created.did() + "/schema.json";
            ResolveResult result = resolver.resolve(didWithPath, defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.contentStream()).isEqualTo(expectedContent);
        }

        @Test
        void resolvePath_notFound_returnsNotFoundError() {
            CreateResult created = createDid();
            String jsonl = LogSerializer.serialize(created.log());

            LogFetcher testFetcher = url -> {
                if (url.endsWith("did.jsonl")) return jsonl;
                throw new IOException("HTTP 404 for " + url);
            };

            DidResolver resolver = new HttpResolver(testFetcher);
            ResolveResult result = resolver.resolve(created.did() + "/missing.json", defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.resolutionMetadata().error()).isEqualTo("notFound");
        }

        @Test
        void resolvePath_explicitFilesServiceOverride_used() {
            CreateResult created = createDid();
            String scid = created.log().first().parameters().scid();
            String didBase = "did:webvh:" + scid + ":" + DOMAIN;

            // Create a document with an explicit #files service pointing to a CDN
            ObjectNode doc = MAPPER.createObjectNode();
            doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc.put("id", didBase);
            ObjectNode filesService = MAPPER.createObjectNode();
            filesService.put("id", "#files");
            filesService.put("type", "relativeRef");
            filesService.put("serviceEndpoint", "https://cdn.example.com/assets/");
            doc.putArray("service").add(filesService);

            UpdateResult updated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(new DidDocument(doc))
                            .signer(fixture.signer())
                            .build());

            String jsonl = LogSerializer.serialize(updated.log());
            String expectedContent = "cdn-content";

            LogFetcher testFetcher = url -> {
                if (url.endsWith("did.jsonl")) return jsonl;
                if (url.equals("https://cdn.example.com/assets/logo.png")) return expectedContent;
                throw new IOException("Unexpected URL: " + url);
            };

            DidResolver resolver = new HttpResolver(testFetcher);
            ResolveResult result = resolver.resolve(didBase + "/logo.png", defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.contentStream()).isEqualTo(expectedContent);
        }
    }

    // -------------------------------------------------------------------------
    // /whois resolution (implicit #whois service)
    // -------------------------------------------------------------------------

    @Nested
    class WhoisResolution {

        @Test
        void resolveWhois_returnsVpContent() {
            CreateResult created = createDid();
            String jsonl = LogSerializer.serialize(created.log());
            String vpContent = "{\"type\":[\"VerifiablePresentation\"]}";

            LogFetcher testFetcher = url -> {
                if (url.endsWith("did.jsonl")) return jsonl;
                if (url.endsWith("whois.vp")) return vpContent;
                throw new IOException("Unexpected URL: " + url);
            };

            DidResolver resolver = new HttpResolver(testFetcher);
            String didWithWhois = created.did() + "/whois";
            ResolveResult result = resolver.resolve(didWithWhois, defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.did()).isEqualTo(didWithWhois);
            assertThat(result.document()).isNull();
            assertThat(result.contentStream()).isEqualTo(vpContent);
        }

        @Test
        void resolveWhois_notFound_returnsNotFoundError() {
            CreateResult created = createDid();
            String jsonl = LogSerializer.serialize(created.log());

            LogFetcher testFetcher = url -> {
                if (url.endsWith("did.jsonl")) return jsonl;
                throw new IOException("HTTP 404 for " + url);
            };

            DidResolver resolver = new HttpResolver(testFetcher);
            ResolveResult result = resolver.resolve(created.did() + "/whois", defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.resolutionMetadata().error()).isEqualTo("notFound");
        }

        @Test
        void resolveWhois_explicitWhoisServiceOverride_used() {
            CreateResult created = createDid();
            String scid = created.log().first().parameters().scid();
            String didBase = "did:webvh:" + scid + ":" + DOMAIN;

            ObjectNode doc = MAPPER.createObjectNode();
            doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
            doc.put("id", didBase);
            ObjectNode whoisService = MAPPER.createObjectNode();
            whoisService.put("id", "#whois");
            whoisService.put("type", "LinkedVerifiablePresentation");
            whoisService.put("serviceEndpoint", "https://example.com/custom/whois.json");
            doc.putArray("service").add(whoisService);

            UpdateResult updated = UpdateOperation.update(
                    UpdateOptions.builder()
                            .log(created.log())
                            .updatedDocument(new DidDocument(doc))
                            .signer(fixture.signer())
                            .build());

            String jsonl = LogSerializer.serialize(updated.log());
            String customVp = "{\"custom\":true}";

            LogFetcher testFetcher = url -> {
                if (url.endsWith("did.jsonl")) return jsonl;
                if (url.equals("https://example.com/custom/whois.json")) return customVp;
                throw new IOException("Unexpected URL: " + url);
            };

            DidResolver resolver = new HttpResolver(testFetcher);
            ResolveResult result = resolver.resolve(didBase + "/whois", defaultOptions());

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.contentStream()).isEqualTo(customVp);
        }

        @Test
        void resolveWhois_deactivatedDid_returnsDeactivatedMetadata() {
            // A deactivated DID does not return an error — it returns null document
            // with deactivated=true in metadata (per DID Core). Path dereferencing
            // is therefore not available.
            CreateResult created = createDid();
            var deactivated = DeactivateOperation.deactivate(
                    DeactivateOptions.builder()
                            .log(created.log())
                            .signer(fixture.signer())
                            .build());

            String jsonl = LogSerializer.serialize(deactivated.log());
            DidResolver resolver = new HttpResolver(url -> jsonl);
            ResolveResult result = resolver.resolve(created.did() + "/whois", defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.document()).isNull();
            assertThat(result.documentMetadata().deactivated()).isTrue();
        }
    }
}
