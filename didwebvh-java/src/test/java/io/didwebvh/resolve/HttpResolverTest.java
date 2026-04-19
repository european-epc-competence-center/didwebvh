package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;
import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;
import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;
import io.didwebvh.log.LogSerializer;
import io.didwebvh.operation.CreateOperation;
import io.didwebvh.operation.UpdateOperation;
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
                        .initialDocument(doc)
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
            assertThat(result.metadata().scid()).isEqualTo(
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
                            .updatedDocument(updatedDoc)
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
            assertThat(result.metadata().versionId()).isEqualTo(created.log().first().versionId());
            assertThat(result.document()).isEqualTo(created.document());
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
            assertThat(result.metadata().error()).isEqualTo("notFound");
            assertThat(result.metadata().problemDetails()).isNotNull();
        }

        @Test
        void malformedJsonl_returnsInvalidDidMetadata() {
            LogFetcher badFetcher = url -> "this is not valid jsonl at all";
            DidResolver resolver = new HttpResolver(badFetcher);

            CreateResult created = createDid();
            ResolveResult result = resolver.resolve(created.did(), defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }

        @Test
        void invalidDid_returnsInvalidDidMetadata() {
            LogFetcher fetcher = url -> "{}";
            DidResolver resolver = new HttpResolver(fetcher);

            ResolveResult result = resolver.resolve("did:web:not-webvh", defaultOptions());

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.metadata().error()).isEqualTo("invalidDid");
        }
    }
}
