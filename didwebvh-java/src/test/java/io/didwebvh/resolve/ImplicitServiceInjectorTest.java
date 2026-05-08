package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ImplicitServiceInjector}.
 *
 * <p>Verifies that the implicit {@code #files} and {@code #whois} services are
 * injected into a DID document when absent, and that explicit service
 * definitions override the implicit ones.
 */
class ImplicitServiceInjectorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DID = "did:webvh:QmTest:example.com";

    @Test
    void inject_addsBothImplicitServices() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);

        ImplicitServiceInjector.inject(doc, DID);

        JsonNode services = doc.path("service");
        assertThat(services.isArray()).isTrue();
        assertThat(services).hasSize(2);

        // #files service
        JsonNode files = services.get(0);
        assertThat(files.path("id").asText()).isEqualTo("#files");
        assertThat(files.path("type").asText()).isEqualTo("relativeRef");
        assertThat(files.path("serviceEndpoint").asText()).isEqualTo("https://example.com/");

        // #whois service
        JsonNode whois = services.get(1);
        assertThat(whois.path("id").asText()).isEqualTo("#whois");
        assertThat(whois.path("type").asText()).isEqualTo("LinkedVerifiablePresentation");
        assertThat(whois.path("serviceEndpoint").asText()).isEqualTo("https://example.com/whois.vp");
        assertThat(whois.path("@context").asText())
                .isEqualTo("https://identity.foundation/linked-vp/contexts/v1");
    }

    @Test
    void inject_withDidPath_usesPathInBaseUrl() {
        String did = "did:webvh:QmTest:example.com:dids:issuer";
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", did);

        ImplicitServiceInjector.inject(doc, did);

        JsonNode services = doc.path("service");
        JsonNode files = services.get(0);
        assertThat(files.path("serviceEndpoint").asText())
                .isEqualTo("https://example.com/dids/issuer/");

        JsonNode whois = services.get(1);
        assertThat(whois.path("serviceEndpoint").asText())
                .isEqualTo("https://example.com/dids/issuer/whois.vp");
    }

    @Test
    void inject_preservesExistingServices() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        ObjectNode existingService = MAPPER.createObjectNode();
        existingService.put("id", "#my-service");
        existingService.put("type", "MyService");
        existingService.put("serviceEndpoint", "https://example.com/api");
        doc.putArray("service").add(existingService);

        ImplicitServiceInjector.inject(doc, DID);

        JsonNode services = doc.path("service");
        assertThat(services).hasSize(3);
        assertThat(services.get(0).path("id").asText()).isEqualTo("#my-service");
    }

    @Test
    void inject_explicitFilesOverridesImplicit() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        ObjectNode explicitFiles = MAPPER.createObjectNode();
        explicitFiles.put("id", "#files");
        explicitFiles.put("type", "relativeRef");
        explicitFiles.put("serviceEndpoint", "https://cdn.example.com/");
        doc.putArray("service").add(explicitFiles);

        ImplicitServiceInjector.inject(doc, DID);

        JsonNode services = doc.path("service");
        assertThat(services).hasSize(2); // only #whois added
        JsonNode files = services.get(0);
        assertThat(files.path("serviceEndpoint").asText()).isEqualTo("https://cdn.example.com/");
    }

    @Test
    void inject_explicitWhoisOverridesImplicit() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        ObjectNode explicitWhois = MAPPER.createObjectNode();
        explicitWhois.put("id", DID + "#whois"); // absolute ID form
        explicitWhois.put("type", "LinkedVerifiablePresentation");
        explicitWhois.put("serviceEndpoint", "https://example.com/custom-whois");
        doc.putArray("service").add(explicitWhois);

        ImplicitServiceInjector.inject(doc, DID);

        JsonNode services = doc.path("service");
        assertThat(services).hasSize(2); // only #files added
        JsonNode whois = services.get(0);
        assertThat(whois.path("serviceEndpoint").asText()).isEqualTo("https://example.com/custom-whois");
    }

    @Test
    void inject_createsServiceArrayIfMissing() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        // no "service" field at all

        ImplicitServiceInjector.inject(doc, DID);

        assertThat(doc.has("service")).isTrue();
        assertThat(doc.path("service").isArray()).isTrue();
    }

    @Test
    void inject_nonObjectDocument_noOp() {
        JsonNode textNode = MAPPER.valueToTree("not an object");
        // Should not throw
        ImplicitServiceInjector.inject(textNode, DID);
    }
}
