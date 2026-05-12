package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.DidDocument;
import org.junit.jupiter.api.Test;

import java.util.List;

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

        DidDocument result = ImplicitServiceInjector.inject(new DidDocument(doc), DID);

        List<DidDocument> services = result.getObjects("service");
        assertThat(services).hasSize(2);

        // #files service
        DidDocument files = services.get(0);
        assertThat(files.getString("id")).isEqualTo("#files");
        assertThat(files.getString("type")).isEqualTo("relativeRef");
        assertThat(files.getString("serviceEndpoint")).isEqualTo("https://example.com/");

        // #whois service
        DidDocument whois = services.get(1);
        assertThat(whois.getString("id")).isEqualTo("#whois");
        assertThat(whois.getString("type")).isEqualTo("LinkedVerifiablePresentation");
        assertThat(whois.getString("serviceEndpoint")).isEqualTo("https://example.com/whois.vp");
        assertThat(whois.getString("@context"))
                .isEqualTo("https://identity.foundation/linked-vp/contexts/v1");
    }

    @Test
    void inject_withDidPath_usesPathInBaseUrl() {
        String did = "did:webvh:QmTest:example.com:dids:issuer";
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", did);

        DidDocument result = ImplicitServiceInjector.inject(new DidDocument(doc), did);

        List<DidDocument> services = result.getObjects("service");
        DidDocument files = services.get(0);
        assertThat(files.getString("serviceEndpoint"))
                .isEqualTo("https://example.com/dids/issuer/");

        DidDocument whois = services.get(1);
        assertThat(whois.getString("serviceEndpoint"))
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

        DidDocument result = ImplicitServiceInjector.inject(new DidDocument(doc), DID);

        List<DidDocument> services = result.getObjects("service");
        assertThat(services).hasSize(3);
        assertThat(services.get(0).getString("id")).isEqualTo("#my-service");
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

        DidDocument result = ImplicitServiceInjector.inject(new DidDocument(doc), DID);

        List<DidDocument> services = result.getObjects("service");
        assertThat(services).hasSize(2); // only #whois added
        DidDocument files = services.get(0);
        assertThat(files.getString("serviceEndpoint")).isEqualTo("https://cdn.example.com/");
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

        DidDocument result = ImplicitServiceInjector.inject(new DidDocument(doc), DID);

        List<DidDocument> services = result.getObjects("service");
        assertThat(services).hasSize(2); // only #files added
        DidDocument whois = services.get(0);
        assertThat(whois.getString("serviceEndpoint")).isEqualTo("https://example.com/custom-whois");
    }

    @Test
    void inject_createsServiceArrayIfMissing() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        // no "service" field at all

        DidDocument result = ImplicitServiceInjector.inject(new DidDocument(doc), DID);

        assertThat(result.has("service")).isTrue();
        assertThat(result.getObjects("service")).isNotEmpty();
    }

    @Test
    void inject_nonObjectDocument_noOp() {
        DidDocument textNode = new DidDocument(MAPPER.valueToTree("not an object"));
        // Should not throw
        DidDocument result = ImplicitServiceInjector.inject(textNode, DID);
        assertThat(result).isSameAs(textNode);
    }
}
