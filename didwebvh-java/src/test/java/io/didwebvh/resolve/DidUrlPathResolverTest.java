package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.DidDocument;
import io.didwebvh.exception.DidNotFoundException;
import io.didwebvh.exception.DidWebVhException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DidUrlPathResolver}.
 *
 * <p>Verifies that DID URL paths are correctly mapped to target HTTPS URLs
 * by looking up services in the DID document.
 */
class DidUrlPathResolverTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DID = "did:webvh:QmTest:example.com";

    /**
     * Builds a DID document with the two implicit services already injected.
     * This mirrors what LogBasedResolver returns after resolution.
     */
    private DidDocument documentWithImplicitServices() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        return ImplicitServiceInjector.inject(new DidDocument(doc), DID);
    }

    @Test
    void resolvePath_whois_returnsWhoisVpUrl() {
        DidDocument doc = documentWithImplicitServices();
        String url = DidUrlPathResolver.resolvePath(doc, DID, "/whois");
        assertThat(url).isEqualTo("https://example.com/whois.vp");
    }

    @Test
    void resolvePath_simpleFilePath_appendsToFilesEndpoint() {
        DidDocument doc = documentWithImplicitServices();
        String url = DidUrlPathResolver.resolvePath(doc, DID, "/governance/issuers.json");
        assertThat(url).isEqualTo("https://example.com/governance/issuers.json");
    }

    @Test
    void resolvePath_nestedFilePath_appendsCorrectly() {
        DidDocument doc = documentWithImplicitServices();
        String url = DidUrlPathResolver.resolvePath(doc, DID, "/deep/nested/path/file.txt");
        assertThat(url).isEqualTo("https://example.com/deep/nested/path/file.txt");
    }

    @Test
    void resolvePath_withDidPath_baseUrlIncludesPathSegments() {
        String did = "did:webvh:QmTest:example.com:dids:issuer";
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", did);
        DidDocument document = ImplicitServiceInjector.inject(new DidDocument(doc), did);

        String url = DidUrlPathResolver.resolvePath(document, did, "/whois");
        assertThat(url).isEqualTo("https://example.com/dids/issuer/whois.vp");

        String fileUrl = DidUrlPathResolver.resolvePath(document, did, "/schema.json");
        assertThat(fileUrl).isEqualTo("https://example.com/dids/issuer/schema.json");
    }

    @Test
    void resolvePath_explicitFilesService_respectsOverride() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        ObjectNode explicitFiles = MAPPER.createObjectNode();
        explicitFiles.put("id", "#files");
        explicitFiles.put("type", "relativeRef");
        explicitFiles.put("serviceEndpoint", "https://cdn.example.com/assets/");
        doc.putArray("service").add(explicitFiles);

        String url = DidUrlPathResolver.resolvePath(new DidDocument(doc), DID, "/logo.png");
        assertThat(url).isEqualTo("https://cdn.example.com/assets/logo.png");
    }

    @Test
    void resolvePath_explicitWhoisService_respectsOverride() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        ObjectNode explicitWhois = MAPPER.createObjectNode();
        explicitWhois.put("id", "#whois");
        explicitWhois.put("type", "LinkedVerifiablePresentation");
        explicitWhois.put("serviceEndpoint", "https://example.com/custom/whois.vp");
        doc.putArray("service").add(explicitWhois);

        String url = DidUrlPathResolver.resolvePath(new DidDocument(doc), DID, "/whois");
        assertThat(url).isEqualTo("https://example.com/custom/whois.vp");
    }

    @Test
    void resolvePath_missingFilesService_throwsNotFound() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        // No services at all

        assertThatThrownBy(() -> DidUrlPathResolver.resolvePath(new DidDocument(doc), DID, "/file.json"))
                .isInstanceOf(DidNotFoundException.class)
                .hasMessageContaining("files service not found");
    }

    @Test
    void resolvePath_missingWhoisService_throwsNotFound() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        // No services at all

        assertThatThrownBy(() -> DidUrlPathResolver.resolvePath(new DidDocument(doc), DID, "/whois"))
                .isInstanceOf(DidNotFoundException.class)
                .hasMessageContaining("whois service not found");
    }

    @Test
    void resolvePath_missingServiceEndpoint_throwsInvalidDid() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        ObjectNode badService = MAPPER.createObjectNode();
        badService.put("id", "#files");
        badService.put("type", "relativeRef");
        // No serviceEndpoint!
        doc.putArray("service").add(badService);

        assertThatThrownBy(() -> DidUrlPathResolver.resolvePath(new DidDocument(doc), DID, "/file.json"))
                .isInstanceOf(DidWebVhException.class)
                .hasMessageContaining("Missing or empty serviceEndpoint");
    }

    @Test
    void resolvePath_filesEndpointWithoutTrailingSlash_addsSlash() {
        ObjectNode doc = MAPPER.createObjectNode();
        doc.put("id", DID);
        ObjectNode files = MAPPER.createObjectNode();
        files.put("id", "#files");
        files.put("type", "relativeRef");
        files.put("serviceEndpoint", "https://example.com/no-trailing-slash");
        doc.putArray("service").add(files);

        String url = DidUrlPathResolver.resolvePath(new DidDocument(doc), DID, "/file.json");
        assertThat(url).isEqualTo("https://example.com/no-trailing-slash/file.json");
    }
}
