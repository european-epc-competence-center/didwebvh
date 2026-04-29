package io.didwebvh.resolve;

import io.didwebvh.exception.InvalidDidException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DidUrlTransformer} verifying the DID-to-HTTPS URL transformation per spec §3.4.
 */
class DidUrlTransformerTest {

    private static final String SCID = "QmVk3TBLNriSdFDVXDDHLsxRNiGgS96v5kDqe8hMsFUB3";

    // -------------------------------------------------------------------------
    // toLogUrl — transformation table
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
            // No path → .well-known
            "did:webvh:" + SCID + ":example.com,"
                    + "https://example.com/.well-known/did.jsonl",
            // Single path segment
            "did:webvh:" + SCID + ":example.com:dids,"
                    + "https://example.com/dids/did.jsonl",
            // Multiple path segments
            "did:webvh:" + SCID + ":example.com:dids:issuer,"
                    + "https://example.com/dids/issuer/did.jsonl",
            // Percent-encoded port, no path
            "did:webvh:" + SCID + ":example.com%3A3000,"
                    + "https://example.com:3000/.well-known/did.jsonl",
            // Percent-encoded port, lowercase %3a
            "did:webvh:" + SCID + ":example.com%3a8080,"
                    + "https://example.com:8080/.well-known/did.jsonl",
            // Percent-encoded port with path
            "did:webvh:" + SCID + ":example.com%3A3000:dids:issuer,"
                    + "https://example.com:3000/dids/issuer/did.jsonl",
            // IDNA — ASCII label (no conversion needed)
            "did:webvh:" + SCID + ":example.com,"
                    + "https://example.com/.well-known/did.jsonl",
    })
    void toLogUrl_transformationTable(String did, String expected) {
        assertThat(DidUrlTransformer.toLogUrl(did)).isEqualTo(expected);
    }

    @Test
    void toLogUrl_idnaUnicodeDomain() {
        // München → xn--mnchen-3ya (standard Punycode conversion)
        String did = "did:webvh:" + SCID + ":münchen.de";
        String url = DidUrlTransformer.toLogUrl(did);
        assertThat(url).startsWith("https://xn--mnchen-3ya.de/");
        assertThat(url).endsWith("/did.jsonl");
    }

    @Test
    void toLogUrl_unicodePathSegment() {
        // Unicode characters in path segment must be percent-encoded
        String did = "did:webvh:" + SCID + ":example.com:用户";
        String url = DidUrlTransformer.toLogUrl(did);
        assertThat(url).isEqualTo("https://example.com/%E7%94%A8%E6%88%B7/did.jsonl");
    }

    // -------------------------------------------------------------------------
    // toWitnessUrl — same transform but different filename
    // -------------------------------------------------------------------------

    @Test
    void toWitnessUrl_noPath() {
        String did = "did:webvh:" + SCID + ":example.com";
        assertThat(DidUrlTransformer.toWitnessUrl(did))
                .isEqualTo("https://example.com/.well-known/did-witness.json");
    }

    @Test
    void toWitnessUrl_withPath() {
        String did = "did:webvh:" + SCID + ":example.com:dids:issuer";
        assertThat(DidUrlTransformer.toWitnessUrl(did))
                .isEqualTo("https://example.com/dids/issuer/did-witness.json");
    }

    @Test
    void toWitnessUrl_portEncoded() {
        String did = "did:webvh:" + SCID + ":localhost%3A8080";
        assertThat(DidUrlTransformer.toWitnessUrl(did))
                .isEqualTo("https://localhost:8080/.well-known/did-witness.json");
    }

    // -------------------------------------------------------------------------
    // extractScid
    // -------------------------------------------------------------------------

    @Test
    void extractScid_realScid() {
        String did = "did:webvh:" + SCID + ":example.com";
        assertThat(DidUrlTransformer.extractScid(did)).isEqualTo(SCID);
    }

    @Test
    void extractScid_placeholder() {
        String did = "did:webvh:{SCID}:example.com";
        assertThat(DidUrlTransformer.extractScid(did)).isEqualTo("{SCID}");
    }

    @Test
    void extractScid_withPath() {
        String did = "did:webvh:" + SCID + ":example.com:dids:issuer";
        assertThat(DidUrlTransformer.extractScid(did)).isEqualTo(SCID);
    }

    // -------------------------------------------------------------------------
    // Error cases
    // -------------------------------------------------------------------------

    @Test
    void toLogUrl_nullDid_throwsInvalidDid() {
        assertThatThrownBy(() -> DidUrlTransformer.toLogUrl(null))
                .isInstanceOf(InvalidDidException.class);
    }

    @Test
    void toLogUrl_wrongMethod_throwsInvalidDid() {
        assertThatThrownBy(() -> DidUrlTransformer.toLogUrl("did:web:example.com"))
                .isInstanceOf(InvalidDidException.class);
    }

    @Test
    void toLogUrl_noHostSegment_throwsInvalidDid() {
        // Only prefix + SCID, no host
        assertThatThrownBy(() -> DidUrlTransformer.toLogUrl("did:webvh:" + SCID))
                .isInstanceOf(InvalidDidException.class);
    }

    @Test
    void toLogUrl_emptyHostSegment_throwsInvalidDid() {
        assertThatThrownBy(() -> DidUrlTransformer.toLogUrl("did:webvh:" + SCID + ":"))
                .isInstanceOf(InvalidDidException.class);
    }

    @Test
    void extractScid_noScid_throwsInvalidDid() {
        assertThatThrownBy(() -> DidUrlTransformer.extractScid("did:webvh:"))
                .isInstanceOf(InvalidDidException.class);
    }

    // -------------------------------------------------------------------------
    // extractFragment / stripFragment
    // -------------------------------------------------------------------------

    @Test
    void extractFragment_withFragment_returnsFragmentIncludingHash() {
        assertThat(DidUrlTransformer.extractFragment("did:webvh:" + SCID + ":example.com#key-1"))
                .isEqualTo("#key-1");
    }

    @Test
    void extractFragment_noFragment_returnsNull() {
        assertThat(DidUrlTransformer.extractFragment("did:webvh:" + SCID + ":example.com"))
                .isNull();
    }

    @Test
    void extractFragment_null_returnsNull() {
        assertThat(DidUrlTransformer.extractFragment(null)).isNull();
    }

    @Test
    void stripFragment_withFragment_removesHashAndTrailer() {
        String base = "did:webvh:" + SCID + ":example.com";
        assertThat(DidUrlTransformer.stripFragment(base + "#key-1")).isEqualTo(base);
    }

    @Test
    void stripFragment_noFragment_returnsUnchanged() {
        String did = "did:webvh:" + SCID + ":example.com";
        assertThat(DidUrlTransformer.stripFragment(did)).isEqualTo(did);
    }

    @Test
    void stripFragment_null_returnsNull() {
        assertThat(DidUrlTransformer.stripFragment(null)).isNull();
    }
}
