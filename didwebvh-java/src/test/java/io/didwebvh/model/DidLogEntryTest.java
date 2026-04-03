package io.didwebvh.model;

import io.didwebvh.model.proof.DataIntegrityProof;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DidLogEntryTest {

    // -------------------------------------------------------------------------
    // versionNumber()
    // -------------------------------------------------------------------------

    @Test
    void versionNumber_returnsFirstSegment() {
        var entry = entryWithVersionId("1-QmFoo");
        assertThat(entry.versionNumber()).isEqualTo(1);
    }

    @Test
    void versionNumber_largeNumber() {
        var entry = entryWithVersionId("42-Abc123XYZ");
        assertThat(entry.versionNumber()).isEqualTo(42);
    }

    @Test
    void versionNumber_singleDigit() {
        var entry = entryWithVersionId("7-SomeLongHash");
        assertThat(entry.versionNumber()).isEqualTo(7);
    }

    // -------------------------------------------------------------------------
    // entryHash()
    // -------------------------------------------------------------------------

    @Test
    void entryHash_returnsSecondSegment() {
        var entry = entryWithVersionId("1-QmFoo");
        assertThat(entry.entryHash()).isEqualTo("QmFoo");
    }

    @Test
    void entryHash_realisticMultihash() {
        String hash = "QmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e";
        var entry = entryWithVersionId("3-" + hash);
        assertThat(entry.entryHash()).isEqualTo(hash);
    }

    @Test
    void entryHash_containsHyphen_usesFirstHyphenOnly() {
        // if (hypothetically) the hash itself contained a '-', only the part
        // before the first '-' is the version number
        var entry = entryWithVersionId("2-Abc-NotAVersion");
        assertThat(entry.versionNumber()).isEqualTo(2);
        assertThat(entry.entryHash()).isEqualTo("Abc-NotAVersion");
    }

    // -------------------------------------------------------------------------
    // withoutProof()
    // -------------------------------------------------------------------------

    @Test
    void withoutProof_removesProof() {
        var proof = new DataIntegrityProof(
                "DataIntegrityProof", "eddsa-jcs-2022", "did:example:key#key-1",
                null, "assertionMethod", "Sig", null);
        var entry = new DidLogEntry("1-QmFoo", "2025-01-01T00:00:00Z",
                null, null, List.of(proof));

        var stripped = entry.withoutProof();

        assertThat(stripped.proof()).isNull();
        assertThat(stripped.versionId()).isEqualTo(entry.versionId());
        assertThat(stripped.versionTime()).isEqualTo(entry.versionTime());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static DidLogEntry entryWithVersionId(String versionId) {
        return new DidLogEntry(versionId, "2025-01-01T00:00:00Z", null, null, null);
    }
}
